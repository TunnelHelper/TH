//go:build linux

package linux

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

const (
	testVICICmdRequest      = 0
	testVICICmdResponse     = 1
	testVICIEventRegister   = 3
	testVICIEventUnregister = 4
	testVICIEventConfirm    = 5
	testVICIKeyValue        = 3
	testVICIListStart       = 4
	testVICIListItem        = 5
	testVICIListEnd         = 6
)

type fakeVICIServer struct {
	mu           sync.Mutex
	connection   string
	keyID        string
	connectionUp bool
	keyLoaded    bool
	sharedLoaded bool
	commands     []string
}

func TestVICIControllerCredentialAndConnectionLifecycle(t *testing.T) {
	remotePublicKey := base64.StdEncoding.EncodeToString(generatedPublicDER(t))
	record := model.Tunnel{
		Name: "ike", Kind: model.KindXFRMIKEv2, Interface: "xfrm0",
		Spec: model.Spec{XFRMIKEv2: &model.XFRMIKEv2Spec{
			UnderlayInterface: "eth0", LocalAddress: "%any", RemoteAddress: "192.0.2.2",
			LocalID: "left", RemoteID: "right", AuthMethod: model.IKEAuthRPK,
			RemotePublicKey: remotePublicKey, StartAction: "none",
		}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	keyID, err := privateKeyID(record)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeVICIServer{connection: connectionName(record), keyID: keyID}
	controller := newVICIController("memory.vici", time.Second)
	controller.dialContext = fake.dialContext
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := controller.ensurePrivateKey(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := controller.ensurePrivateKey(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := controller.loadConnection(ctx, record); err != nil {
		t.Fatal(err)
	}
	loaded, err := controller.connectionLoaded(ctx, record)
	if err != nil || !loaded {
		t.Fatalf("connection loaded = %t, %v", loaded, err)
	}
	if count, err := controller.countSAs(ctx, record); err != nil || count != 0 {
		t.Fatalf("SA count = %d, %v", count, err)
	}
	if err := controller.initiate(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := controller.terminate(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := controller.unloadConnection(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := controller.unloadPrivateKey(ctx, record); err != nil {
		t.Fatal(err)
	}

	psk := record
	psk.Spec.XFRMIKEv2 = &model.XFRMIKEv2Spec{
		UnderlayInterface: "eth0", LocalAddress: "%any", RemoteAddress: "192.0.2.2",
		LocalID: "left", RemoteID: "right", AuthMethod: model.IKEAuthPSK,
		PSK: "0123456789abcdef", IfID: record.Spec.XFRMIKEv2.IfID, ReqID: record.Spec.XFRMIKEv2.ReqID,
	}
	if err := model.PrepareUpdate(&psk, &record, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := controller.loadShared(ctx, psk); err != nil {
		t.Fatal(err)
	}
	if err := controller.unloadShared(ctx, psk); err != nil {
		t.Fatal(err)
	}

	fake.mu.Lock()
	commands := slices.Clone(fake.commands)
	keyLoaded := fake.keyLoaded
	connectionUp := fake.connectionUp
	sharedLoaded := fake.sharedLoaded
	fake.mu.Unlock()
	if countValue(commands, "load-key") != 1 {
		t.Fatalf("load-key commands = %v, want exactly one", commands)
	}
	for _, command := range []string{"get-keys", "load-key", "load-conn", "get-conns", "list-sas", "initiate", "terminate", "unload-conn", "unload-key", "load-shared", "unload-shared"} {
		if !slices.Contains(commands, command) {
			t.Fatalf("VICI lifecycle did not issue %q: %v", command, commands)
		}
	}
	if keyLoaded || connectionUp || sharedLoaded {
		t.Fatalf("fake VICI state was not fully unloaded: key=%t connection=%t shared=%t", keyLoaded, connectionUp, sharedLoaded)
	}
}

func countValue(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func (s *fakeVICIServer) dialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go s.serve(server)
	return client, nil
}

func (s *fakeVICIServer) serve(connection net.Conn) {
	defer connection.Close()
	for {
		packetType, name, err := readTestVICIPacket(connection)
		if err != nil {
			return
		}
		switch packetType {
		case testVICIEventRegister, testVICIEventUnregister:
			if err := writeTestVICIPacket(connection, []byte{testVICIEventConfirm}); err != nil {
				return
			}
		case testVICICmdRequest:
			values, lists := s.handle(name)
			if err := writeTestVICIResponse(connection, values, lists); err != nil {
				return
			}
		default:
			return
		}
	}
}

func (s *fakeVICIServer) handle(command string) (map[string]string, map[string][]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, command)
	values := map[string]string{"success": "yes"}
	lists := make(map[string][]string)
	switch command {
	case "get-keys":
		if s.keyLoaded {
			lists["keys"] = []string{s.keyID}
		}
	case "load-key":
		s.keyLoaded = true
		values["id"] = s.keyID
	case "unload-key":
		s.keyLoaded = false
	case "get-conns":
		if s.connectionUp {
			lists["conns"] = []string{s.connection}
		}
	case "load-conn":
		s.connectionUp = true
	case "unload-conn":
		s.connectionUp = false
	case "load-shared":
		s.sharedLoaded = true
	case "unload-shared":
		s.sharedLoaded = false
	case "list-sas", "initiate", "terminate", "version":
	default:
		values["success"] = "no"
		values["errmsg"] = "unsupported fake command"
	}
	return values, lists
}

func readTestVICIPacket(reader io.Reader) (byte, string, error) {
	lengthData := make([]byte, 4)
	if _, err := io.ReadFull(reader, lengthData); err != nil {
		return 0, "", err
	}
	payload := make([]byte, binary.BigEndian.Uint32(lengthData))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return 0, "", err
	}
	if len(payload) == 0 {
		return 0, "", errors.New("empty VICI packet")
	}
	packetType := payload[0]
	if packetType != testVICICmdRequest && packetType != testVICIEventRegister && packetType != testVICIEventUnregister {
		return packetType, "", nil
	}
	if len(payload) < 2 || int(payload[1])+2 > len(payload) {
		return 0, "", errors.New("malformed named VICI packet")
	}
	return packetType, string(payload[2 : 2+int(payload[1])]), nil
}

func writeTestVICIResponse(writer io.Writer, values map[string]string, lists map[string][]string) error {
	payload := bytes.NewBuffer([]byte{testVICICmdResponse})
	for key, value := range values {
		payload.WriteByte(testVICIKeyValue)
		payload.WriteByte(byte(len(key)))
		payload.WriteString(key)
		_ = binary.Write(payload, binary.BigEndian, uint16(len(value)))
		payload.WriteString(value)
	}
	for key, items := range lists {
		payload.WriteByte(testVICIListStart)
		payload.WriteByte(byte(len(key)))
		payload.WriteString(key)
		for _, item := range items {
			payload.WriteByte(testVICIListItem)
			_ = binary.Write(payload, binary.BigEndian, uint16(len(item)))
			payload.WriteString(item)
		}
		payload.WriteByte(testVICIListEnd)
	}
	return writeTestVICIPacket(writer, payload.Bytes())
}

func writeTestVICIPacket(writer io.Writer, payload []byte) error {
	frame := bytes.NewBuffer(nil)
	if err := binary.Write(frame, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	if _, err := frame.Write(payload); err != nil {
		return err
	}
	_, err := writer.Write(frame.Bytes())
	return err
}
