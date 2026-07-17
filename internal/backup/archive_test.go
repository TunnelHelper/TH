package backup

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/TunnelHelper/TH/internal/model"
)

func TestAgeArchiveRoundTripAndAuthentication(t *testing.T) {
	record := model.Tunnel{
		Name: "wg", Kind: model.KindWireGuard, Interface: "wg0",
		Spec: model.Spec{WireGuard: &model.WireGuardSpec{}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	archive := Archive{
		FormatVersion: FormatVersion, ProductVersion: "test", SchemaVersion: model.SchemaVersion,
		CreatedAt: time.Now().UTC(), Tunnels: []model.Tunnel{record},
	}
	if err := SealArchive(&archive); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	passphrase := "correct horse battery staple"
	if err := Encrypt(&encrypted, passphrase, archive); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte(record.Spec.WireGuard.PrivateKey)) {
		t.Fatal("encrypted backup contains plaintext private key")
	}
	decoded, err := Decrypt(bytes.NewReader(encrypted.Bytes()), passphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, archive) {
		t.Fatalf("decoded archive differs: %+v", decoded)
	}
	if _, err := Decrypt(bytes.NewReader(encrypted.Bytes()), "incorrect passphrase value"); err == nil {
		t.Fatal("wrong passphrase decrypted archive")
	}
	tampered := append([]byte(nil), encrypted.Bytes()...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := Decrypt(bytes.NewReader(tampered), passphrase); err == nil {
		t.Fatal("tampered archive decrypted successfully")
	}
}

func TestArchiveAllowsEmptyDesiredState(t *testing.T) {
	archive := Archive{
		FormatVersion: FormatVersion, ProductVersion: "test", SchemaVersion: model.SchemaVersion, CreatedAt: time.Now().UTC(),
	}
	if err := SealArchive(&archive); err != nil {
		t.Fatal(err)
	}
	var encrypted bytes.Buffer
	if err := Encrypt(&encrypted, "empty archive passphrase", archive); err != nil {
		t.Fatal(err)
	}
	if _, err := Decrypt(bytes.NewReader(encrypted.Bytes()), "empty archive passphrase"); err != nil {
		t.Fatal(err)
	}
}

func TestPassphraseValidation(t *testing.T) {
	if err := ValidatePassphrase("too-short"); err == nil {
		t.Fatal("short passphrase was accepted")
	}
	if err := ValidatePassphrase("valid passphrase\nwith newline"); err == nil {
		t.Fatal("passphrase with newline was accepted")
	}
}
