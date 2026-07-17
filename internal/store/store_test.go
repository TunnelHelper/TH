package store

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sudogeeker/tunnel-helper/internal/model"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestFileStoreLifecycleAndPermissions(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	records, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	record := preparedGRE(t, "one", "gre0")
	if err := records.Create(record); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "tunnels", record.ID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("record mode = %04o, want 0600", info.Mode().Perm())
	}
	loaded, err := records.Get(record.ID)
	if err != nil || loaded.Name != record.Name {
		t.Fatalf("Get = %+v, %v", loaded, err)
	}
	loaded.Name = "renamed"
	if err := model.PrepareUpdate(&loaded, &record, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := records.Update(loaded, record.Generation); err != nil {
		t.Fatal(err)
	}
	if err := records.Update(loaded, record.Generation); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update error = %v, want ErrConflict", err)
	}
	cacheDir := filepath.Join(stateDir, "cache", "srv6", record.ID)
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "feed.txt"), []byte("cached"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := records.Delete(record.ID, loaded.Generation); err != nil {
		t.Fatal(err)
	}
	if _, err := records.Get(record.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
	if _, err := os.Lstat(cacheDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record cache remains after delete: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(stateDir, "tunnels"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("unexpected files after delete: %v, %v", entries, err)
	}
}

func TestFileStoreRejectsCollisions(t *testing.T) {
	records, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	one := preparedGRE(t, "one", "gre0")
	if err := records.Create(one); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []model.Tunnel{
		preparedGRE(t, "one", "gre1"),
		preparedGRE(t, "two", "gre0"),
	} {
		if err := records.Create(candidate); !errors.Is(err, ErrConflict) {
			t.Fatalf("collision error = %v, want ErrConflict", err)
		}
	}
	peer, _ := wgtypes.GeneratePrivateKey()
	firstWG := preparedWireGuard(t, "wg-one", "wg0", peer.PublicKey().String())
	secondWG := preparedWireGuard(t, "wg-two", "wg1", peer.PublicKey().String())
	if err := records.Create(firstWG); err != nil {
		t.Fatal(err)
	}
	if err := records.Create(secondWG); !errors.Is(err, ErrConflict) {
		t.Fatalf("managed route collision error = %v, want ErrConflict", err)
	}
	srv6 := preparedSRv6(t, "srv6", 1000)
	if err := records.Create(srv6); !errors.Is(err, ErrConflict) {
		t.Fatalf("exclusive SRv6 table collision error = %v, want ErrConflict", err)
	}
}

func preparedWireGuard(t *testing.T, name, iface, peerKey string) model.Tunnel {
	t.Helper()
	record := model.Tunnel{
		Name: name, Kind: model.KindWireGuard, Interface: iface,
		Spec: model.Spec{WireGuard: &model.WireGuardSpec{
			RouteAllowedIPs: true,
			RouteTable:      1000,
			Peers: []model.WireGuardPeer{{
				PublicKey: peerKey, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/24")},
			}},
		}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}

func preparedSRv6(t *testing.T, name string, table int) model.Tunnel {
	t.Helper()
	sid := netip.MustParseAddr("2001:db8::1")
	record := model.Tunnel{
		Name: name, Kind: model.KindSRv6,
		Spec: model.Spec{SRv6: &model.SRv6Spec{
			BaseURL: "https://routes.example/", UnderlayInterface: "eth0", Table: table,
			Sources: []model.SRv6Source{{Name: "carrier", SIDv4: &sid, MTU: 1500}},
		}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestFileStoreRejectsUnsafeOrMalformedRecords(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	records, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := model.NewID()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(stateDir, "tunnels", id+".json")
	if err := os.WriteFile(path, []byte("{}\n{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := records.Get(id); err == nil {
		t.Fatal("unsafe malformed record was accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/dev/null", path); err != nil {
		t.Fatal(err)
	}
	if _, err := records.Get(id); err == nil {
		t.Fatal("symlink record was accepted")
	}
}

func TestOpenRejectsSymlinkStateDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink state directory was accepted")
	}
}

func TestOpenRejectsFilesystemRoot(t *testing.T) {
	if _, err := Open(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root was accepted as the state directory")
	}
}

func preparedGRE(t *testing.T, name, iface string) model.Tunnel {
	t.Helper()
	record := model.Tunnel{
		Name: name, Kind: model.KindGRE, Interface: iface,
		Spec: model.Spec{GRE: &model.GRESpec{Local: netip.MustParseAddr("192.0.2.1"), Remote: netip.MustParseAddr("192.0.2.2")}},
	}
	if err := model.PrepareNew(&record, time.Now()); err != nil {
		t.Fatal(err)
	}
	return record
}
