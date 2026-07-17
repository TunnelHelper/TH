package app

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicNewFileNeverOverwritesExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.age")
	if err := os.WriteFile(path, []byte("existing"), 0600); err != nil {
		t.Fatal(err)
	}
	err := writeAtomicNewFile(path, 0600, func(writer io.Writer) error {
		_, err := writer.Write([]byte("replacement"))
		return err
	})
	if err == nil {
		t.Fatal("existing output path was accepted")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "existing" {
		t.Fatalf("existing output changed to %q", data)
	}
}

func TestWriteAtomicNewFilePublishesCompleteModeProtectedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backup.age")
	if err := writeAtomicNewFile(path, 0600, func(writer io.Writer) error {
		_, err := writer.Write([]byte("complete"))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("mode = %04o", info.Mode().Perm())
	}
	data, _ := os.ReadFile(path)
	if string(data) != "complete" {
		t.Fatalf("data = %q", data)
	}
}

func TestPassphraseFileRequiresPrivateRegularFile(t *testing.T) {
	t.Setenv("TH_BACKUP_PASSPHRASE", "")
	directory := t.TempDir()
	path := filepath.Join(directory, "passphrase")
	if err := os.WriteFile(path, []byte("private backup passphrase\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupPassphrase(path, false); err == nil {
		t.Fatal("world-readable passphrase file was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	passphrase, err := readBackupPassphrase(path, false)
	if err != nil || passphrase != "private backup passphrase" {
		t.Fatalf("passphrase = %q, %v", passphrase, err)
	}
	link := filepath.Join(directory, "passphrase-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBackupPassphrase(link, false); err == nil {
		t.Fatal("symlink passphrase file was accepted")
	}
}
