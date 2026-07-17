package backup

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/TunnelHelper/TH/internal/model"
)

const (
	FormatVersion      = 1
	MaxPlaintextBytes  = 256 << 20
	MaxEncryptedBytes  = MaxPlaintextBytes + (1 << 20)
	MaxPassphraseBytes = 1024
)

type Archive struct {
	FormatVersion  int            `json:"format_version"`
	ProductVersion string         `json:"product_version"`
	SchemaVersion  int            `json:"schema_version"`
	CreatedAt      time.Time      `json:"created_at"`
	ContentSHA256  string         `json:"content_sha256"`
	Tunnels        []model.Tunnel `json:"tunnels"`
}

func SealArchive(archive *Archive) error {
	if archive == nil {
		return errors.New("backup archive is required")
	}
	digest, err := archiveDigest(*archive)
	if err != nil {
		return err
	}
	archive.ContentSHA256 = fmt.Sprintf("%x", digest)
	return nil
}

func ValidatePassphrase(passphrase string) error {
	if len(passphrase) < 12 {
		return errors.New("backup passphrase must contain at least 12 bytes")
	}
	if len(passphrase) > MaxPassphraseBytes {
		return fmt.Errorf("backup passphrase exceeds %d bytes", MaxPassphraseBytes)
	}
	if strings.ContainsAny(passphrase, "\x00\r\n") {
		return errors.New("backup passphrase must not contain NUL or newlines")
	}
	return nil
}

func ValidateArchive(archive Archive) error {
	if archive.FormatVersion != FormatVersion {
		return fmt.Errorf("backup format_version must be %d", FormatVersion)
	}
	if archive.ProductVersion == "" {
		return errors.New("backup product_version is required")
	}
	if archive.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("backup schema_version %d is incompatible with daemon schema %d", archive.SchemaVersion, model.SchemaVersion)
	}
	if archive.CreatedAt.IsZero() {
		return errors.New("backup created_at is required")
	}
	for index := range archive.Tunnels {
		if err := model.Validate(&archive.Tunnels[index]); err != nil {
			return fmt.Errorf("backup tunnel %d: %w", index, err)
		}
	}
	digest, err := archiveDigest(archive)
	if err != nil {
		return err
	}
	if archive.ContentSHA256 != fmt.Sprintf("%x", digest) {
		return errors.New("backup content SHA-256 mismatch")
	}
	return nil
}

func archiveDigest(archive Archive) ([sha256.Size]byte, error) {
	payload := struct {
		FormatVersion  int            `json:"format_version"`
		ProductVersion string         `json:"product_version"`
		SchemaVersion  int            `json:"schema_version"`
		CreatedAt      time.Time      `json:"created_at"`
		Tunnels        []model.Tunnel `json:"tunnels"`
	}{
		FormatVersion: archive.FormatVersion, ProductVersion: archive.ProductVersion,
		SchemaVersion: archive.SchemaVersion, CreatedAt: archive.CreatedAt, Tunnels: archive.Tunnels,
	}
	hash := sha256.New()
	if err := json.NewEncoder(hash).Encode(payload); err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode backup checksum payload: %w", err)
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

func Encrypt(writer io.Writer, passphrase string, archive Archive) error {
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	if err := ValidateArchive(archive); err != nil {
		return err
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return fmt.Errorf("prepare age recipient: %w", err)
	}
	encrypted, err := age.Encrypt(writer, recipient)
	if err != nil {
		return fmt.Errorf("start age encryption: %w", err)
	}
	limited := &maxWriter{writer: encrypted, remaining: MaxPlaintextBytes}
	encodeErr := json.NewEncoder(limited).Encode(archive)
	closeErr := encrypted.Close()
	if err := errors.Join(encodeErr, closeErr); err != nil {
		return fmt.Errorf("encrypt backup archive: %w", err)
	}
	return nil
}

func Decrypt(reader io.Reader, passphrase string) (Archive, error) {
	if err := ValidatePassphrase(passphrase); err != nil {
		return Archive{}, err
	}
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return Archive{}, fmt.Errorf("prepare age identity: %w", err)
	}
	plaintext, err := age.Decrypt(io.LimitReader(reader, MaxEncryptedBytes+1), identity)
	if err != nil {
		return Archive{}, fmt.Errorf("decrypt age backup: %w", err)
	}
	limited := &io.LimitedReader{R: plaintext, N: MaxPlaintextBytes + 1}
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var archive Archive
	if err := decoder.Decode(&archive); err != nil {
		return Archive{}, fmt.Errorf("decode backup archive: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Archive{}, errors.New("backup archive must contain exactly one JSON value")
	}
	if limited.N <= 0 {
		return Archive{}, errors.New("backup plaintext exceeds 256 MiB")
	}
	if err := ValidateArchive(archive); err != nil {
		return Archive{}, err
	}
	return archive, nil
}

type maxWriter struct {
	writer    io.Writer
	remaining int64
}

func (w *maxWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, errors.New("backup plaintext exceeds 256 MiB")
	}
	written, err := w.writer.Write(data)
	w.remaining -= int64(written)
	return written, err
}
