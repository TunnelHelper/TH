package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	backupformat "github.com/TunnelHelper/TH/internal/backup"
	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

func runExport(ctx context.Context, client *control.Client, args []string) error {
	redacted := false
	outputPath := ""
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--redacted":
			if redacted {
				return errors.New("--redacted may be specified once")
			}
			redacted = true
		case "--output":
			index++
			if index >= len(args) || outputPath != "" {
				return usageError()
			}
			outputPath = args[index]
		default:
			return usageError()
		}
	}
	if !redacted {
		return errors.New("export requires --redacted; use root-only backup for secret material")
	}
	views, err := client.List(ctx)
	if err != nil {
		return err
	}
	bundle := model.Bundle{BundleVersion: model.BundleVersion, Tunnels: make([]model.Tunnel, 0, len(views))}
	for _, view := range views {
		bundle.Tunnels = append(bundle.Tunnels, view.Tunnel)
	}
	if outputPath == "" || outputPath == "-" {
		return outputJSON(bundle, nil)
	}
	return writeAtomicNewFile(outputPath, 0600, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(bundle)
	})
}

func runBackup(ctx context.Context, client *control.Client, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("backup requires root")
	}
	path, passphraseFile, err := parseBackupArgs(args)
	if err != nil {
		return err
	}
	passphrase, err := readBackupPassphrase(passphraseFile, true)
	if err != nil {
		return err
	}
	if err := writeAtomicNewFile(path, 0600, func(writer io.Writer) error {
		return client.Backup(ctx, passphrase, writer)
	}); err != nil {
		return err
	}
	return outputJSON(struct {
		Path      string `json:"path"`
		Encrypted bool   `json:"encrypted"`
	}{Path: path, Encrypted: true}, nil)
}

func runRestore(ctx context.Context, client *control.Client, args []string) error {
	if os.Geteuid() != 0 {
		return errors.New("restore requires root")
	}
	path, passphraseFile, check, wait, err := parseRestoreArgs(args)
	if err != nil {
		return err
	}
	passphrase, err := readBackupPassphrase(passphraseFile, false)
	if err != nil {
		return err
	}
	file, err := openBackupFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	result, err := client.RestoreBackup(ctx, passphrase, file, check, wait)
	return outputJSON(result, err)
}

func parseBackupArgs(args []string) (path, passphraseFile string, err error) {
	positionals := make([]string, 0, 1)
	for index := 1; index < len(args); index++ {
		if args[index] == "--passphrase-file" {
			index++
			if index >= len(args) || passphraseFile != "" {
				return "", "", usageError()
			}
			passphraseFile = args[index]
			continue
		}
		positionals = append(positionals, args[index])
	}
	if len(positionals) != 1 {
		return "", "", usageError()
	}
	return positionals[0], passphraseFile, nil
}

func parseRestoreArgs(args []string) (path, passphraseFile string, check, wait bool, err error) {
	positionals := make([]string, 0, 1)
	for index := 1; index < len(args); index++ {
		switch args[index] {
		case "--passphrase-file":
			index++
			if index >= len(args) || passphraseFile != "" {
				return "", "", false, false, usageError()
			}
			passphraseFile = args[index]
		case "--check":
			if check {
				return "", "", false, false, errors.New("--check may be specified once")
			}
			check = true
		case "--wait":
			if wait {
				return "", "", false, false, errors.New("--wait may be specified once")
			}
			wait = true
		default:
			positionals = append(positionals, args[index])
		}
	}
	if len(positionals) != 1 {
		return "", "", false, false, usageError()
	}
	return positionals[0], passphraseFile, check, wait, nil
}

func readBackupPassphrase(path string, confirm bool) (string, error) {
	var passphrase string
	if path != "" {
		file, info, err := openRegularNoFollow(path)
		if err != nil {
			return "", fmt.Errorf("inspect passphrase file: %w", err)
		}
		defer file.Close()
		if info.Mode().Perm()&0077 != 0 {
			return "", fmt.Errorf("passphrase file has unsafe mode %04o", info.Mode().Perm())
		}
		data, err := io.ReadAll(io.LimitReader(file, backupformat.MaxPassphraseBytes+3))
		if err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
		if len(data) > backupformat.MaxPassphraseBytes+2 {
			return "", errors.New("passphrase file is too large")
		}
		passphrase = strings.TrimRight(string(data), "\r\n")
	} else if value := os.Getenv("TH_BACKUP_PASSPHRASE"); value != "" {
		passphrase = value
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", errors.New("set TH_BACKUP_PASSPHRASE, use --passphrase-file, or run from a terminal")
		}
		operation := "Restore"
		if confirm {
			operation = "Backup"
		}
		fmt.Fprintf(os.Stderr, "%s passphrase: ", operation)
		data, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		passphrase = string(data)
		if confirm {
			fmt.Fprint(os.Stderr, "Confirm passphrase: ")
			confirmation, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			if passphrase != string(confirmation) {
				return "", errors.New("backup passphrases do not match")
			}
		}
	}
	if err := backupformat.ValidatePassphrase(passphrase); err != nil {
		return "", err
	}
	return passphrase, nil
}

func openBackupFile(path string) (*os.File, error) {
	file, info, err := openRegularNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("inspect backup file: %w", err)
	}
	if info.Size() > backupformat.MaxEncryptedBytes {
		file.Close()
		return nil, errors.New("encrypted backup exceeds size limit")
	}
	return file, nil
}

func openRegularNoFollow(path string) (*os.File, os.FileInfo, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, nil, errors.New("path is not a regular file")
	}
	return file, info, nil
}

func writeAtomicNewFile(path string, mode os.FileMode, write func(io.Writer) error) error {
	directory := filepath.Dir(path)
	if directory == "" {
		directory = "."
	}
	temporary, err := os.CreateTemp(directory, ".th-output-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if err := write(temporary); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return fmt.Errorf("publish output without replacing an existing file: %w", err)
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}
