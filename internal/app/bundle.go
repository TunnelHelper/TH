package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TunnelHelper/TH/internal/model"
)

const maxBundleBytes = 4 << 20

func readBundle(path string) (model.Bundle, error) {
	if path == "-" {
		data, err := io.ReadAll(io.LimitReader(os.Stdin, maxBundleBytes+1))
		if err != nil {
			return model.Bundle{}, fmt.Errorf("read bundle: %w", err)
		}
		if len(data) > maxBundleBytes {
			return model.Bundle{}, errors.New("bundle exceeds 4 MiB")
		}
		return decodeBundleData(data)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return model.Bundle{}, fmt.Errorf("inspect bundle path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return model.Bundle{}, errors.New("bundle path must not be a symlink")
	}
	if info.IsDir() {
		return readBundleDirectory(path)
	}
	if !info.Mode().IsRegular() {
		return model.Bundle{}, errors.New("bundle path must be a regular file or directory")
	}
	data, err := readBundleFile(path, info.Size())
	if err != nil {
		return model.Bundle{}, err
	}
	return decodeBundleData(data)
}

func readBundleDirectory(path string) (model.Bundle, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return model.Bundle{}, fmt.Errorf("read bundle directory: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	bundle := model.Bundle{BundleVersion: model.BundleVersion}
	total := int64(0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return model.Bundle{}, fmt.Errorf("bundle file %q must not be a symlink", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return model.Bundle{}, fmt.Errorf("inspect bundle file %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return model.Bundle{}, fmt.Errorf("bundle file %q is not regular", entry.Name())
		}
		total += info.Size()
		if total > maxBundleBytes {
			return model.Bundle{}, errors.New("bundle directory exceeds 4 MiB")
		}
		data, err := readBundleFile(filepath.Join(path, entry.Name()), info.Size())
		if err != nil {
			return model.Bundle{}, err
		}
		decoded, err := decodeBundleData(data)
		if err != nil {
			return model.Bundle{}, fmt.Errorf("decode bundle file %q: %w", entry.Name(), err)
		}
		if decoded.BundleVersion != model.BundleVersion {
			return model.Bundle{}, fmt.Errorf("bundle file %q has unsupported bundle_version %d", entry.Name(), decoded.BundleVersion)
		}
		bundle.Tunnels = append(bundle.Tunnels, decoded.Tunnels...)
		if len(bundle.Tunnels) > model.MaxTunnelRecords {
			return model.Bundle{}, fmt.Errorf("bundle exceeds %d tunnels", model.MaxTunnelRecords)
		}
	}
	if len(bundle.Tunnels) == 0 {
		return model.Bundle{}, errors.New("bundle directory contains no JSON tunnel records")
	}
	return bundle, nil
}

func readBundleFile(path string, size int64) ([]byte, error) {
	if size > maxBundleBytes {
		return nil, fmt.Errorf("bundle file %q exceeds 4 MiB", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open bundle file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read bundle file: %w", err)
	}
	if len(data) > maxBundleBytes {
		return nil, fmt.Errorf("bundle file %q exceeds 4 MiB", path)
	}
	return data, nil
}

func decodeBundleData(data []byte) (model.Bundle, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return model.Bundle{}, errors.New("bundle JSON is empty")
	}
	if trimmed[0] == '[' {
		var tunnels []model.Tunnel
		if err := decodeOneJSON(trimmed, &tunnels); err != nil {
			return model.Bundle{}, fmt.Errorf("decode tunnel array: %w", err)
		}
		return model.Bundle{BundleVersion: model.BundleVersion, Tunnels: tunnels}, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &object); err != nil {
		return model.Bundle{}, fmt.Errorf("decode bundle JSON: %w", err)
	}
	if _, isBundle := object["bundle_version"]; isBundle || object["tunnels"] != nil {
		var bundle model.Bundle
		if err := decodeOneJSON(trimmed, &bundle); err != nil {
			return model.Bundle{}, fmt.Errorf("decode bundle: %w", err)
		}
		return bundle, nil
	}
	record, err := decodeTunnelData(trimmed)
	if err != nil {
		return model.Bundle{}, err
	}
	return model.Bundle{BundleVersion: model.BundleVersion, Tunnels: []model.Tunnel{record}}, nil
}
