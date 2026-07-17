package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/model"
	"github.com/TunnelHelper/TH/internal/version"
)

func runCLI(client *control.Client, timeout time.Duration, socketPath string, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := args[0]
	switch command {
	case "version":
		if len(args) != 1 {
			return usageError()
		}
		return outputJSON(version.Current(), nil)
	case "doctor":
		if len(args) != 1 {
			return usageError()
		}
		report := diagnose(ctx, socketPath, client)
		if err := outputJSON(report, nil); err != nil {
			return err
		}
		if !report.OK {
			return ErrDoctorFailed
		}
		return nil
	case "watch":
		return runWatch(client, args)
	case "export":
		return runExport(ctx, client, args)
	case "backup":
		return runBackup(ctx, client, args)
	case "restore":
		return runRestore(ctx, client, args)
	case "validate", "plan", "apply":
		path, prune, wait, err := parseBundleCommand(args)
		if err != nil {
			return err
		}
		bundle, err := readBundle(path)
		if err != nil {
			return err
		}
		if command == "validate" {
			if prune || wait {
				return usageError()
			}
			if _, err := client.PlanBundle(ctx, bundle, false); err != nil {
				return err
			}
			return outputJSON(struct {
				Valid         bool `json:"valid"`
				BundleVersion int  `json:"bundle_version"`
				Tunnels       int  `json:"tunnels"`
			}{Valid: true, BundleVersion: bundle.BundleVersion, Tunnels: len(bundle.Tunnels)}, nil)
		}
		if command == "plan" {
			if wait {
				return usageError()
			}
			value, err := client.PlanBundle(ctx, bundle, prune)
			return outputJSON(value, err)
		}
		value, err := client.ApplyBundle(ctx, bundle, prune, wait)
		return outputJSON(value, err)
	case "health":
		if len(args) != 1 {
			return usageError()
		}
		value, err := client.Health(ctx)
		return outputJSON(value, err)
	case "list":
		if len(args) != 1 {
			return usageError()
		}
		value, err := client.List(ctx)
		return outputJSON(value, err)
	case "get":
		if len(args) != 2 {
			return usageError()
		}
		value, err := client.Get(ctx, args[1])
		return outputJSON(value, err)
	case "create":
		positionals, wait, err := parseWaitOption(args)
		if err != nil || len(positionals) != 2 {
			return usageError()
		}
		record, err := readTunnel(positionals[1])
		if err != nil {
			return err
		}
		value, err := client.CreateWithWait(ctx, record, wait)
		return outputJSON(value, err)
	case "update":
		positionals, wait, err := parseWaitOption(args)
		if err != nil || len(positionals) != 2 {
			return usageError()
		}
		record, err := readTunnel(positionals[1])
		if err != nil {
			return err
		}
		if record.ID == "" || record.Generation == 0 {
			return errors.New("updated record requires id and generation")
		}
		value, err := client.UpdateWithWait(ctx, model.TunnelView{Tunnel: record}, wait)
		return outputJSON(value, err)
	case "enable", "disable":
		positionals, wait, err := parseWaitOption(args)
		if err != nil || len(positionals) != 2 {
			return usageError()
		}
		view, err := client.Get(ctx, positionals[1])
		if err != nil {
			return err
		}
		value, err := client.SetEnabledWithWait(ctx, view, command == "enable", wait)
		return outputJSON(value, err)
	case "delete":
		if len(args) != 2 {
			return usageError()
		}
		view, err := client.Get(ctx, args[1])
		if err != nil {
			return err
		}
		return client.Delete(ctx, view)
	case "reconcile":
		if len(args) == 1 {
			value, err := client.ReconcileAll(ctx)
			return outputJSON(value, err)
		}
		if len(args) == 2 {
			value, err := client.Reconcile(ctx, args[1])
			return outputJSON(value, err)
		}
		return usageError()
	default:
		return usageError()
	}
}

func parseWaitOption(args []string) ([]string, bool, error) {
	positionals := make([]string, 0, len(args))
	wait := false
	for _, arg := range args {
		if arg != "--wait" {
			positionals = append(positionals, arg)
			continue
		}
		if wait {
			return nil, false, errors.New("--wait may be specified once")
		}
		wait = true
	}
	return positionals, wait, nil
}

func parseBundleCommand(args []string) (path string, prune, wait bool, err error) {
	positionals := make([]string, 0, 1)
	for _, arg := range args[1:] {
		switch arg {
		case "--prune":
			if prune {
				return "", false, false, errors.New("--prune may be specified once")
			}
			prune = true
		case "--wait":
			if wait {
				return "", false, false, errors.New("--wait may be specified once")
			}
			wait = true
		default:
			positionals = append(positionals, arg)
		}
	}
	if len(positionals) != 1 {
		return "", false, false, usageError()
	}
	return positionals[0], prune, wait, nil
}

func readTunnel(path string) (model.Tunnel, error) {
	var reader io.Reader
	if path == "-" {
		reader = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return model.Tunnel{}, fmt.Errorf("open tunnel JSON: %w", err)
		}
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, (4<<20)+1))
	if err != nil {
		return model.Tunnel{}, fmt.Errorf("read tunnel JSON: %w", err)
	}
	if len(data) > 4<<20 {
		return model.Tunnel{}, errors.New("tunnel JSON exceeds 4 MiB")
	}
	return decodeTunnelData(data)
}

func decodeTunnelData(data []byte) (model.Tunnel, error) {
	var record model.Tunnel
	recordErr := decodeOneJSON(data, &record)
	if recordErr == nil {
		return record, nil
	}
	var view model.TunnelView
	viewErr := decodeOneJSON(data, &view)
	if viewErr == nil {
		return view.Tunnel, nil
	}
	return model.Tunnel{}, fmt.Errorf("decode tunnel JSON: %w", errors.Join(recordErr, viewErr))
}

func decodeOneJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("tunnel JSON must contain exactly one value")
	}
	return nil
}

func outputJSON(value any, err error) error {
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
