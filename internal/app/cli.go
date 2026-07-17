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
		if len(args) != 2 {
			return usageError()
		}
		record, err := readTunnel(args[1])
		if err != nil {
			return err
		}
		value, err := client.Create(ctx, record)
		return outputJSON(value, err)
	case "update":
		if len(args) != 2 {
			return usageError()
		}
		record, err := readTunnel(args[1])
		if err != nil {
			return err
		}
		if record.ID == "" || record.Generation == 0 {
			return errors.New("updated record requires id and generation")
		}
		value, err := client.Update(ctx, model.TunnelView{Tunnel: record})
		return outputJSON(value, err)
	case "enable", "disable":
		if len(args) != 2 {
			return usageError()
		}
		view, err := client.Get(ctx, args[1])
		if err != nil {
			return err
		}
		value, err := client.SetEnabled(ctx, view, command == "enable")
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
