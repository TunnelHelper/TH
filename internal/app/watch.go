package app

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/TunnelHelper/TH/internal/control"
)

func runWatch(client *control.Client, args []string) error {
	after, err := parseAfterOption(args)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	encoder := json.NewEncoder(os.Stdout)
	firstConnection := true
	for {
		events, streamErrors, err := client.WatchEvents(ctx, after)
		if err != nil {
			if firstConnection {
				return err
			}
			if !waitForReconnect(ctx) {
				return nil
			}
			continue
		}
		firstConnection = false
		streamEnded := false
		for !streamEnded {
			select {
			case <-ctx.Done():
				return nil
			case event, ok := <-events:
				if !ok {
					events = nil
					if streamErrors == nil {
						streamEnded = true
					}
					continue
				}
				if event.Sequence > after {
					after = event.Sequence
				}
				if err := encoder.Encode(event); err != nil {
					return err
				}
			case streamErr, ok := <-streamErrors:
				if !ok {
					streamErrors = nil
					if events == nil {
						streamEnded = true
					}
					continue
				}
				if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
					streamEnded = true
				}
			}
		}
		if !waitForReconnect(ctx) {
			return nil
		}
	}
}

func waitForReconnect(ctx context.Context) bool {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func parseAfterOption(args []string) (uint64, error) {
	if len(args) == 1 {
		return 0, nil
	}
	if len(args) != 3 || args[1] != "--after" {
		return 0, usageError()
	}
	after, err := strconv.ParseUint(args[2], 10, 64)
	if err != nil {
		return 0, errors.New("--after must be an unsigned event sequence")
	}
	return after, nil
}
