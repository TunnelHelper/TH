//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	linuxbackend "github.com/TunnelHelper/TH/internal/backend/linux"
	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/core"
	"github.com/TunnelHelper/TH/internal/store"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("thd", flag.ContinueOnError)
	configPath := flags.String("config", config.DefaultConfigPath, "daemon settings file")
	stateDir := flags.String("state-dir", "", "override persistent state directory")
	runtimeDir := flags.String("runtime-dir", "", "override runtime directory")
	socketPath := flags.String("socket", "", "override control socket path")
	viciSocket := flags.String("vici-socket", "", "override strongSwan VICI socket path")
	socketGID := flags.Int("socket-gid", -1, "override control socket group ID")
	reconcileInterval := flags.Duration("reconcile-interval", 0, "override reconcile interval")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("thd does not accept positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("thd must run as root")
	}

	settings, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *stateDir != "" {
		settings.StateDir = *stateDir
	}
	if *runtimeDir != "" {
		settings.RuntimeDir = *runtimeDir
	}
	if *socketPath != "" {
		settings.SocketPath = *socketPath
	}
	if *viciSocket != "" {
		settings.VICISocketPath = *viciSocket
	}
	if *socketGID >= 0 {
		settings.SocketGID = *socketGID
	}
	if *reconcileInterval > 0 {
		settings.ReconcileIntervalSeconds = int(reconcileInterval.Round(time.Second) / time.Second)
	}
	if err := settings.Validate(); err != nil {
		return err
	}
	if err := settings.ResolveSocketGID(); err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	records, err := store.Open(settings.StateDir)
	if err != nil {
		return err
	}
	backend, err := linuxbackend.New(settings)
	if err != nil {
		return err
	}
	reconciler := core.NewReconciler(records, backend, settings.ReconcileInterval())
	manager := core.NewManager(records, reconciler)
	server := control.NewServer(manager)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		reconciler.Run(ctx)
	}()

	serveErr := control.ServeUnix(ctx, settings, server.Handler(), logger)
	stop()
	workers.Wait()
	closeErr := reconciler.Close()
	return errors.Join(serveErr, closeErr)
}
