package control

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
)

func ServeUnix(ctx context.Context, settings config.Settings, handler http.Handler, logger *slog.Logger) error {
	listener, socketInfo, err := listenUnix(settings)
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
		removeOwnedSocket(settings.SocketPath, socketInfo)
	}()

	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       settings.RequestTimeout(),
		WriteTimeout:      settings.RequestTimeout() + 5*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()

	logger.Info("control API listening", "socket", settings.SocketPath)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	if ctx.Err() != nil {
		<-shutdownDone
	}
	return err
}

func listenUnix(settings config.Settings) (*net.UnixListener, os.FileInfo, error) {
	if settings.SocketGID < 0 {
		return nil, nil, errors.New("control socket group has not been resolved")
	}
	if err := os.MkdirAll(settings.RuntimeDir, 0750); err != nil {
		return nil, nil, fmt.Errorf("create runtime directory: %w", err)
	}
	runtimeInfo, err := os.Lstat(settings.RuntimeDir)
	if err != nil {
		return nil, nil, fmt.Errorf("inspect runtime directory: %w", err)
	}
	if !runtimeInfo.IsDir() || runtimeInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("runtime path %s is not a real directory", settings.RuntimeDir)
	}
	if err := os.Chown(settings.RuntimeDir, 0, settings.SocketGID); err != nil {
		return nil, nil, fmt.Errorf("set runtime directory ownership: %w", err)
	}
	if err := os.Chmod(settings.RuntimeDir, 0750); err != nil {
		return nil, nil, fmt.Errorf("set runtime directory mode: %w", err)
	}
	if err := removeStaleSocket(settings.SocketPath, settings.RequestTimeout()); err != nil {
		return nil, nil, err
	}
	address := &net.UnixAddr{Name: settings.SocketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, nil, fmt.Errorf("listen on control socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(settings.SocketPath, os.FileMode(settings.SocketMode)); err != nil {
		_ = listener.Close()
		_ = os.Remove(settings.SocketPath)
		return nil, nil, fmt.Errorf("set control socket mode: %w", err)
	}
	if err := os.Chown(settings.SocketPath, 0, settings.SocketGID); err != nil {
		_ = listener.Close()
		_ = os.Remove(settings.SocketPath)
		return nil, nil, fmt.Errorf("set control socket ownership: %w", err)
	}
	info, err := os.Lstat(settings.SocketPath)
	if err != nil {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("stat control socket: %w", err)
	}
	return listener, info, nil
}

func removeStaleSocket(path string, timeout time.Duration) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refuse to replace non-socket path %s", path)
	}
	connection, dialErr := net.DialTimeout("unix", path, timeout)
	if dialErr == nil {
		_ = connection.Close()
		return fmt.Errorf("another thd is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

func removeOwnedSocket(path string, original os.FileInfo) {
	current, err := os.Lstat(path)
	if err != nil || original == nil || !os.SameFile(original, current) {
		return
	}
	_ = os.Remove(path)
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
}
