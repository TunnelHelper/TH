package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/sudogeeker/tunnel-helper/internal/config"
	"github.com/sudogeeker/tunnel-helper/internal/control"
)

var ErrAborted = errors.New("aborted")

func Run(args []string) error {
	flags := flag.NewFlagSet("tunnel-helper", flag.ContinueOnError)
	socketDefault := os.Getenv("TUNNEL_HELPER_SOCKET")
	if socketDefault == "" {
		socketDefault = config.Defaults().SocketPath
	}
	socket := flags.String("socket", socketDefault, "tunnel-helperd control socket")
	timeout := flags.Duration("timeout", 15*time.Second, "daemon request timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	client := control.NewClient(*socket, *timeout)
	defer client.CloseIdleConnections()

	remaining := flags.Args()
	if len(remaining) == 0 || remaining[0] == "tui" {
		if len(remaining) > 1 {
			return errors.New("tui does not accept positional arguments")
		}
		return runTUI(client, *timeout)
	}
	return runCLI(client, *timeout, remaining)
}

func wrapAbort(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) || errors.Is(err, huh.ErrUserAborted) || strings.Contains(err.Error(), "interrupt") {
		return ErrAborted
	}
	return err
}

func usageError() error {
	return fmt.Errorf("usage: tunnel-helper [--socket PATH] [tui|health|list|get ID|create FILE|update FILE|enable ID|disable ID|delete ID|reconcile [ID]]")
}
