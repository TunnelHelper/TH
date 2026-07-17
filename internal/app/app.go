package app

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/TunnelHelper/TH/internal/config"
	"github.com/TunnelHelper/TH/internal/control"
	"github.com/TunnelHelper/TH/internal/version"
	"github.com/charmbracelet/huh"
)

var ErrAborted = errors.New("aborted")

func Run(args []string) error {
	flags := flag.NewFlagSet("th", flag.ContinueOnError)
	socketDefault := os.Getenv("TH_SOCKET")
	if socketDefault == "" {
		socketDefault = config.Defaults().SocketPath
	}
	socket := flags.String("socket", socketDefault, "thd control socket")
	timeout := flags.Duration("timeout", 15*time.Second, "daemon request timeout")
	showVersion := flags.Bool("version", false, "show client version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		return outputJSON(version.Current(), nil)
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
	return runCLI(client, *timeout, *socket, remaining)
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
	return fmt.Errorf("usage: th [--socket PATH] [tui|version|doctor|health|watch [--after SEQUENCE]|list|get ID|create FILE [--wait]|update FILE [--wait]|enable ID [--wait]|disable ID [--wait]|delete ID|reconcile [ID]]")
}
