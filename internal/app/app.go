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
	flags.Usage = func() { fmt.Fprint(flags.Output(), usageText) }
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
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
	return errors.New(strings.TrimSpace(usageText))
}

const usageText = `Usage: th [global options] [command]

Interactive commands:
  tui                         Open the tunnel manager (default)
  help                        Show this help
  version                     Show client version
  doctor                      Diagnose daemon connectivity
  health                      Show backend health
  watch [--after SEQUENCE]    Stream status events

Tunnel commands:
  list | get ID
  create FILE [--wait] | update FILE [--wait]
  enable ID [--wait] | disable ID [--wait]
  delete ID | reconcile [ID]

Configuration and recovery:
  export --redacted [--output FILE]
  validate PATH | plan PATH [--prune] | apply PATH [--prune] [--wait]
  backup FILE [--passphrase-file FILE]
  restore FILE [--passphrase-file FILE] [--check] [--wait]

Global options:
  --socket PATH               thd control socket
  --timeout DURATION          daemon request timeout
  --version                   show client version
`
