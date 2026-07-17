package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/TunnelHelper/TH/internal/app"
)

func main() {
	if err := app.Run(os.Args[1:]); err != nil {
		if errors.Is(err, app.ErrAborted) {
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
