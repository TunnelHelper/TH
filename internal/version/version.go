package version

import (
	"runtime"
	"strings"
)

var (
	Version = "dev"
	Commit  = "unknown"
	Date    = ""
)

type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func Current() Info {
	return Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

// Label returns compact build metadata for secondary UI text.
func (i Info) Label() string {
	productVersion := strings.TrimSpace(i.Version)
	if productVersion == "" {
		productVersion = "dev"
	}
	commit := strings.TrimSpace(i.Commit)
	if commit == "" || commit == "unknown" {
		return productVersion
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	return productVersion + "  " + commit
}
