package version

import "runtime"

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
