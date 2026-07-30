package version

import "testing"

func TestInfoLabelKeepsBuildMetadataSecondary(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "defaults", info: Info{Version: "dev", Commit: "unknown"}, want: "dev"},
		{name: "empty", info: Info{}, want: "dev"},
		{name: "release", info: Info{Version: "v2.2.0", Commit: "0123456789abcdef"}, want: "v2.2.0  0123456789ab"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.info.Label(); got != test.want {
				t.Fatalf("Label() = %q, want %q", got, test.want)
			}
		})
	}
}
