package version

import "testing"

func TestServerVersion(t *testing.T) {
	oldConfig := config
	t.Cleanup(func() { SetConfig(oldConfig) })
	for _, setting := range []string{"", "short", "full", "unknown", "neutral"} {
		for _, addHash := range []bool{false, true} {
			SetConfig(setting)
			want := appName + "_" + info.Version
			if setting == "short" {
				want = appName
			}
			if addHash {
				want += "_" + info.CommitHash
			}
			if setting == "neutral" {
				want = "EDI"
			}
			if got := "SSH-2.0-" + GetServerVersion("_", addHash); got != "SSH-2.0-"+want {
				t.Errorf("setting=%q addHash=%v: got %q, want %q", setting, addHash, got, "SSH-2.0-"+want)
			}
		}
	}
}
