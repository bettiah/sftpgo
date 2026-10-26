//go:build edi

// Run file-scoped via edi/test.sh only; package-mode -tags edi contaminates globals.
package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drakkan/sftpgo/v2/internal/config"
)

func TestEDIAWSIAMAuthDefaultsAndEnv(t *testing.T) {
	config.Init()
	t.Cleanup(config.Init)
	if c := config.GetProviderConf(); c.AWSIAMAuth || c.AWSIAMRegion != "" {
		t.Fatal("aws_iam_auth must default off with no region")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "iam.json"), []byte(`{"data_provider":{"aws_iam_region":"eu-central-1"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := config.LoadConfig(dir, "iam.json"); err != nil {
		t.Fatal(err)
	}
	if c := config.GetProviderConf(); c.AWSIAMAuth || c.AWSIAMRegion != "eu-central-1" {
		t.Fatalf("json: %v %q", c.AWSIAMAuth, c.AWSIAMRegion)
	}
	t.Setenv("SFTPGO_DATA_PROVIDER__AWS_IAM_AUTH", "true")
	t.Setenv("SFTPGO_DATA_PROVIDER__AWS_IAM_REGION", "eu-west-1")
	config.Init()
	if err := config.LoadConfig(dir, "iam.json"); err != nil {
		t.Fatal(err)
	}
	if c := config.GetProviderConf(); !c.AWSIAMAuth || c.AWSIAMRegion != "eu-west-1" {
		t.Fatalf("env: %v %q", c.AWSIAMAuth, c.AWSIAMRegion)
	}
}
