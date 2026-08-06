// Command vault-plugin-secrets-temporalcloud serves the Temporal Cloud
// secrets engine as an external Vault plugin.
package main

import (
	"fmt"
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	temporalcloud "github.com/ausmartway/vault-plugin-secrets-temporalcloud"
)

// Build information, injected by GoReleaser at link time. The defaults are
// what you get from a plain `go build`, which is the common case during
// development.
//
// Vault gives an operator no way to ask a registered plugin which build it is
// running, so `--version` on the binary is the only way to check that the file
// in the plugin directory is the one you think it is.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()

	showVersion := flags.Bool("version", false,
		"print build information and exit")

	if err := flags.Parse(os.Args[1:]); err != nil {
		logFatal(err)
	}

	if *showVersion {
		fmt.Printf("vault-plugin-secrets-temporalcloud %s (commit %s, built %s)\n",
			version, commit, date)
		return
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: temporalcloud.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		logFatal(err)
	}
}

func logFatal(err error) {
	hclog.New(&hclog.LoggerOptions{}).Error("plugin shutting down", "error", err)
	os.Exit(1)
}
