// Command vault-plugin-secrets-temporalcloud serves the Temporal Cloud
// secrets engine as an external Vault plugin.
package main

import (
	"os"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"

	temporalcloud "github.com/temporal-sa/vault-plugin-temporalcloud"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		logFatal(err)
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
