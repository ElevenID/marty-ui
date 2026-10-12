package main

import (
	"os"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/backend"
	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

func main() {
	meta := &api.PluginAPIClientMeta{}
	flags := meta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(1)
	}
	if err := plugin.ServeMultiplex(&plugin.ServeOpts{
		BackendFactoryFunc: backend.Factory,
		TLSProviderFunc:    api.VaultPluginTLSProvider(meta.GetTLSConfig()),
	}); err != nil {
		hclog.New(nil).Error("plugin shutting down", "error", err)
		os.Exit(1)
	}
}
