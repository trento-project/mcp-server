// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

package cmd_test

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/trento-project/mcp-server/cmd"
	"github.com/trento-project/mcp-server/internal/server"
	"github.com/trento-project/mcp-server/internal/utils"
)

func TestParseFlagsCorrect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        []string
		expConf     server.ServeOptions
		errExpected bool
	}{
		{
			name: "all arguments are captured",
			args: []string{
				"--port", "9090",
				"--oasPath", "/tmp/api.json",
				"--transport", "sse",
				"--base-url", "http://example.com/mcp",
				"--oauth-enabled",
				"--oauth-authorization-server-url", "http://auth.example.com/auth",
				"--oauth-issuer", "http://auth.example.com",
				"--oauth-validate-url", "http://auth.example.com/validate",
				"--trento-url", "http://trento.example.com",
				"--trento-username", "trento",
				"--trento-password", "trento-pass",
				"--verbosity", "-1",
			},
			expConf: server.ServeOptions{
				Port:                        9090,
				OASPath:                     "/tmp/api.json",
				Transport:                   utils.TransportSSE,
				McpBaseURL:                  "http://example.com/mcp",
				OauthEnabled:                true,
				OauthAuthorizationServerURL: "http://auth.example.com/auth",
				OauthIssuer:                 "http://auth.example.com",
				OauthValidateURL:            "http://auth.example.com/validate",
				TrentoURL:                   "http://trento.example.com",
				TrentoUsername:              "trento",
				TrentoPassword:              "trento-pass",
			},
			errExpected: false,
		},
		{
			name: "default values",
			args: []string{},
			expConf: server.ServeOptions{
				Port:                        5000,
				OASPath:                     "./api/openapi.json",
				Transport:                   utils.TransportStreamable,
				McpBaseURL:                  "",
				OauthEnabled:                false,
				OauthAuthorizationServerURL: "https://my-idp.example.com/.well-known/openid-configuration",
				OauthIssuer:                 "https://my-idp.example.com/",
				OauthValidateURL:            "https://my-idp.example.com/userinfo",
				TrentoURL:                   "https://demo.trento-project.io",
				TrentoUsername:              "demo",
				TrentoPassword:              "demopass",
			},
			errExpected: false,
		},
		{
			name:        "invalid transport",
			args:        []string{"--transport", "invalid-transport"},
			expConf:     server.ServeOptions{}, // not checked on error
			errExpected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Do not run in parallel because they modify a global variable (serveOpts)
			b := bytes.NewBufferString("")
			command := cmd.NewRootCmd()
			// We only want to test flags, not the server execution
			command.RunE = func(_ *cobra.Command, _ []string) error { return nil }
			command.SetOut(b)
			command.SetErr(b)
			cmd.SetFlags(command)
			command.SetArgs(tt.args)
			err := command.Execute()

			if !tt.errExpected {
				require.NoError(t, err)

				opts := cmd.ServeOpts()
				// Name and Version are set automatically.
				tt.expConf.Name = opts.Name
				tt.expConf.Version = opts.Version
				assert.Equal(t, tt.expConf, opts)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestInitLogger(t *testing.T) {
	t.Parallel()

	err := cmd.InitLogger(cmd.NewRootCmd(), []string{})
	require.NoError(t, err)
}

func TestVersion(t *testing.T) {
	t.Parallel()

	v := cmd.Version()
	assert.Contains(t, v, "devel")
}
