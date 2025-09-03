// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:gochecknoglobals
package server

var (
	CreateMCPServer           = createMCPServer
	HandleServerRun           = handleServerRun
	HandleToolsRegistration   = handleToolsRegistration
	StartSSEServer            = startSSEServer
	StartStreamableHTTPServer = startStreamableHTTPServer
	WaitForShutdown           = waitForShutdown
	APIKeyAuthContextFunc     = apiKeyAuthContextFunc
)
