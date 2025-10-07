// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:gochecknoglobals
package server

var (
	CheckAPIServerConnectivity = checkAPIServerConnectivity
	CheckOASDocsConnectivity   = checkOASDocsConnectivity
	CheckSingleAPIServer       = checkSingleAPIServer
	CreateLivenessChecker      = createLivenessChecker
	CreateMCPServer            = createMCPServer
	CreateReadinessChecker     = createReadinessChecker
	HandleAPIKeyAuth           = handleAPIKeyAuth
	HandleMCPServerRun         = handleMCPServerRun
	HandleToolsRegistration    = handleToolsRegistration
	LoadOpenAPISpec            = loadOpenAPISpec
	LoadOpenAPISpecFromURL     = loadOpenAPISpecFromURL
	RegisterToolsFromSpec      = registerToolsFromSpec
	StartHealthServer          = startHealthServer
	StartSSEServer             = startSSEServer
	StartServer                = startServer
	StartStreamableHTTPServer  = startStreamableHTTPServer
	WaitForShutdown            = waitForShutdown
	WithLogger                 = withLogger
)
