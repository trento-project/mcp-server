// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:gochecknoglobals
package server

var (
	BearerTokenEnv             = bearerTokenEnv
	CheckAPIServerConnectivity = checkAPIServerConnectivity
	CreateLivenessChecker      = createLivenessChecker
	CreateMCPServer            = createMCPServer
	CreateReadinessChecker     = createReadinessChecker
	HandleMCPServerRun         = handleMCPServerRun
	HandleToolsRegistration    = handleToolsRegistration
	LoadOpenAPISpec            = loadOpenAPISpec
	LoadOpenAPISpecFromURL     = loadOpenAPISpecFromURL
	MethodCallTool             = methodCallTool
	MethodInitialize           = methodInitialize
	RegisterToolsFromSpec      = registerToolsFromSpec
	SessionBearerTokenKey      = sessionBearerTokenKey
	SessionTokens              = &sessionTokens
	SetAPIKeyInContext         = setAPIKeyInContext
	StartHealthServer          = startHealthServer
	StartSSEServer             = startSSEServer
	StartServer                = startServer
	StartStreamableHTTPServer  = startStreamableHTTPServer
	WaitForShutdown            = waitForShutdown
	WithAuthMiddleware         = withAuthMiddleware
	WithLogger                 = withLogger
)
