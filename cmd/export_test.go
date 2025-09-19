// Copyright 2025 SUSE LLC
// SPDX-License-Identifier: Apache-2.0

//nolint:gochecknoglobals
package cmd

// Exports for testing.
var (
	ConfigureCLI   = configureCLI
	InitLogger     = initLogger
	ReadConfigFile = readConfigFile
	NewRootCmd     = newRootCmd
	SetFlags       = setFlags
)
