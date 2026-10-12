// SPDX-FileCopyrightText: SUSE LLC
// SPDX-License-Identifier: GPL-3.0-or-later

//nolint:gochecknoglobals
package cmd

// Exports for testing.
var (
	ConfigKeyConfig      = configKeyConfig
	ConfigKeyTrentoURL   = configKeyTrentoURL
	ConfigureCLI         = configureCLI
	CreateAndBindFlags   = createAndBindFlags
	FlagConfigs          = flagConfigs
	GetConfigDescription = getConfigDescription
	InitLogger           = initLogger
	NewRootCmd           = newRootCmd
	ReadConfigFile       = readConfigFile
	SetFlags             = setFlags
)
