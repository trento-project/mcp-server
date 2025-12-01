# Changelog

## 0.1.0 - 2025-11-28

### What's Changed

* Revert release (#78) @nelsonkopliku
* bump version 1.0.0 (#77) @nelsonkopliku
* fix get_version_from_git.sh (#76) @nelsonkopliku
* Revert release (#75) @nelsonkopliku
* Release version 1.0.0 (#74) @nelsonkopliku
* [TRNT-3946] Improve user documentation (#62) @antgamdia
* [TRNT-3946] Add missing INSECURE_SKIP_TLS_VERIFY to default config (#72) @antgamdia
* Aligns golang version  (#53) @gagandeepb
* [TRNT-3854] Add OBS workflows (#41) @antgamdia
* [TRNT-3845] Add asciidoc-linter and fix issues (#26) @antgamdia
* [TRNT-3850] Remove unused OAuth logic (#21) @antgamdia
* Fix for autobuild (#17) @EMaksy
* [TRNT-3844] Add initial MCP server code (#7) @antgamdia

#### Features

* [TRNT-3946] Replace header name  "Authorization" (#69) @antgamdia
* [TRTN-3845] Improve handling of paths (#67) @antgamdia
* [TRNT-3845] Use autodiscovery of Trento API endpoints (#59) @antgamdia
* [TRNT-3854] Rename binaries (#66) @antgamdia
* [TRNT-3854] Rename rpm binary to `mcp-server-trento` (#61) @antgamdia
* [TRNT-3845] Delete hardcoded API docs (#24) @antgamdia
* [TRNT-3854] Add opional health check server (#57) @antgamdia
* [TRNT-3854] Delete local helm chart (#51) @antgamdia
* [TRNT-3854] Improve config file and include it in packaging (#52) @antgamdia
* [TRNT-3845] Support multiple API docs (#54) @antgamdia
* [TRNT-3854] Rename pkg in OBS (#45) @antgamdia
* [TRNT-3854] Allow passing configuration in multiple ways (#43) @antgamdia
* [TRNT-3854] Download OAS file from HTTP (#46) @antgamdia
* [TRNT-3853] Redirect library log traces to our logger (#29) @antgamdia
* [TRNT-3854] Add initial release workflows (#42) @antgamdia
* [TRNT-3854] Prepare CI for more steps (#38) @antgamdia
* [TRNT-3853] Use asdf versions in the scripts and CI (#25) @antgamdia
* [TRNT-3854] Add packaging folder (#40) @antgamdia
* [TRNT-3854] Update dockerfile and makefile (#37) @antgamdia
* [TRNT-3850] Use modelcontextprotocol/go-sdk (#16) @antgamdia
* [TRNT-3853] Use API-key based authentication (#14) @antgamdia
* [TRNT-3850] Add initial unit tests (#10) @antgamdia
* [TRNT-3850] Improve existing mcp server logic (#9) @antgamdia
* [TRNT-3850] Use the evcc-io/openapi-mcp fork instead (#8) @antgamdia
* [TRNT-3844] Add initial MCP server code (#1) @antgamdia

#### Bug Fixes

* [TRNT-4079] Use custom http client for tool execution (#73) @antgamdia
* [TRNT-3853] Use per-mcp-session API tokens (#58) @antgamdia
* [TRNT-3853] Increase timeouts (#30) @antgamdia
* [TRNT-3853] Fix container push (#34) @antgamdia

#### Dependencies

<details>
<summary>21 changes</summary>
* Bump golangci/golangci-lint-action from 8 to 9 (#70) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/checkout from 5 to 6 (#71) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/modelcontextprotocol/go-sdk from 1.0.0 to 1.1.0 (#68) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/download-artifact from 5 to 6 (#65) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/upload-artifact from 4 to 5 (#64) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump apache/skywalking-eyes from 0.7.0 to 0.8.0 (#63) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump stefanzweifel/git-auto-commit-action from 6 to 7 (#60) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/modelcontextprotocol/go-sdk from 0.7.0 to 1.0.0 (#56) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/modelcontextprotocol/go-sdk from 0.6.0 to 0.7.0 (#50) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/evcc-io/openapi-mcp from 0.5.1 to 0.6.0 (#48) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/checkout from 4 to 5 (#44) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/modelcontextprotocol/go-sdk from 0.4.0 to 0.5.0 (#36) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/evcc-io/openapi-mcp from 0.5.0 to 0.5.1 (#33) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/modelcontextprotocol/go-sdk from 0.3.1 to 0.4.0 (#32) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/setup-go from 5 to 6 (#31) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/spf13/cobra from 1.9.1 to 1.10.1 (#20) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/getkin/kin-openapi from 0.132.0 to 0.133.0 (#19) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/mark3labs/mcp-go from 0.37.0 to 0.38.0 (#18) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/checkout from 4 to 5 (#15) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump actions/download-artifact from 4 to 5 (#13) @[dependabot[bot]](https://github.com/apps/dependabot)
* Bump github.com/mark3labs/mcp-go from 0.36.0 to 0.37.0 (#11) @[dependabot[bot]](https://github.com/apps/dependabot)

</details>
**Full Changelog**: https://github.com/trento-project/mcp-server/compare/...0.1.0
