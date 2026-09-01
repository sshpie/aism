# Contributing

Thank you for your interest in contributing to tiptoe.

## How to contribute

1. Fork the repository and create a feature branch.
2. Make your changes. Keep the stdlib-only constraint — no external Go modules.
3. Run `go vet ./...` and `go build ./...` before opening a pull request.
4. Open a pull request against `main` with a clear description of what changed and why.

## Code style

- Standard Go formatting (`gofmt`).
- No external dependencies — all packages must be from the Go standard library.
- New features should include at least one usage example in the PR description.

## Reporting issues

Open a GitHub issue with:
- tiptoe version (`tiptoe version`)
- The command you ran
- The output you saw
- The output you expected

## Cisco DevNet

tiptoe is listed on the [Cisco DevNet Code Exchange](https://developer.cisco.com/codeexchange/). Contributions that extend the Catalyst Center, Cisco XDR, or Webex integrations are especially welcome. See the `cisco/` package for the integration surface.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.
