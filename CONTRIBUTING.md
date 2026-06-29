# Contributing to RouteX

Thanks for your interest in contributing! RouteX is part of the PingLess Studios open-source ecosystem.

## Getting Started

1. **Fork** the repository
2. **Clone** your fork: `git clone https://github.com/YOUR_USERNAME/RouteX-Reverse-Proxy.git`
3. **Build**: `make build`
4. **Run tests**: `go test -short ./...` (69 tests should pass)
5. Create a feature branch: `git checkout -b feat/my-feature`

## Development Guidelines

### Code Style
- Follow standard Go conventions (`gofmt`, `go vet`)
- Use `go.uber.org/zap` for structured logging
- Use `sync.RWMutex` for shared state access
- Use `context.Context` propagation throughout
- Each proxy instance runs in isolated goroutine group — panics in one must not crash others
- Zero global mutable state — all state scoped to struct instances

### Testing
- Unit tests for all new logic
- Integration tests for proxy engine changes (real TCP/UDP connections)
- Run `go test -race -cover ./...` before submitting

### Commit Messages
- Use conventional commits: `feat:`, `fix:`, `docs:`, `refactor:`, `test:`
- Keep messages concise and descriptive

## Pull Request Process

1. Ensure all tests pass: `go test -short ./...`
2. Ensure the build succeeds: `go build ./...`
3. Update documentation if you change config schema or API endpoints
4. Add your changes to the PR description with context on *why*
5. Link any related issues

## Adding New Features

### New Config Fields
- Add types to `internal/config/defs.go`
- Add validation in `internal/config/global.go` or `internal/config/proxy.go`
- Add defaults in `applyGlobalDefaults()`

### New API Endpoints
- Add routes in `internal/api/routes.go`
- Add handler functions with proper error responses
- Use `writeJSON()` helper for consistent JSON output

### New L7 Protocol Detector
- Add validation function in `internal/l7/patterns.go`
- Add mode case in `ProtocolDetector.Check()`
- Add tests with valid and invalid payload samples

## Questions?

Open a [Discussion](https://github.com/AnAverageBeing/RouteX-Reverse-Proxy/discussions) or join our [Discord](https://discord.gg/qgBMREWWgp).
