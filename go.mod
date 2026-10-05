module github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent

// Kept small on purpose, like the node-agent and the CLI in the ISOGrid
// monorepo. Each dependency is added with the feature that needs it: the
// WebSocket client for the stream (coder/websocket, pure Go, no transitive
// dependencies), a pure-Go SQLite driver for the local store
// (modernc.org/sqlite, no cgo, so the binary stays static), and Argon2id for
// the console's password hashes (golang.org/x/crypto). Vault/OpenBao and the
// Docker Engine are reached with the standard library.
go 1.23

require (
	github.com/coder/websocket v1.8.13
	golang.org/x/crypto v0.31.0
	modernc.org/sqlite v1.34.5
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.28.0 // indirect
	modernc.org/libc v1.55.3 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.8.0 // indirect
)
