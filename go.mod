module github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent

// Kept small on purpose, like the node-agent and the CLI in the ISOGrid
// monorepo. Each dependency is added with the feature that needs it: the
// WebSocket client for the stream (coder/websocket, pure Go, no transitive
// dependencies); planned next, a pure-Go SQLite driver (modernc.org/sqlite,
// no cgo). Vault/OpenBao is reached with the standard library.
go 1.23

require github.com/coder/websocket v1.8.13
