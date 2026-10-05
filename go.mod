module github.com/ISOGrid-by-SkyVault/isogrid-nomad-agent

// Standard library only for now, like the node-agent and the CLI in the
// ISOGrid monorepo. Planned additions, each added with the feature that needs
// it: a pure-Go SQLite driver (modernc.org/sqlite, no cgo), an AMQP 1.0/0.9.1
// client for the broker, and a Vault/OpenBao HTTP client (stdlib is enough).
go 1.23
