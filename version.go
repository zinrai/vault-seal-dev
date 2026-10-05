package main

import "fmt"

// Placeholders, not empty: a locally built binary reports these, and
// goreleaser overwrites them via -ldflags -X.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func printVersion() {
	fmt.Printf("vault-seal-dev version %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
}
