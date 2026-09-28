//go:build !unicorn

package main

import (
	"fmt"
	"os"
)

// main for builds without the unicorn engine: the sizing probe needs a real
// CPU engine to measure, so explain how to get one instead of failing to
// compile. (Mirrors cmd/golem's no-backend behavior.)
func main() {
	fmt.Fprintln(os.Stderr, "tcgsizing requires the unicorn engine: rebuild with")
	fmt.Fprintln(os.Stderr, "  CGO_ENABLED=0 go build -tags unicorn ./cmd/tcgsizing")
	fmt.Fprintln(os.Stderr, "and make libunicorn findable ($GOLEM_UNICORN or loader path).")
	os.Exit(1)
}
