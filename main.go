// json-sanitizer scans files or directories for JSON content and replaces
// sensitive values (names, IPs, emails, passwords, tokens) with safe placeholders.
//
// Run `json-sanitizer --help` for usage information.
package main

import (
	"fmt"
	"os"

	"github.com/mcarlsonTC/json-sanitizer/cmd"
)

func main() {
	// All the real work is in cmd.Execute(). Keeping main.go thin is idiomatic Go:
	// it makes the actual logic easy to test (you can call cmd.Execute() from tests)
	// and keeps the entry point focused on a single job — handle the exit code.
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
