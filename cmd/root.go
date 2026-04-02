// Package cmd handles all command-line argument parsing.
// Keeping this separate from main.go means the CLI logic is easy to test
// and main.go stays tiny (just calls cmd.Execute()).
package cmd

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/mcarlsonTC/json-sanitizer/internal/walker"
)

// usage is the help text printed when --help is used or arguments are wrong.
const usage = `json-sanitizer — replace sensitive values in JSON with safe placeholders

Usage:
  json-sanitizer [flags] <file-or-directory>

What it sanitizes:
  • Name fields (username, actor, author, owner, …)  → random animal name
  • IP address fields and IP-looking values           → 1.1.1.1
  • Email fields and email-looking values             → animal@example.com
  • Passwords, tokens, secrets, API keys             → [REDACTED]
  • Phone numbers                                    → 555-0100

Flags:
  --output <dir>   Write sanitized files to <dir> instead of overwriting originals.
                   The original directory structure is mirrored under <dir>.
  --dry-run        Print sanitized output to stdout without writing any files.
  --verbose        Log the name of each file as it is processed.
  --help           Show this message.

Examples:
  json-sanitizer data.json                        # overwrite in-place
  json-sanitizer --output ./clean ./logs/         # sanitize directory, keep originals
  json-sanitizer --dry-run report.json            # preview without writing
  SANITIZER_SEED=42 json-sanitizer data.json      # deterministic animal names (for tests)
`

// Execute is called from main(). It parses flags, validates arguments,
// and hands off to walker.Run() which does the actual file processing.
//
// Returning an error (rather than calling os.Exit directly) makes this
// function testable — tests can call Execute() and check the error.
func Execute() error {
	// Define our flags. flag.CommandLine is the default flag set that
	// reads from os.Args. We set a custom usage function to print our
	// nicely formatted help text instead of Go's default output.
	fs := flag.NewFlagSet("json-sanitizer", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }

	// Declare the flags. The arguments are: flag name, default value, description.
	outputDir := fs.String("output", "", "directory to write sanitized files to")
	dryRun := fs.Bool("dry-run", false, "print sanitized output to stdout, don't write files")
	verbose := fs.Bool("verbose", false, "log each file as it is processed")

	// Parse os.Args[1:] (everything after the program name)
	if err := fs.Parse(os.Args[1:]); err != nil {
		// ContinueOnError means Parse returns the error instead of calling os.Exit.
		// This lets us handle --help gracefully.
		if errors.Is(err, flag.ErrHelp) {
			return nil // --help already printed usage; exit cleanly
		}
		return err
	}

	// After parsing flags, fs.Args() contains the remaining positional arguments.
	// We expect exactly one: the input file or directory.
	args := fs.Args()
	if len(args) != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one argument (file or directory), got %d", len(args))
	}

	cfg := walker.Config{
		InputPath: args[0],
		OutputDir: *outputDir,
		DryRun:    *dryRun,
		Verbose:   *verbose,
	}

	return walker.Run(cfg)
}
