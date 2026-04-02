// Package walker handles finding files (from a path argument) and processing
// each one through the sanitizer. It supports both single files and directories.
package walker

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mcarlsonTC/json-sanitizer/internal/detector"
	"github.com/mcarlsonTC/json-sanitizer/internal/sanitizer"
)

// Config holds the user's choices from the command line.
// Walker doesn't parse flags itself — it receives an already-built Config
// from the cmd package. This separation makes walker easier to test.
type Config struct {
	InputPath string // file or directory to process
	OutputDir string // where to write results; empty = overwrite in-place
	DryRun    bool   // if true, print to stdout instead of writing
	Verbose   bool   // if true, log each file as it's processed
}

// Run is the entry point called from cmd. It figures out whether InputPath
// is a single file or a directory, then processes accordingly.
func Run(cfg Config) error {
	info, err := os.Stat(cfg.InputPath)
	if err != nil {
		return fmt.Errorf("cannot access %q: %w", cfg.InputPath, err)
	}

	if info.IsDir() {
		return walkDir(cfg.InputPath, cfg)
	}
	return processFile(cfg.InputPath, cfg.InputPath, cfg)
}

// walkDir recursively visits every file under root.
// It skips hidden directories (like .git) and symlinks to directories.
func walkDir(root string, cfg Config) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// WalkDir gives us errors for individual entries — log and continue
			fmt.Fprintf(os.Stderr, "warning: skipping %q: %v\n", path, err)
			return nil
		}

		// Skip hidden directories (names starting with ".") like .git, .svn
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir // tells WalkDir not to descend into this dir
		}

		// Skip directories themselves — we only process files
		if d.IsDir() {
			return nil
		}

		// Skip symlinks — following them could cause infinite loops
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		return processFile(path, root, cfg)
	})
}

// processFile reads one file, finds all JSON spans, sanitizes them,
// and writes the result to the appropriate destination.
//
// root is the original walk root — used to compute relative paths when
// mirroring a directory structure to OutputDir.
func processFile(path, root string, cfg Config) error {
	src, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %q: %w", path, err)
	}

	// Skip files that look like binaries. We check the first 512 bytes:
	// if more than 30% of them are non-printable ASCII, it's probably not a text file.
	if isBinary(src) {
		if cfg.Verbose {
			fmt.Printf("skipping binary file: %s\n", path)
		}
		return nil
	}

	// Find all JSON spans in the file (works for both pure JSON and mixed text/logs)
	spans := detector.FindJSONSpans(src)
	if len(spans) == 0 {
		if cfg.Verbose {
			fmt.Printf("no JSON found: %s\n", path)
		}
		return nil
	}

	if cfg.Verbose {
		fmt.Printf("processing %s (%d JSON spans)\n", path, len(spans))
	}

	// Reconstruct the file with each JSON span replaced by its sanitized version.
	// We build the output by copying the bytes between spans unchanged, and
	// inserting sanitized JSON where the original spans were.
	//
	// Example: "LOG: {...} more text {...} end"
	//   Copy "LOG: "                (before span 0)
	//   Insert sanitized span 0
	//   Copy " more text "          (between span 0 and span 1)
	//   Insert sanitized span 1
	//   Copy " end"                 (after span 1)
	out := make([]byte, 0, len(src))
	cursor := 0 // tracks our position in the original src

	for _, span := range spans {
		// Copy everything before this span unchanged
		out = append(out, src[cursor:span.Start]...)

		// Sanitize the JSON span
		clean, err := sanitizer.Sanitize(span.Content)
		if err != nil {
			// If sanitization fails (shouldn't happen after isValidJSON), keep original
			fmt.Fprintf(os.Stderr, "warning: could not sanitize span in %q: %v\n", path, err)
			out = append(out, span.Content...)
		} else {
			out = append(out, clean...)
		}

		cursor = span.End
	}

	// Copy any remaining bytes after the last span
	out = append(out, src[cursor:]...)

	// Dry-run: just print to stdout
	if cfg.DryRun {
		fmt.Printf("--- %s ---\n", path)
		fmt.Println(string(out))
		return nil
	}

	// Determine where to write the output
	dest, err := resolveOutputPath(path, root, cfg.OutputDir)
	if err != nil {
		return fmt.Errorf("resolving output path for %q: %w", path, err)
	}

	return safeWrite(dest, out)
}

// resolveOutputPath computes where to write the sanitized file.
//
// If outputDir is empty, we overwrite the original file in-place.
// If outputDir is set, we mirror the directory structure:
//   input:  /logs/app/server.log  (root: /logs)
//   output: /sanitized/app/server.log  (outputDir: /sanitized)
func resolveOutputPath(inputPath, root, outputDir string) (string, error) {
	if outputDir == "" {
		return inputPath, nil // overwrite in-place
	}

	// Compute the path of inputPath relative to root, then join under outputDir
	rel, err := filepath.Rel(root, inputPath)
	if err != nil {
		return "", err
	}

	return filepath.Join(outputDir, rel), nil
}

// safeWrite writes data to path using a write-then-rename pattern.
// This prevents a half-written file if the program crashes mid-write:
//   1. Write to a temp file in the same directory
//   2. os.Rename atomically replaces the destination
// On POSIX systems (Mac/Linux), rename is atomic when src and dst are on
// the same filesystem — which they are since we use the same directory.
func safeWrite(dest string, data []byte) error {
	// Ensure the destination directory exists (important when using --output)
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("creating directory %q: %w", dir, err)
	}

	// Write to a temp file in the same directory as the destination.
	// os.CreateTemp(dir, pattern) creates a uniquely-named file.
	tmp, err := os.CreateTemp(dir, ".sanitizer-tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %q: %w", dir, err)
	}
	tmpPath := tmp.Name()

	// Make sure we clean up the temp file if anything goes wrong.
	// defer runs when the function returns, even if an error occurs.
	defer func() {
		tmp.Close()
		// Remove only if rename didn't succeed (file still exists at tmpPath)
		os.Remove(tmpPath) // safe to call even if already renamed away
	}()

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("writing to temp file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Atomic rename: if this succeeds, the destination is fully written.
	// os.Remove in the defer is a no-op after a successful rename.
	if err := os.Rename(tmpPath, dest); err != nil {
		return fmt.Errorf("renaming temp file to %q: %w", dest, err)
	}

	return nil
}

// isBinary makes a quick guess about whether src is a binary file.
// We sample the first 512 bytes: if more than 30% are non-printable
// (outside ASCII 9-13 and 32-126), we treat it as binary and skip it.
// This avoids garbling images, executables, etc.
func isBinary(src []byte) bool {
	sample := src
	if len(sample) > 512 {
		sample = sample[:512]
	}
	if len(sample) == 0 {
		return false
	}

	nonPrintable := 0
	for _, b := range sample {
		// Allow tab (9), newline (10), carriage return (13), and printable ASCII (32-126)
		if b < 9 || (b > 13 && b < 32) || b > 126 {
			nonPrintable++
		}
	}

	return float64(nonPrintable)/float64(len(sample)) > 0.30
}
