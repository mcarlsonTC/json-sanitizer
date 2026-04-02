// Package detector finds JSON objects and arrays embedded anywhere in a
// byte slice — including inside log lines, config files, or arbitrary text.
// It does NOT require the whole file to be valid JSON.
package detector

import "encoding/json"

// Span marks the location of one JSON object or array within a larger byte slice.
// Start is the index of the opening '{' or '['.
// End is one past the closing '}' or ']' (so src[Start:End] is the raw JSON).
type Span struct {
	Start   int
	End     int
	Content []byte // convenience copy of src[Start:End]
}

// FindJSONSpans scans src and returns the location of every valid JSON
// object ({...}) or array ([...]) it finds, in order of appearance.
//
// How it works — brace-counting with string awareness:
//
//  1. Walk every byte. Track whether we're inside a JSON string (inString).
//  2. Inside a string, ignore braces; watch only for closing '"' and '\\'.
//  3. Outside a string, '{' or '[' increments depth. When depth goes 0→1,
//     record the start. '}' or ']' decrements depth. When depth goes 1→0,
//     record the end and run a quick validity check.
//  4. The validity check (json.Unmarshal) rejects false positives like CSS
//     rules `{color: red}` or shell arrays — those aren't valid JSON.
//
// This is O(n) in file size and handles nested structures correctly.
func FindJSONSpans(src []byte) []Span {
	var spans []Span

	depth := 0      // how many levels deep we are ({[ increments, }] decrements)
	inString := false // are we currently inside a JSON string?
	escaped := false  // was the last character a backslash inside a string?
	spanStart := 0    // byte index where the current top-level span started

	for i, b := range src {
		// --- String escape handling ---
		// If the previous byte was '\', this byte is escaped — skip it.
		// (Without this, a '\"' inside a string would incorrectly close it.)
		if escaped {
			escaped = false
			continue
		}

		// --- Inside a string ---
		if inString {
			switch b {
			case '\\':
				escaped = true // next byte is escaped
			case '"':
				inString = false // end of string
			}
			continue // braces inside strings don't count
		}

		// --- Outside a string ---
		switch b {
		case '"':
			inString = true

		case '{', '[':
			if depth == 0 {
				spanStart = i // remember where this top-level span begins
			}
			depth++

		case '}', ']':
			if depth == 0 {
				// Unmatched closing brace — skip it (malformed input)
				continue
			}
			depth--
			if depth == 0 {
				// We just closed a top-level span. Validate it before keeping.
				candidate := src[spanStart : i+1]
				if isValidJSON(candidate) {
					spans = append(spans, Span{
						Start:   spanStart,
						End:     i + 1,
						Content: candidate,
					})
				}
			}
		}
	}

	return spans
}

// isValidJSON returns true if candidate can be parsed by encoding/json as
// an object or array. This filters out CSS, shell expressions, etc.
// We use json.Unmarshal here (not a custom check) to stay correct for edge
// cases like Unicode, escaped characters, and numbers.
func isValidJSON(candidate []byte) bool {
	var v interface{}
	err := json.Unmarshal(candidate, &v)
	if err != nil {
		return false
	}
	// Only accept objects and arrays, not bare strings/numbers
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return true
	default:
		return false
	}
}
