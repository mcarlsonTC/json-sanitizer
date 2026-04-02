// Package sanitizer replaces sensitive values in parsed JSON data.
// It handles name fields, IP addresses, emails, passwords, tokens, and phones.
package sanitizer

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/mcarlsonTC/json-sanitizer/internal/animals"
)

// These regexes are compiled once at startup (not inside a loop) for performance.
// regexp.MustCompile panics if the pattern is invalid — fine here since patterns are hardcoded.
var (
	// ipRegex matches IPv4 addresses like "192.168.1.100"
	// \d{1,3} matches 1-3 digits, and we require exactly 4 groups separated by dots.
	ipRegex = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)

	// emailRegex matches values that look like an email: something@something.something
	// This intentionally simple pattern avoids false negatives on unusual domains.
	emailRegex = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

	// trailingCommaRe matches a comma followed by optional whitespace and a closing
	// brace or bracket. Standard JSON forbids trailing commas, but they're common in
	// YAML-embedded test logs and JSON5-style files. We strip them before parsing.
	// \s matches spaces, tabs, and newlines — so this handles multi-line JSON too.
	trailingCommaRe = regexp.MustCompile(`,(\s*[}\]])`)
)

// Key lookup tables — using maps for O(1) lookup.
// All keys are stored lowercase; we lowercase the actual key before lookup.
// This means "Username", "userName", and "username" all match.

var nameKeys = map[string]bool{
	"name": true, "firstname": true, "first_name": true,
	"lastname": true, "last_name": true, "fullname": true, "full_name": true,
	"displayname": true, "display_name": true,
	"username": true, "user_name": true,
	"actor": true, "author": true, "owner": true,
	"givenname": true, "given_name": true,
	"surname": true, "realname": true, "real_name": true,
	"nickname": true, "nick_name": true, "handle": true,
	"user": true,
}

var ipKeys = map[string]bool{
	"ip": true, "ipaddress": true, "ip_address": true,
	"remoteaddr": true, "remote_addr": true,
	"clientip": true, "client_ip": true,
	"sourceip": true, "source_ip": true,
	"remoteip": true, "remote_ip": true,
	"peerip": true, "peer_ip": true,
	"hostip": true, "host_ip": true,
	"ipv4": true, "ipv6": true,
	"srcip": true, "dstip": true, "dst_ip": true, "src_ip": true,
}

var emailKeys = map[string]bool{
	"email": true, "emailaddress": true, "email_address": true,
	"e_mail": true, "mail": true, "useremail": true, "user_email": true,
	"contactemail": true, "contact_email": true,
}

var secretKeys = map[string]bool{
	"password": true, "passwd": true, "pass": true,
	"secret": true, "token": true,
	"apikey": true, "api_key": true,
	"auth": true, "authorization": true,
	"accesstoken": true, "access_token": true,
	"refreshtoken": true, "refresh_token": true,
	"privatekey": true, "private_key": true,
	"credential": true, "credentials": true,
	"sessiontoken": true, "session_token": true,
	"bearertoken": true, "bearer_token": true,
	"secretkey": true, "secret_key": true,
	"clientsecret": true, "client_secret": true,
	"ssn": true, "sin": true, // social security / insurance numbers
}

var phoneKeys = map[string]bool{
	"phone": true, "phonenumber": true, "phone_number": true,
	"mobile": true, "cell": true, "fax": true,
	"telephone": true, "tel": true,
	"contactnumber": true, "contact_number": true,
}

// Sanitize takes raw JSON bytes, replaces sensitive values, and returns
// new JSON bytes. The JSON structure is preserved — only values change.
//
// Important: json.Marshal produces compact JSON (no extra spaces or indentation).
// Key order may also change because Go maps are unordered. This is an accepted
// trade-off for a sanitizer tool — the data is correct, just reformatted.
func Sanitize(raw []byte) ([]byte, error) {
	// Step 1: Strip trailing commas so we can handle "relaxed" JSON.
	// Standard json.Unmarshal rejects trailing commas (e.g. {"a": 1,}),
	// but they appear frequently in YAML test fixtures and JSON5-style files.
	// The regex replaces ,<whitespace>} and ,<whitespace>] with just } or ].
	raw = trailingCommaRe.ReplaceAll(raw, []byte("$1"))

	// Step 2: Parse the JSON into a generic Go value.
	// encoding/json decodes objects as map[string]interface{},
	// arrays as []interface{}, strings as string, numbers as float64, etc.
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}

	// Step 2: Recursively walk and sanitize the value.
	sanitized := sanitizeValue("", v)

	// Step 3: Re-encode back to JSON bytes.
	return json.Marshal(sanitized)
}

// sanitizeValue is the recursive core. It handles every JSON type:
//   - object (map) → sanitize each key/value pair
//   - array        → sanitize each element
//   - string       → check if value itself looks like an IP or email
//   - everything else (number, bool, null) → return unchanged
//
// The key parameter is the parent key name, used to decide how to sanitize
// a string value. For array elements, key is passed through from the parent.
func sanitizeValue(key string, v interface{}) interface{} {
	switch val := v.(type) {

	case map[string]interface{}:
		// This is a JSON object like {"name": "Alice", "ip": "1.2.3.4"}
		return sanitizeObject(val)

	case []interface{}:
		// This is a JSON array. Sanitize each element individually.
		// Pattern: create a new slice, fill it — this is the Go idiom for
		// transforming a slice without modifying the original.
		result := make([]interface{}, len(val))
		for i, elem := range val {
			result[i] = sanitizeValue(key, elem) // pass parent key for context
		}
		return result

	case string:
		// Apply key-based rules first (most specific), then value-pattern rules.
		return sanitizeString(key, val)

	default:
		// numbers (float64), booleans, nil — leave unchanged
		return v
	}
}

// sanitizeObject walks every key-value pair in a JSON object.
// It builds a new map with the same keys but sanitized values.
func sanitizeObject(obj map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{}, len(obj))
	for k, v := range obj {
		result[k] = sanitizeValue(k, v)
	}
	return result
}

// sanitizeString decides what replacement to use for a string value.
// It first checks the key name, then falls back to inspecting the value itself.
func sanitizeString(key, value string) string {
	// Normalize key to lowercase so "Username", "userName", "USER_NAME" all match.
	lk := strings.ToLower(key)

	// Key-based rules — checked in order of specificity
	switch {
	case nameKeys[lk]:
		return animals.Random() // e.g. "Alice" → "Platypus"

	case ipKeys[lk]:
		return "1.1.1.1"

	case emailKeys[lk]:
		return "animal@example.com"

	case secretKeys[lk]:
		return "[REDACTED]"

	case phoneKeys[lk]:
		return "555-0100"
	}

	// Value-pattern rules — catch sensitive values even when the key name
	// isn't recognized (e.g. a field named "addr" containing an IP address).
	switch {
	case ipRegex.MatchString(value):
		return "1.1.1.1"

	case emailRegex.MatchString(value):
		return "animal@example.com"
	}

	// Nothing matched — return the original value unchanged
	return value
}
