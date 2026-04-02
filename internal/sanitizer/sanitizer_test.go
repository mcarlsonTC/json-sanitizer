package sanitizer

import (
	"encoding/json"
	"os"
	"testing"
)

// helper decodes JSON bytes into a map for easy field access in tests
func decode(t *testing.T, b []byte) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("failed to decode output JSON: %v\nbytes: %s", err, b)
	}
	return m
}

func TestSanitize_NameFields(t *testing.T) {
	// Use a fixed seed so the test is deterministic
	os.Setenv("SANITIZER_SEED", "1")

	cases := []string{"name", "username", "firstName", "lastName", "actor", "Author", "owner", "displayName"}
	for _, key := range cases {
		raw, _ := json.Marshal(map[string]string{key: "Alice"})
		out, err := Sanitize(raw)
		if err != nil {
			t.Fatalf("Sanitize error for key %q: %v", key, err)
		}
		m := decode(t, out)
		val, _ := m[key].(string)
		if val == "Alice" {
			t.Errorf("key %q: expected name to be replaced, still got %q", key, val)
		}
		if val == "" {
			t.Errorf("key %q: replacement was empty", key)
		}
	}
}

func TestSanitize_IPFields(t *testing.T) {
	cases := []string{"ip", "ipAddress", "remoteAddr", "clientIp", "sourceIp"}
	for _, key := range cases {
		raw, _ := json.Marshal(map[string]string{key: "192.168.1.100"})
		out, err := Sanitize(raw)
		if err != nil {
			t.Fatalf("Sanitize error for key %q: %v", key, err)
		}
		m := decode(t, out)
		if m[key] != "1.1.1.1" {
			t.Errorf("key %q: expected 1.1.1.1, got %v", key, m[key])
		}
	}
}

func TestSanitize_IPValueDetection(t *testing.T) {
	// Even if the key name doesn't match, IP-looking values should be replaced
	raw := []byte(`{"addr":"10.0.0.1"}`)
	out, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if m["addr"] != "1.1.1.1" {
		t.Errorf("expected IP value to be replaced regardless of key name, got %v", m["addr"])
	}
}

func TestSanitize_EmailFields(t *testing.T) {
	cases := []string{"email", "emailAddress", "mail"}
	for _, key := range cases {
		raw, _ := json.Marshal(map[string]string{key: "alice@example.com"})
		out, err := Sanitize(raw)
		if err != nil {
			t.Fatalf("Sanitize error for key %q: %v", key, err)
		}
		m := decode(t, out)
		if m[key] != "animal@example.com" {
			t.Errorf("key %q: expected animal@example.com, got %v", key, m[key])
		}
	}
}

func TestSanitize_EmailValueDetection(t *testing.T) {
	// Email-looking values should be replaced even with an unrecognized key
	raw := []byte(`{"contact":"bob@corp.io"}`)
	out, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)
	if m["contact"] != "animal@example.com" {
		t.Errorf("expected email value to be replaced, got %v", m["contact"])
	}
}

func TestSanitize_SecretFields(t *testing.T) {
	cases := []string{"password", "token", "apiKey", "secret", "authorization", "accessToken"}
	for _, key := range cases {
		raw, _ := json.Marshal(map[string]string{key: "supersecret123"})
		out, err := Sanitize(raw)
		if err != nil {
			t.Fatalf("Sanitize error for key %q: %v", key, err)
		}
		m := decode(t, out)
		if m[key] != "[REDACTED]" {
			t.Errorf("key %q: expected [REDACTED], got %v", key, m[key])
		}
	}
}

func TestSanitize_PhoneFields(t *testing.T) {
	cases := []string{"phone", "phoneNumber", "mobile", "telephone"}
	for _, key := range cases {
		raw, _ := json.Marshal(map[string]string{key: "555-867-5309"})
		out, err := Sanitize(raw)
		if err != nil {
			t.Fatalf("Sanitize error for key %q: %v", key, err)
		}
		m := decode(t, out)
		if m[key] != "555-0100" {
			t.Errorf("key %q: expected 555-0100, got %v", key, m[key])
		}
	}
}

func TestSanitize_NestedObject(t *testing.T) {
	raw := []byte(`{"user":{"name":"Alice","ip":"1.2.3.4","password":"secret"}}`)
	out, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]map[string]interface{}
	json.Unmarshal(out, &result)

	user := result["user"]
	if user["name"] == "Alice" {
		t.Error("nested name was not sanitized")
	}
	if user["ip"] != "1.1.1.1" {
		t.Errorf("nested ip: expected 1.1.1.1, got %v", user["ip"])
	}
	if user["password"] != "[REDACTED]" {
		t.Errorf("nested password: expected [REDACTED], got %v", user["password"])
	}
}

func TestSanitize_ArrayOfObjects(t *testing.T) {
	raw := []byte(`[{"name":"Alice","ip":"1.2.3.4"},{"name":"Bob","ip":"5.6.7.8"}]`)
	out, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	var result []map[string]interface{}
	json.Unmarshal(out, &result)

	for i, obj := range result {
		if obj["ip"] != "1.1.1.1" {
			t.Errorf("array[%d].ip: expected 1.1.1.1, got %v", i, obj["ip"])
		}
	}
}

func TestSanitize_NonSensitiveFieldsUnchanged(t *testing.T) {
	raw := []byte(`{"count":42,"active":true,"label":"hello","nothing":null}`)
	out, err := Sanitize(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := decode(t, out)

	if m["count"] != float64(42) {
		t.Errorf("count should be unchanged, got %v", m["count"])
	}
	if m["active"] != true {
		t.Errorf("active should be unchanged, got %v", m["active"])
	}
	if m["label"] != "hello" {
		t.Errorf("label should be unchanged, got %v", m["label"])
	}
	if m["nothing"] != nil {
		t.Errorf("null should be unchanged, got %v", m["nothing"])
	}
}

func TestSanitize_InvalidJSON(t *testing.T) {
	_, err := Sanitize([]byte(`not json`))
	if err == nil {
		t.Error("expected error for invalid JSON input")
	}
}
