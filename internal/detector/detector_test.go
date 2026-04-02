package detector

import (
	"testing"
)

func TestFindJSONSpans_SimpleObject(t *testing.T) {
	src := []byte(`{"name":"Alice","ip":"1.2.3.4"}`)
	spans := FindJSONSpans(src)

	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Start != 0 || spans[0].End != len(src) {
		t.Errorf("expected span [0:%d], got [%d:%d]", len(src), spans[0].Start, spans[0].End)
	}
}

func TestFindJSONSpans_EmbeddedInText(t *testing.T) {
	// Simulates a log line with JSON in the middle
	src := []byte(`2024-01-01 INFO {"user":"bob"} request complete`)
	spans := FindJSONSpans(src)

	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	want := `{"user":"bob"}`
	if string(spans[0].Content) != want {
		t.Errorf("expected content %q, got %q", want, string(spans[0].Content))
	}
}

func TestFindJSONSpans_MultipleSeparateObjects(t *testing.T) {
	src := []byte(`{"a":1} some text {"b":2}`)
	spans := FindJSONSpans(src)

	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
}

func TestFindJSONSpans_Nested(t *testing.T) {
	// Nested objects should produce exactly one top-level span
	src := []byte(`{"outer":{"inner":"value"}}`)
	spans := FindJSONSpans(src)

	if len(spans) != 1 {
		t.Fatalf("expected 1 span for nested object, got %d", len(spans))
	}
}

func TestFindJSONSpans_ArrayOfObjects(t *testing.T) {
	src := []byte(`[{"name":"Alice"},{"name":"Bob"}]`)
	spans := FindJSONSpans(src)

	// The whole array is one top-level span
	if len(spans) != 1 {
		t.Fatalf("expected 1 span for array, got %d", len(spans))
	}
}

func TestFindJSONSpans_BracesInsideString(t *testing.T) {
	// Braces inside strings should NOT start new spans
	src := []byte(`{"template":"click {here}"}`)
	spans := FindJSONSpans(src)

	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d (brace inside string was mis-detected)", len(spans))
	}
}

func TestFindJSONSpans_EscapedQuoteInsideString(t *testing.T) {
	// \" inside a string should not close the string
	src := []byte(`{"msg":"say \"hello\""}`)
	spans := FindJSONSpans(src)

	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
}

func TestFindJSONSpans_BraceCounterTrusted(t *testing.T) {
	// The detector trusts the brace counter without JSON validation, so any
	// balanced {…} block is returned — including CSS-style ones. The sanitizer
	// downstream handles content that isn't real JSON gracefully.
	src := []byte(`body { color: red } {"valid":true}`)
	spans := FindJSONSpans(src)

	if len(spans) != 2 {
		t.Fatalf("expected 2 spans (brace counter trusted), got %d", len(spans))
	}
	if string(spans[1].Content) != `{"valid":true}` {
		t.Errorf("unexpected second span content: %q", string(spans[1].Content))
	}
}

func TestFindJSONSpans_EmptyInput(t *testing.T) {
	spans := FindJSONSpans([]byte(""))
	if len(spans) != 0 {
		t.Errorf("expected 0 spans for empty input, got %d", len(spans))
	}
}

func TestFindJSONSpans_NoJSON(t *testing.T) {
	spans := FindJSONSpans([]byte("just a plain text file with no json"))
	if len(spans) != 0 {
		t.Errorf("expected 0 spans, got %d", len(spans))
	}
}
