package metrics

import (
	"math"
	"strings"
	"testing"
)

func TestWriterRendersFamiliesAndSamples(t *testing.T) {
	var w writer
	w.family("a_metric", "Some help.", typeGauge)
	w.sample("a_metric", 1, label{"entry", "github-ci"}, label{"state", "authorized"})
	w.sample("a_metric", 0, label{"entry", "github-ci"}, label{"state", "needs_auth"})
	w.family("a_counter", "Another help.", typeCounter)
	w.sample("a_counter", 42)

	want := strings.Join([]string{
		"# HELP a_metric Some help.",
		"# TYPE a_metric gauge",
		`a_metric{entry="github-ci",state="authorized"} 1`,
		`a_metric{entry="github-ci",state="needs_auth"} 0`,
		"",
		"# HELP a_counter Another help.",
		"# TYPE a_counter counter",
		"a_counter 42",
		"",
	}, "\n")

	if got := string(w.Bytes()); got != want {
		t.Errorf("output =\n%q\nwant\n%q", got, want)
	}
}

func TestEscaping(t *testing.T) {
	var w writer
	w.family("m", "help with \\ backslash\nand newline", typeGauge)
	w.sample("m", 1, label{"l", `va"lue` + "\n" + `back\slash`})

	got := string(w.Bytes())
	if !strings.Contains(got, `# HELP m help with \\ backslash\nand newline`) {
		t.Errorf("help line not escaped: %q", got)
	}
	if !strings.Contains(got, `m{l="va\"lue\nback\\slash"} 1`) {
		t.Errorf("label value not escaped: %q", got)
	}
	// A scraper must still see exactly two header lines and one sample line.
	if lines := strings.Count(strings.TrimSuffix(got, "\n"), "\n"); lines != 2 {
		t.Errorf("output spans %d newlines, want the escapes to stay on one line each", lines)
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		value float64
		want  string
	}{
		{0, "0"},
		{1, "1"},
		{1765440576, "1765440576"},
		{1765440576.5, "1765440576.5"},
		{-1, "-1"},
		{0.25, "0.25"},
		{1e20, "1e+20"},
		{math.Inf(1), "+Inf"},
		{math.Inf(-1), "-Inf"},
		{math.NaN(), "NaN"},
	}
	for _, tt := range tests {
		if got := formatValue(tt.value); got != tt.want {
			t.Errorf("formatValue(%v) = %q, want %q", tt.value, got, tt.want)
		}
	}
}
