// Package metrics exposes the agent's state in the Prometheus text exposition
// format. It is written against the standard library only: the agent publishes
// a handful of gauges and counters, which does not justify a client library.
package metrics

import (
	"bytes"
	"math"
	"strconv"
	"strings"
)

// Metric types used in the "# TYPE" lines.
const (
	typeGauge   = "gauge"
	typeCounter = "counter"
)

// label is one name/value pair of a metric series.
type label struct {
	Name  string
	Value string
}

// writer builds a document in the Prometheus text exposition format, version
// 0.0.4. Samples of one metric family must be written consecutively, right
// after the family header.
type writer struct {
	buf bytes.Buffer
}

// family writes the HELP and TYPE header of a metric family.
func (w *writer) family(name, help, metricType string) {
	if w.buf.Len() > 0 {
		w.buf.WriteByte('\n')
	}
	w.buf.WriteString("# HELP ")
	w.buf.WriteString(name)
	w.buf.WriteByte(' ')
	w.buf.WriteString(escapeHelp(help))
	w.buf.WriteByte('\n')
	w.buf.WriteString("# TYPE ")
	w.buf.WriteString(name)
	w.buf.WriteByte(' ')
	w.buf.WriteString(metricType)
	w.buf.WriteByte('\n')
}

// sample writes one series of the current metric family.
func (w *writer) sample(name string, value float64, labels ...label) {
	w.buf.WriteString(name)
	if len(labels) > 0 {
		w.buf.WriteByte('{')
		for i, l := range labels {
			if i > 0 {
				w.buf.WriteByte(',')
			}
			w.buf.WriteString(l.Name)
			w.buf.WriteString(`="`)
			w.buf.WriteString(escapeLabelValue(l.Value))
			w.buf.WriteByte('"')
		}
		w.buf.WriteByte('}')
	}
	w.buf.WriteByte(' ')
	w.buf.WriteString(formatValue(value))
	w.buf.WriteByte('\n')
}

func (w *writer) Bytes() []byte { return w.buf.Bytes() }

var helpEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`)

var labelValueEscaper = strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`)

func escapeHelp(s string) string { return helpEscaper.Replace(s) }

func escapeLabelValue(s string) string { return labelValueEscaper.Replace(s) }

// formatValue renders a sample value the way Prometheus expects it. Whole
// numbers within the range where float64 is exact are written in full so that
// timestamps stay readable when the endpoint is inspected by hand.
func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	case math.Abs(v) < 1e15:
		return strconv.FormatFloat(v, 'f', -1, 64)
	default:
		return strconv.FormatFloat(v, 'g', -1, 64)
	}
}
