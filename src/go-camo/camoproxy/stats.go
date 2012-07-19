package camoproxy

import (
	metrics "github.com/rcrowley/go-metrics"
	"bytes"
	"fmt"
)

type proxyStats struct {
	registry	  *metrics.StandardRegistry
	Enable        bool
}

func NewProxyStats() *proxyStats {
	r := metrics.NewRegistry()
	c := metrics.NewMeter()
	r.Register("clients", c)
	c.Mark(0)
	b := metrics.NewMeter()
	r.Register("bytes", b)
	b.Mark(0)
	ps := &proxyStats{registry: r}
	ps.Enable = true
	return ps
}

func (ps *proxyStats) AddServed() {
	if ps.Enable != true {
		return
	}
	m := ps.registry.Get("clients")
	if m == nil {
		return
	}
	m.(metrics.Meter).Mark(1)
}

func (ps *proxyStats) AddBytes(bc int64) {
	if ps.Enable != true {
		return
	}
	if bc <= 0 {
		return
	}
	m := ps.registry.Get("bytes")
	if m == nil {
		return
	}
	m.(metrics.Meter).Mark(bc)
}

func (ps *proxyStats) GetStats() *bytes.Buffer {
	buf := &bytes.Buffer{}
	for _, stat := range []string{"clients", "bytes"} {
		m := ps.registry.Get(stat).(metrics.Meter)
		if m == nil {
			continue
		}
		// mark values so they update
		m.Mark(0)
		fmt.Fprintf(buf, "meter %s\n", stat)
		fmt.Fprintf(buf, "  count:       %9d\n", m.Count())
		fmt.Fprintf(buf, "  1-min rate:  %12.2f\n", m.Rate1())
		fmt.Fprintf(buf, "  5-min rate:  %12.2f\n", m.Rate5())
		fmt.Fprintf(buf, "  15-min rate: %12.2f\n", m.Rate15())
		fmt.Fprintf(buf, "  mean rate:   %12.2f\n", m.RateMean())
	}
	return buf
}
