package client

import (
	"fmt"
	"net/url"
)

// Sample mirrors metrics.Sample (snake_case json tags on the server side here —
// the metrics package DOES tag its fields).
type Sample struct {
	Scope     string  `json:"scope"`
	TargetID  string  `json:"target_id"`
	Name      string  `json:"name"`
	CPUPct    float64 `json:"cpu_pct"`
	MemUsed   int64   `json:"mem_used"`
	MemTotal  int64   `json:"mem_total"`
	DiskUsed  int64   `json:"disk_used"`
	DiskTotal int64   `json:"disk_total"`
	DiskRead  int64   `json:"disk_read"`
	DiskWrite int64   `json:"disk_write"`
	NetRx     int64   `json:"net_rx"`
	NetTx     int64   `json:"net_tx"`
	IOWait    float64 `json:"iowait"`
	CPUPres   float64 `json:"cpu_pres"`
	MemPres   float64 `json:"mem_pres"`
	IOPres    float64 `json:"io_pres"`
	TS        string  `json:"ts"`
}

// MetricHistory returns recent samples for a scope ("host" or "vm") over the
// trailing mins window. For scope "vm", target is the session id (or "" for all).
func (c *Client) MetricHistory(scope, target string, mins int) ([]Sample, error) {
	q := url.Values{}
	q.Set("scope", scope)
	if target != "" {
		q.Set("target", target)
	}
	q.Set("mins", fmt.Sprintf("%d", mins))
	var r struct {
		Samples []Sample `json:"samples"`
	}
	if err := c.getJSON("/api/metrics/history?"+q.Encode(), &r); err != nil {
		return nil, err
	}
	return r.Samples, nil
}
