package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
	"github.com/Utkarsh932006/SiemDashboard/internal/storage"
)

// FormatAlertHTML formats an Alert as a table row HTML fragment.
func FormatAlertHTML(alert *correlation.Alert) string {
	badgeClass := "badge-info"
	switch alert.Severity {
	case "CRITICAL":
		badgeClass = "badge-critical"
	case "HIGH":
		badgeClass = "badge-high"
	case "MEDIUM":
		badgeClass = "badge-medium"
	case "LOW":
		badgeClass = "badge-low"
	}

	return fmt.Sprintf(
		`<tr class="new-row"><td class="cell-time">%s</td><td><span class="badge %s">%s</span></td><td><code class="cell-ip" onclick="pivotIP('%s')" title="Filter by this IP">%s</code></td><td class="cell-rule">%s</td><td class="cell-msg">%s</td></tr>`,
		alert.Timestamp.Format("15:04:05"),
		badgeClass,
		alert.Severity,
		alert.SourceIP,
		alert.SourceIP,
		alert.RuleID,
		alert.Message,
	)
}

// handleAlertsQuery handles GET /api/alerts (returns HTML table rows for HTMX)
func (s *Server) handleAlertsQuery(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "storage not configured", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query()
	severity := strings.ToUpper(strings.TrimSpace(q.Get("severity")))
	if severity == "ALL" {
		severity = ""
	}
	search := strings.TrimSpace(q.Get("q"))
	if search == "" {
		search = strings.TrimSpace(q.Get("search"))
	}
	ip := strings.TrimSpace(q.Get("ip"))
	limit := 100
	if l := q.Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	filter := storage.EventFilter{
		Severity: severity,
		SourceIP: ip,
		Search:   search,
		Limit:    limit,
	}

	alerts, err := s.store.QueryAlerts(filter)
	if err != nil {
		http.Error(w, fmt.Sprintf("query error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if len(alerts) == 0 {
		fmt.Fprintf(w, `<tr id="empty-state"><td colspan="5" style="text-align: center; color: var(--text-dim); padding: 2.5rem 1rem;">[NO ALERTS FOUND] Awaiting telemetry or adjust search filter.</td></tr>`)
		return
	}

	for _, alert := range alerts {
		w.Write([]byte(FormatAlertHTML(alert)))
	}
}

// handleStats handles GET /api/stats (returns JSON metrics for charts and counters)
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.store == nil {
		http.Error(w, "storage not configured", http.StatusInternalServerError)
		return
	}

	stats, err := s.store.GetStats()
	if err != nil {
		http.Error(w, fmt.Sprintf("stats query error: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
