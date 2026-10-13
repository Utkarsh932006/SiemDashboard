package storage

import (
	"fmt"
	"strings"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
)

const dbTimeFormat = "2006-01-02 15:04:05"

// InsertEvent persists a normalized event to the database.
func (s *Store) InsertEvent(e *parser.Event) error {
	ts := e.Timestamp.Format(dbTimeFormat)
	_, err := s.db.Exec(
		`INSERT INTO events (timestamp, source_ip, host, program, facility, severity, event_type, message, raw)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, e.SourceIP, e.Host, e.Program, e.Facility, e.Severity, e.EventType, e.Message, e.Raw,
	)
	return err
}

// InsertAlert persists a triggered alert to the database.
func (s *Store) InsertAlert(a *correlation.Alert) error {
	ts := a.Timestamp.Format(dbTimeFormat)
	_, err := s.db.Exec(
		`INSERT INTO alerts (timestamp, rule_id, rule_name, severity, source_ip, count, message)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ts, a.RuleID, a.RuleName, a.Severity, a.SourceIP, a.Count, a.Message,
	)
	return err
}

// EventFilter holds query parameters for filtering events.
type EventFilter struct {
	Severity  string
	SourceIP  string
	EventType string
	Search    string
	Limit     int
}

// QueryAlerts returns recent alerts matching optional filters.
func (s *Store) QueryAlerts(f EventFilter) ([]*correlation.Alert, error) {
	var conditions []string
	var args []any

	if f.Severity != "" {
		conditions = append(conditions, "severity = ?")
		args = append(args, f.Severity)
	}
	if f.SourceIP != "" {
		conditions = append(conditions, "source_ip LIKE ?")
		args = append(args, "%"+f.SourceIP+"%")
	}
	if f.Search != "" {
		conditions = append(conditions, "(message LIKE ? OR rule_id LIKE ? OR source_ip LIKE ?)")
		term := "%" + f.Search + "%"
		args = append(args, term, term, term)
	}

	query := "SELECT timestamp, rule_id, rule_name, severity, source_ip, count, message FROM alerts"
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("querying alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*correlation.Alert
	for rows.Next() {
		a := &correlation.Alert{}
		var tsStr string
		if err := rows.Scan(&tsStr, &a.RuleID, &a.RuleName, &a.Severity, &a.SourceIP, &a.Count, &a.Message); err != nil {
			return nil, fmt.Errorf("scanning alert row: %w", err)
		}

		if t, err := time.Parse(dbTimeFormat, tsStr); err == nil {
			a.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
			a.Timestamp = t
		} else {
			a.Timestamp = time.Now()
		}

		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

// Stats holds aggregate counts for the dashboard.
type Stats struct {
	Total    int           `json:"total"`
	Critical int           `json:"critical"`
	High     int           `json:"high"`
	Medium   int           `json:"medium"`
	Info     int           `json:"info"`
	TopIPs   []IPCount     `json:"top_ips"`
	Timeline []TimelineBin `json:"timeline"`
}

// IPCount pairs an IP with its event count.
type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// TimelineBin holds event count per hour bucket.
type TimelineBin struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// GetStats returns aggregate statistics from the alerts table.
func (s *Store) GetStats() (*Stats, error) {
	st := &Stats{
		TopIPs:   []IPCount{},
		Timeline: []TimelineBin{},
	}

	// Severity breakdown
	rows, err := s.db.Query("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
	if err != nil {
		return nil, fmt.Errorf("querying severity stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		st.Total += count
		switch sev {
		case "CRITICAL":
			st.Critical = count
		case "HIGH":
			st.High = count
		case "MEDIUM":
			st.Medium = count
		default:
			st.Info += count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Top source IPs
	ipRows, err := s.db.Query("SELECT source_ip, COUNT(*) as c FROM alerts GROUP BY source_ip ORDER BY c DESC LIMIT 10")
	if err != nil {
		return nil, fmt.Errorf("querying top IPs: %w", err)
	}
	defer ipRows.Close()

	for ipRows.Next() {
		var ic IPCount
		if err := ipRows.Scan(&ic.IP, &ic.Count); err != nil {
			return nil, err
		}
		st.TopIPs = append(st.TopIPs, ic)
	}
	if err := ipRows.Err(); err != nil {
		return nil, err
	}

	// Hourly timeline
	tlRows, err := s.db.Query(`
		SELECT COALESCE(strftime('%H:00', timestamp), substr(timestamp, 12, 2) || ':00') as hour, COUNT(*) as c
		FROM alerts
		GROUP BY hour
		ORDER BY hour ASC
	`)
	if err != nil {
		return nil, fmt.Errorf("querying timeline: %w", err)
	}
	defer tlRows.Close()

	for tlRows.Next() {
		var tb TimelineBin
		if err := tlRows.Scan(&tb.Hour, &tb.Count); err != nil {
			return nil, err
		}
		st.Timeline = append(st.Timeline, tb)
	}

	return st, tlRows.Err()
}
