package web

import (
	"strings"
	"testing"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
)

func TestFormatAlertHTMLEscapesUntrustedFields(t *testing.T) {
	alert := &correlation.Alert{
		Timestamp: time.Now(),
		Severity:  "HIGH",
		SourceIP:  `bad" autofocus onfocus="alert(1)`,
		RuleID:    `RULE<script>`,
		Message:   `<img src=x onerror=alert(1)>`,
	}

	rendered := FormatAlertHTML(alert)
	for _, unsafe := range []string{"<script>", "<img src=x", `data-pivot-ip="bad" autofocus`} {
		if strings.Contains(rendered, unsafe) {
			t.Fatalf("rendered alert contains unescaped content %q: %s", unsafe, rendered)
		}
	}
	if !strings.Contains(rendered, "&lt;img src=x onerror=alert(1)&gt;") {
		t.Fatalf("expected escaped message, got: %s", rendered)
	}
	if !strings.Contains(rendered, `data-pivot-ip="bad&#34; autofocus onfocus=&#34;alert(1)"`) {
		t.Fatalf("expected escaped pivot attribute, got: %s", rendered)
	}
}
