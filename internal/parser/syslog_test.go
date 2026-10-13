package parser

import (
	"testing"
)

func TestParseSyslog(t *testing.T) {
	raw := "<34>Oct 11 22:14:15 server01 sshd[1234]: Failed password for root from 192.168.1.105 port 22"
	remoteIP := "10.0.0.1"

	event := Parse(raw, remoteIP)
	if event == nil {
		t.Fatal("expected non-nil event")
	}

	if event.SourceIP != "192.168.1.105" {
		t.Errorf("expected SourceIP '192.168.1.105', got '%s'", event.SourceIP)
	}

	if event.Program != "sshd" {
		t.Errorf("expected Program 'sshd', got '%s'", event.Program)
	}

	if event.EventType != "AUTH_FAILURE" {
		t.Errorf("expected EventType 'AUTH_FAILURE', got '%s'", event.EventType)
	}

	if event.Severity != SeverityHigh {
		t.Errorf("expected Severity '%s', got '%s'", SeverityHigh, event.Severity)
	}

	if event.Facility != "auth" {
		t.Errorf("expected Facility 'auth', got '%s'", event.Facility)
	}
}

func TestParseGenericLog(t *testing.T) {
	raw := "simple unformatted log message"
	remoteIP := "192.168.1.20"

	event := Parse(raw, remoteIP)
	if event == nil {
		t.Fatal("expected non-nil event")
	}

	if event.SourceIP != remoteIP {
		t.Errorf("expected SourceIP '%s', got '%s'", remoteIP, event.SourceIP)
	}

	if event.EventType != "GENERIC" {
		t.Errorf("expected EventType 'GENERIC', got '%s'", event.EventType)
	}
}
