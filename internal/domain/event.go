// Package domain defines the core types, interfaces, and errors for falcosidekick.
// It has zero dependencies on other internal packages.
package domain

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Priority represents a Falco event severity level.
type Priority string

const (
	PriorityDebug         Priority = "debug"
	PriorityInformational Priority = "informational"
	PriorityNotice        Priority = "notice"
	PriorityWarning       Priority = "warning"
	PriorityError         Priority = "error"
	PriorityCritical      Priority = "critical"
	PriorityAlert         Priority = "alert"
	PriorityEmergency     Priority = "emergency"
)

// priorityOrder defines the severity ordering. Immutable after init.
var priorityOrder = map[Priority]int{
	"":                   -1,
	PriorityDebug:         0,
	PriorityInformational: 1,
	PriorityNotice:        2,
	PriorityWarning:       3,
	PriorityError:         4,
	PriorityCritical:      5,
	PriorityAlert:         6,
	PriorityEmergency:     7,
}

// allPriorities lists valid priorities for validation. Immutable after init.
var allPriorities = map[Priority]bool{
	PriorityDebug: true, PriorityInformational: true, PriorityNotice: true,
	PriorityWarning: true, PriorityError: true, PriorityCritical: true,
	PriorityAlert: true, PriorityEmergency: true,
}

// GTE returns true if p is greater than or equal to other in severity.
func (p Priority) GTE(other Priority) bool {
	return priorityOrder[p] >= priorityOrder[other]
}

// String returns the priority as a title-cased string for display.
func (p Priority) String() string {
	if p == "" {
		return ""
	}
	s := string(p)
	return strings.ToUpper(s[:1]) + s[1:]
}

// ParsePriority converts a string to a Priority. Case-insensitive.
func ParsePriority(s string) (Priority, error) {
	p := Priority(strings.ToLower(strings.TrimSpace(s)))
	if p == "" {
		return "", nil
	}
	if !allPriorities[p] {
		return "", fmt.Errorf("unknown priority: %q", s)
	}
	return p, nil
}

// Event represents a Falco security event.
type Event struct {
	UUID         string                 `json:"uuid,omitempty"`
	Output       string                 `json:"output"`
	Priority     Priority               `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
	Source       string                 `json:"source"`
	Tags         []string               `json:"tags,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
}

// Validate checks that the event has the minimum required fields
// and applies defaults for optional fields.
func (e *Event) Validate() error {
	if e.Rule == "" {
		return fmt.Errorf("%w: rule is required", ErrInvalidEvent)
	}
	if e.Time.IsZero() {
		return fmt.Errorf("%w: time is required", ErrInvalidEvent)
	}
	if e.OutputFields == nil {
		e.OutputFields = make(map[string]interface{})
	}
	if e.Source == "" {
		e.Source = "syscall"
	}
	return nil
}

// MarshalJSON implements custom JSON encoding. Priority is encoded as a string.
func (e Event) MarshalJSON() ([]byte, error) {
	type Alias Event
	return json.Marshal(&struct {
		Alias
	}{Alias: Alias(e)})
}
