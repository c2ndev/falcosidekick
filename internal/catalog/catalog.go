// Package catalog provides an output type catalog for creating configured
// outputs and listing available types for the UI.
package catalog

import (
	"fmt"
	"sync"

	"github.com/falcosecurity/falcosidekick/internal/domain"
)

// Catalog holds all known output types. It is constructed once at startup
// from an explicit list (no init, no globals).
type Catalog struct {
	mu    sync.RWMutex
	types map[string]domain.OutputType
}

// New creates a Catalog from an explicit list of output types.
// Returns an error if the list is empty or contains duplicates.
func New(types []domain.OutputType) (*Catalog, error) {
	if len(types) == 0 {
		return nil, fmt.Errorf("catalog: at least one output type required")
	}

	c := &Catalog{types: make(map[string]domain.OutputType, len(types))}
	for _, t := range types {
		if t.Name == "" {
			return nil, fmt.Errorf("catalog: output type with empty name")
		}
		if t.New == nil {
			return nil, fmt.Errorf("catalog: output type %q has nil constructor", t.Name)
		}
		if _, exists := c.types[t.Name]; exists {
			return nil, fmt.Errorf("catalog: duplicate output type %q", t.Name)
		}
		c.types[t.Name] = t
	}
	return c, nil
}

// Get returns an output type by name.
func (c *Catalog) Get(name string) (domain.OutputType, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	t, ok := c.types[name]
	return t, ok
}

// All returns all known output types. Used by the UI pipeline configurator
// to populate the output palette.
func (c *Catalog) All() []domain.OutputType {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]domain.OutputType, 0, len(c.types))
	for _, t := range c.types {
		result = append(result, t)
	}
	return result
}

// Create instantiates a configured output by name.
// Returns an error if the name is unknown or the constructor fails.
func (c *Catalog) Create(name string, cfg map[string]any, deps domain.OutputDeps) (domain.Output, error) {
	t, ok := c.Get(name)
	if !ok {
		return nil, fmt.Errorf("catalog: unknown output type %q", name)
	}
	output, err := t.New(cfg, deps)
	if err != nil {
		return nil, fmt.Errorf("catalog: create %q: %w", name, err)
	}
	return output, nil
}

// Names returns the names of all known output types.
func (c *Catalog) Names() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.types))
	for name := range c.types {
		names = append(names, name)
	}
	return names
}
