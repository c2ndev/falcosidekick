package domain

import "errors"

var (
	ErrCircuitOpen  = errors.New("circuit breaker is open")
	ErrQueueFull    = errors.New("output queue is full")
	ErrNotReady     = errors.New("service not ready")
	ErrShuttingDown = errors.New("service is shutting down")
	ErrInvalidEvent = errors.New("invalid event")
)
