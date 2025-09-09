package logger

import (
	"fmt"
	"io"
)

// EchoLogger is a custom logger for Echo that uses our Zap logger
type EchoLogger struct{}

// Write implements the io.Writer interface for Echo logger
func (l *EchoLogger) Write(p []byte) (n int, err error) {
	// Log Echo's output as info level messages
	if Log != nil {
		Info(string(p))
	} else {
		fmt.Print(string(p))
	}
	return len(p), nil
}

// NewEchoLogger returns a new Echo logger using our structured logger
func NewEchoLogger() io.Writer {
	return &EchoLogger{}
}
