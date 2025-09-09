package logger

import (
	"os"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is the global logger
var (
	Log  *zap.Logger
	once sync.Once
)

// Field is an alias for zap.Field for convenience
type Field = zapcore.Field

// String constructs a string field with the given key and value
func String(key, val string) Field {
	return zap.String(key, val)
}

// Int constructs an int field with the given key and value
func Int(key string, val int) Field {
	return zap.Int(key, val)
}

// Err constructs an error field with the given key and error
func Err(err error) Field {
	return zap.Error(err)
}

// Any takes a key and any value and serializes it using reflection
func Any(key string, val interface{}) Field {
	return zap.Any(key, val)
}

// Init initializes the logger with appropriate configuration
func Init(environment string) {
	once.Do(func() {
		var config zap.Config

		if environment == "production" {
			// Production configuration: JSON format, Info level and above
			config = zap.NewProductionConfig()
			config.EncoderConfig.TimeKey = "timestamp"
			config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
		} else {
			// Development configuration: Console format, Debug level and above
			config = zap.NewDevelopmentConfig()
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		}

		// Common settings
		config.OutputPaths = []string{"stdout"}
		config.ErrorOutputPaths = []string{"stderr"}
		
		var err error
		Log, err = config.Build(
			zap.AddCallerSkip(1), // Skip the wrapper function in the stack trace
		)
		if err != nil {
			// If we can't initialize the logger, use a basic fallback and exit
			fallbackLogger := zap.NewExample()
			fallbackLogger.Error("Failed to initialize logger", zap.Error(err))
			Log = fallbackLogger
			os.Exit(1)
		}
	})
}

// Debug logs a message at debug level with optional fields
func Debug(msg string, fields ...Field) {
	Log.Debug(msg, fields...)
}

// Info logs a message at info level with optional fields
func Info(msg string, fields ...Field) {
	Log.Info(msg, fields...)
}

// Warn logs a message at warn level with optional fields
func Warn(msg string, fields ...Field) {
	Log.Warn(msg, fields...)
}

// Error logs a message at error level with optional fields
func Error(msg string, fields ...Field) {
	Log.Error(msg, fields...)
}

// Fatal logs a message at fatal level with optional fields then exits
func Fatal(msg string, fields ...Field) {
	Log.Fatal(msg, fields...)
}

// With creates a child logger with additional fields
func With(fields ...Field) *zap.Logger {
	return Log.With(fields...)
}

// Sync flushes any buffered log entries
func Sync() {
	_ = Log.Sync()
}
