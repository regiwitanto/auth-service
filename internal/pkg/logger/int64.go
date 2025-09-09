package logger

import (
	"go.uber.org/zap"
)

// Int64 constructs an int64 field with the given key and value
func Int64(key string, val int64) Field {
	return zap.Int64(key, val)
}
