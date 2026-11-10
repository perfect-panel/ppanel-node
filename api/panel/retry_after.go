package panel

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// retryAfterError preserves the HTTP cooldown hint for the admission limiter
// without retrying inside an individual connection's panel request.
type retryAfterError struct {
	err   error
	delay time.Duration
}

func (e *retryAfterError) Error() string             { return e.err.Error() }
func (e *retryAfterError) Unwrap() error             { return e.err }
func (e *retryAfterError) RetryAfter() time.Duration { return e.delay }

func withRetryAfter(err error, header string, now time.Time) error {
	header = strings.TrimSpace(header)
	var delay time.Duration
	if seconds, parseErr := strconv.ParseUint(header, 10, 64); parseErr == nil {
		// A malformed or extreme header must not overflow into immediate retry.
		delay = time.Duration(min(seconds, uint64((24*time.Hour)/time.Second))) * time.Second
	} else if when, parseErr := http.ParseTime(header); parseErr == nil {
		delay = min(when.Sub(now), 24*time.Hour)
	}
	if delay <= 0 {
		return err
	}
	return &retryAfterError{err: err, delay: delay}
}
