package auth

import "errors"

var ErrUserDeactivated = errors.New("auth: user is deactivated")
var ErrCacheWarmupFailed = errors.New("auth: session cache warmup failed")
var ErrSessionNotFound = errors.New("auth: session not found or revoked")
var ErrInvalidResumeSecret = errors.New("auth: resume secret verification failed")
