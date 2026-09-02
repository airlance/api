package otp

import (
	"testing"
	"time"
)

func TestCode_IsActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		code     Code
		expected bool
	}{
		{
			name: "active code",
			code: Code{
				Attempts:    0,
				MaxAttempts: 5,
				ExpiresAt:   now.Add(5 * time.Minute),
				ConsumedAt:  nil,
			},
			expected: true,
		},
		{
			name: "consumed code",
			code: Code{
				Attempts:    0,
				MaxAttempts: 5,
				ExpiresAt:   now.Add(5 * time.Minute),
				ConsumedAt:  &now,
			},
			expected: false,
		},
		{
			name: "expired code",
			code: Code{
				Attempts:    0,
				MaxAttempts: 5,
				ExpiresAt:   now.Add(-1 * time.Minute),
				ConsumedAt:  nil,
			},
			expected: false,
		},
		{
			name: "attempts reached max",
			code: Code{
				Attempts:    5,
				MaxAttempts: 5,
				ExpiresAt:   now.Add(5 * time.Minute),
				ConsumedAt:  nil,
			},
			expected: false,
		},
		{
			name: "attempts exceeded max",
			code: Code{
				Attempts:    6,
				MaxAttempts: 5,
				ExpiresAt:   now.Add(5 * time.Minute),
				ConsumedAt:  nil,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.code.IsActive(now)
			if got != tt.expected {
				t.Errorf("IsActive() = %v, want %v", got, tt.expected)
			}
		})
	}
}
