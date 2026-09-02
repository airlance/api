package ws

import (
	"errors"
	"testing"
)

func TestValidateSequence(t *testing.T) {
	tests := []struct {
		name        string
		expectedSeq uint64
		actualSeq   uint64
		wantErr     error
	}{
		{
			name:        "sequential initial frame",
			expectedSeq: 1,
			actualSeq:   1,
			wantErr:     nil,
		},
		{
			name:        "sequential subsequent frame",
			expectedSeq: 42,
			actualSeq:   42,
			wantErr:     nil,
		},
		{
			name:        "replay attack with past sequence",
			expectedSeq: 5,
			actualSeq:   4,
			wantErr:     ErrSequenceMismatch,
		},
		{
			name:        "immediate replay duplicate",
			expectedSeq: 10,
			actualSeq:   9,
			wantErr:     ErrSequenceMismatch,
		},
		{
			name:        "skipped sequence (out of order)",
			expectedSeq: 2,
			actualSeq:   3,
			wantErr:     ErrSequenceMismatch,
		},
		{
			name:        "zero actual sequence when expecting positive",
			expectedSeq: 1,
			actualSeq:   0,
			wantErr:     ErrSequenceMismatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSequence(tt.expectedSeq, tt.actualSeq)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("expected nil error, got: %v", err)
				}
			} else {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got: %v", tt.wantErr, err)
				}
			}
		})
	}
}
