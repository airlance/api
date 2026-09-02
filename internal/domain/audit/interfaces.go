package audit

import (
	"context"
)

type Repository interface {
	Record(ctx context.Context, e *Event) error
}
