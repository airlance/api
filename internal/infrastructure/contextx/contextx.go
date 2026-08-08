package contextx

import "context"

type contextKey int

const requestIDKey contextKey = 0
const userKey contextKey = 1

func SetRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

func GetRequestID(ctx context.Context) (string, bool) {
	reqID, ok := ctx.Value(requestIDKey).(string)
	return reqID, ok
}

func SetUser[T any](ctx context.Context, user T) context.Context {
	return context.WithValue(ctx, userKey, user)
}

func GetUser[T any](ctx context.Context) (T, bool) {
	user, ok := ctx.Value(userKey).(T)
	return user, ok
}
