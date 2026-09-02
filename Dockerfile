# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/airlance-api ./cmd/main

# Runtime stage
FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/airlance-api /app/airlance-api
COPY migrations /app/migrations

EXPOSE 8080

ENTRYPOINT ["/app/airlance-api"]
CMD ["serve"]
