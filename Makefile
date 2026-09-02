.DEFAULT_GOAL := help

BINARY       := airlance-api
CMD          := ./cmd/main
VERSION      := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS      := -X 'airlance.org/api/internal/cli.Version=$(VERSION)'
GOCACHE_DIR  ?= $(CURDIR)/.gocache

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

## --- Build & run ------------------------------------------------------

.PHONY: build
build: ## Build the airlance-api binary into ./dist
	mkdir -p dist
	go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY) $(CMD)

.PHONY: run
run: ## Run the HTTP/WS server (expects env already loaded, see .env.example)
	go run $(CMD) serve

.PHONY: cleanup
cleanup: ## Purge expired challenges/sessions (pass ARGS="--max-age 24h")
	go run $(CMD) cleanup $(ARGS)

## --- Local infrastructure ----------------------------------------------

.PHONY: dev-up
dev-up: ## Start local Postgres, Redis, and Mailpit via docker compose
	docker compose up -d postgres redis mailpit

.PHONY: dev-down
dev-down: ## Stop local docker compose services
	docker compose down

.PHONY: migrate-up
migrate-up: ## Apply all available migrations
	go run $(CMD) migrate up

.PHONY: migrate-down
migrate-down: ## Roll back one migration (pass ARGS="--steps N" for more)
	go run $(CMD) migrate down $(ARGS)

.PHONY: migrate-create
migrate-create: ## Create a new migration pair: make migrate-create NAME=add_something
	@if [ -z "$(NAME)" ]; then echo "usage: make migrate-create NAME=add_something"; exit 1; fi
	go run $(CMD) migrate create $(NAME)

## --- Secrets ------------------------------------------------------------

.PHONY: keys
keys: ## Generate a fresh HMAC/JWT/wireauth secret set for a new environment
	go run $(CMD) keys all

.PHONY: keys-hmac
keys-hmac: ## Generate a single HMAC key ring entry (pass ARGS="--id 2" to rotate)
	go run $(CMD) keys hmac $(ARGS)

.PHONY: keys-jwt
keys-jwt: ## Generate a single JWT Ed25519 key ring entry
	go run $(CMD) keys jwt $(ARGS)

.PHONY: keys-wireauth
keys-wireauth: ## Generate the wireauth v2 RSA private key file
	go run $(CMD) keys wireauth $(ARGS)

## --- Quality gates (see AGENTS.md > Change checklist) -------------------

.PHONY: fmt
fmt: ## gofmt every tracked Go file
	gofmt -l -w .

.PHONY: vet
vet: ## go vet ./...
	GOCACHE=$(GOCACHE_DIR) go vet ./...

.PHONY: test
test: ## go test ./...
	GOCACHE=$(GOCACHE_DIR) go test ./...

.PHONY: lint
lint: ## golangci-lint run (requires golangci-lint on PATH)
	GOCACHE=$(GOCACHE_DIR) golangci-lint run ./...

.PHONY: check
check: fmt vet lint test ## Run the full local check suite before handoff

.PHONY: clean
clean: ## Remove build/test artifacts
	rm -rf dist coverage.out coverage.html $(GOCACHE_DIR)
