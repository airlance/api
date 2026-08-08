APP_NAME=app
CMD_DIR=./cmd/app
BIN_DIR=./bin
VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.Commit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)

.PHONY: help version run fmt vet lint tidy migrate-up migrate-down migrate-create up

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-25s %s\n", $$1, $$2}'

version: ## Show build metadata
	@echo "Version: $(VERSION)"
	@echo "Commit:  $(COMMIT)"
	@echo "Build:   $(BUILD_DATE)"

docker-dev-build: ## Build docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--no-cache \
		-t airlance/api:dev .

docker-dev-push: ## Push docker image
	docker push airlance/api:dev

up: ## Start docker containers
	docker compose up -d

run: ## Run application
	go run $(CMD_DIR) serve

fmt: ## Format code
	go fmt ./...

vet: ## Vet code
	go vet ./...

lint: ## Run golangci-lint
	golangci-lint run

tidy: ## Go mod tidy
	go mod tidy

migrate-up: ## Apply migrations
	go run $(CMD_DIR) migrate up

migrate-down: ## Rollback one migration
	go run $(CMD_DIR) migrate down --steps 1

migrate-create: ## Create migration
	go run $(CMD_DIR) migrate create $(name)
