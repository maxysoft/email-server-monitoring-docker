# Build metadata — auto-computed so BUILD_DATE is always "now" and VCS_REF/VERSION
# track the repo. Override on the command line if needed: `make build VERSION=v1.2.3`.
VERSION    ?= $(shell cat VERSION 2>/dev/null || echo v0.0.0)
VCS_REF    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Exported so docker compose interpolates ${VERSION}/${VCS_REF}/${BUILD_DATE}.
export VERSION VCS_REF BUILD_DATE

.PHONY: build up down restart logs config print

build: ## Build the image with fresh BUILD_DATE/VCS_REF/VERSION
	docker compose build

up: ## Build (if needed) and start in the background
	docker compose up -d

down: ## Stop and remove the stack
	docker compose down

restart: ## Restart the service
	docker compose restart

logs: ## Tail service logs
	docker compose logs -f

config: ## Render the fully-resolved compose config
	docker compose config

print: ## Show the build metadata that would be used
	@echo "VERSION=$(VERSION)"
	@echo "VCS_REF=$(VCS_REF)"
	@echo "BUILD_DATE=$(BUILD_DATE)"
