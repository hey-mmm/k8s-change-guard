GO ?= go
VERSION ?= $(shell sed -n 's/^const Version = "\([^"]*\)"/\1/p' internal/guard/common.go)
GO_PACKAGES := ./cmd/... ./internal/... ./scripts/packaging
GOFMT_PATHS := cmd internal scripts/packaging

.PHONY: all fmt fmt-check vet test scenario verify-knowledge build release release-windows acceptance health

all: fmt-check vet test scenario verify-knowledge

fmt:
	gofmt -w $(GOFMT_PATHS)

fmt-check:
	@unformatted="$$(gofmt -l $(GOFMT_PATHS))"; \
	if [ -n "$$unformatted" ]; then echo "unformatted Go files:"; echo "$$unformatted"; exit 1; fi

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

scenario:
	$(GO) run ./cmd/change-guard scenario --output scenario-matrix.json

verify-knowledge:
	$(GO) run ./cmd/change-guard verify-knowledge --knowledge-dir knowledge

build:
	$(GO) build -trimpath -buildvcs=false -o bin/change-guard ./cmd/change-guard

release:
	sh scripts/build-release.sh --version "$(VERSION)"

release-windows:
	pwsh -NoProfile -File scripts/build-release.ps1 -Go "$(GO)" -Version "$(VERSION)"

acceptance:
	sh scripts/acceptance.sh

health:
	sh scripts/health-check.sh
