# vhlocal (Go port) build + release.
# Build ordering: `make ui` (npm build → vhlocal/web/app) before `make build`
# so the embedded UI is current. Binaries are self-contained (assets embedded).

GO       ?= go
BIN      ?= bin/vhlocal
PKG      := ./cmd/vhlocal
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X vhlocal.Version=$(VERSION)
# CGO off keeps cross-compilation pure/static (research R12).
export CGO_ENABLED = 0

.PHONY: all build ui test vet fmt release clean bench-efficacy browser-test

# Score existing artifacts only; this target never launches a scan/provider.
bench-efficacy:
	@test -n "$(RESULTS)" || (echo 'Set RESULTS to an existing results directory'; exit 2)
	$(GO) run ./cmd/vhlocal bench efficacy --results "$(RESULTS)" --truth testdata/benchmark/truth/ground_truth.json $(if $(BASELINE),--baseline "$(BASELINE)",) --json

# Requires the operator-installed Playwright package and browser runtime.
browser-test:
	cd web-react && npx --no-install playwright test --config tests/browser/playwright.config.ts

all: build

ui:
	cd web-react && npm ci && npm run build

build:
	@mkdir -p $(dir $(BIN))
	$(GO) build -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

# Cross-platform release binaries (SC-012). Run `make ui` first.
release:
	@mkdir -p dist
	@for pair in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
	  os=$${pair%/*}; arch=$${pair#*/}; \
	  out=dist/$(notdir $(BIN))-$$os-$$arch; \
	  echo "building $$out"; \
	  GOOS=$$os GOARCH=$$arch $(GO) build -ldflags '$(LDFLAGS)' -o $$out $(PKG) || exit 1; \
	done

clean:
	rm -f $(BIN)
	rm -rf dist
