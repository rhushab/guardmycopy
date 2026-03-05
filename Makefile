APP := guardmycopy
CMD := ./cmd/guardmycopy
GO ?= go
GO_BIN := $(shell $(GO) env GOPATH)/bin
STATICCHECK_VERSION ?= latest
GOVULNCHECK_VERSION ?= latest
STATICCHECK := $(GO_BIN)/staticcheck
GOVULNCHECK := $(GO_BIN)/govulncheck

.PHONY: fmt fmt-check vet tools lint vuln test build run ci

fmt:
	$(GO) fmt ./...

fmt-check:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "The following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

vet:
	$(GO) vet ./...

tools: $(STATICCHECK) $(GOVULNCHECK)

$(STATICCHECK):
	$(GO) install honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION)

$(GOVULNCHECK):
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)

lint: $(STATICCHECK)
	$(STATICCHECK) ./...

vuln: $(GOVULNCHECK)
	$(GOVULNCHECK) ./...

test:
	$(GO) test ./...

build:
	$(GO) build $(CMD)

run:
	$(GO) run $(CMD) run

ci: fmt-check test vet lint vuln build
