APP := clipguard
CMD := ./cmd/clipguard
GO ?= go

.PHONY: fmt fmt-check vet lint test build run ci

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

lint:
	@if command -v staticcheck >/dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not found; skipping optional lint step"; \
	fi

test:
	$(GO) test ./...

build:
	$(GO) build $(CMD)

run:
	$(GO) run $(CMD) run

ci: fmt-check test vet lint build
