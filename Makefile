APP := clipguard
CMD := ./cmd/clipguard

.PHONY: test build run

test:
	go test ./...

build:
	go build $(CMD)

run:
	go run $(CMD) run
