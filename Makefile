.PHONY: build test fuzz integration docker dev-up

build:
	CGO_ENABLED=0 go build -trimpath -o tds-proxy ./cmd/tds-proxy

test:
	go vet ./...
	go test -race -count=1 ./...

# Runs each fuzz target for FUZZTIME (default 30s).
FUZZTIME ?= 30s
fuzz:
	for f in FuzzParseLogin7 FuzzParsePrelogin FuzzParseLoginTokens FuzzReadMessage; do \
		go test -run='^$$' -fuzz="^$$f\$$" -fuzztime=$(FUZZTIME) ./internal/protocol/ || exit 1; done

integration:
	./scripts/integration-test.sh -v

docker:
	docker build -t tds-auth-proxy:latest .

dev-up:
	./scripts/dev-setup.sh
	docker compose up -d --build
