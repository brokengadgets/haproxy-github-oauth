BIN := bin/haproxy-github-oauth
MODULE := haproxy-github-oauth
GO := go
GOLANGCI := golangci-lint

.PHONY: all build test lint check clean docker-build lua-test integration-test

all: check build

build:
	$(GO) build -o $(BIN) ./cmd/server/

test:
	$(GO) test -race -count=1 ./...

lint:
	$(GOLANGCI) run ./...
	@if command -v yamllint >/dev/null 2>&1; then \
		yamllint -d relaxed .; \
	else \
		echo "yamllint not installed, skipping"; \
	fi
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck scripts/*.sh; \
	else \
		echo "shellcheck not installed, skipping"; \
	fi
	@if command -v hadolint >/dev/null 2>&1; then \
		hadolint docker/Dockerfile; \
	else \
		echo "hadolint not installed, skipping"; \
	fi
	@if command -v luacheck >/dev/null 2>&1; then \
		luacheck haproxy/lua/; \
	else \
		echo "luacheck not installed, skipping"; \
	fi

lua-test:
	@if command -v busted >/dev/null 2>&1; then \
		busted --pattern "_test" haproxy/lua/; \
	else \
		echo "busted not installed; install with: luarocks install busted"; \
	fi

check: lint test

integration-test:
	$(GO) test -race -count=1 -tags integration ./tests/integration/...

docker-build:
	docker build -f docker/Dockerfile -t $(MODULE):local .

clean:
	rm -rf $(BIN) bin/
