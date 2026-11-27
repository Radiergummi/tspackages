.PHONY: check lint lint-go lint-workflows lint-docs vuln fmt fmt-check test integration tailnet cover build

## The gate CI runs: lint, formatting, vet and the race-enabled tests
check: lint fmt-check
	go vet ./...
	go test -race ./...

## Lint the Go code, the workflows and the docs
lint: lint-go lint-workflows lint-docs

lint-go:
	golangci-lint run ./...

lint-workflows:
	actionlint
	zizmor --config .github/zizmor.yml .github/workflows/ .github/actions/

## Format the Go code in place
fmt:
	golangci-lint fmt ./...

## Fail on Go code that needs formatting
fmt-check:
	golangci-lint fmt --diff ./... 2>&1 | diff /dev/null -

## Run the unit tests
test:
	go test ./...

## Run the end-to-end tests against real Composer, pip, uv, twine and the go command (needs composer 2.x, git, python3 with pip, uv and twine, and go; the PyPI tests download pinned build backends once)
integration:
	go test -tags integration ./integration/...

## Run tspackages and a client as real tsnet nodes against an in-process control server, including main's startup and shutdown
tailnet:
	go test -race -tags tailnet ./internal/server ./cmd/tspackages

## Write cover.out and cover.html
cover:
	go test -coverprofile=cover.out ./...
	go tool cover -html=cover.out -o cover.html

## Fail on a reachable vulnerability that VULN_IGNORE does not list
# Space-separated GO-YYYY-NNNN IDs, each with a comment saying why. Drop an ID
# once govulncheck names a release that fixes it.
VULN_IGNORE :=

vuln:
	@out=$$(go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -format json ./...) && \
	found=$$(printf '%s' "$$out" | jq -r --arg ignore "$(VULN_IGNORE)" \
		'select(.finding.trace[0].function? != null) | .finding.osv | select(IN($$ignore | split(" ")[]) | not)' | sort -u) && \
	if [ -n "$$found" ]; then echo "reachable vulnerabilities:"; echo "$$found"; exit 1; fi

## Build ./tspackages, stamped with the version and commit
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)" -o tspackages ./cmd/tspackages

## Lint the prose of the docs
DOCS := $(wildcard docs/*.md) README.md CONTRIBUTING.md SECURITY.md CHANGELOG.md
VALE_FLAGS ?=

# The Vale release lint-docs runs, by SHA-256 per platform. Dictionaries change
# between releases, so a Vale from PATH could pass words CI's fails.
VALE_VERSION := 3.22.0
VALE_PLATFORM := $(shell uname -s)_$(shell uname -m)
VALE_ASSET_Linux_x86_64   := Linux_64-bit=52f5cd0314a1b7384cac6aa102a68193977312f6ba9c9f3ae001b5deec8e3a10
VALE_ASSET_Linux_aarch64  := Linux_arm64=18f57dfe023e804159b2bb307f00274d801d426c518a8a0cc25d4f98bf035e73
VALE_ASSET_Darwin_x86_64  := macOS_64-bit=e54a94b86d45f8bdd751f31ad3d06d6ae04da1154e720a006ed0f2e03a675fff
VALE_ASSET_Darwin_arm64   := macOS_arm64=7dea014d6586101f6f695105f2e8825b7297236df0af9e68e193bcb4e4d25f7e
VALE_ASSET := $(VALE_ASSET_$(VALE_PLATFORM))
VALE := .vale/bin/vale-$(VALE_VERSION)

lint-docs: $(VALE) .vale/styles/.synced
	$(VALE) $(VALE_FLAGS) $(DOCS)

$(VALE):
	@set -e; asset='$(VALE_ASSET)'; \
	[ -n "$$asset" ] || { echo "no pinned Vale build for $(VALE_PLATFORM)" >&2; exit 1; }; \
	tgz=$$(mktemp); \
	curl -fsSL -o "$$tgz" "https://github.com/vale-cli/vale/releases/download/v$(VALE_VERSION)/vale_$(VALE_VERSION)_$${asset%=*}.tar.gz"; \
	echo "$${asset##*=}  $$tgz" | sha256sum -c - >/dev/null || { echo "checksum mismatch: Vale $(VALE_VERSION)" >&2; rm -f "$$tgz"; exit 1; }; \
	mkdir -p $(@D); tar -xzf "$$tgz" -C $(@D) vale; rm -f "$$tgz"; mv $(@D)/vale $@

# The style packages .vale.ini names, by URL and SHA-256. Fetched here rather
# than by `vale sync`, which checks nothing it downloads.
VALE_PACKAGES := \
	https://github.com/errata-ai/Google/releases/download/v0.7.0/Google.zip=dddb3dca035a067fe9ab13a1d8d8f89cb63e8b83ab4cf1934a935d60cd91d697 \
	https://github.com/errata-ai/proselint/releases/download/v0.3.4/proselint.zip=48b1fb481ba44f6505d44346b283f6cdc74efd234f913bbdb09bf34420fab81c

.vale/styles/.synced: Makefile
	@set -e; for package in $(VALE_PACKAGES); do \
		url=$${package%=*}; zip=$$(mktemp); \
		curl -fsSL -o "$$zip" "$$url"; \
		echo "$${package##*=}  $$zip" | sha256sum -c - >/dev/null || { echo "checksum mismatch: $$url" >&2; rm -f "$$zip"; exit 1; }; \
		unzip -qo "$$zip" -d .vale/styles; rm -f "$$zip"; \
	done
	touch $@
