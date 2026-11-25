.PHONY: check lint lint-go lint-workflows lint-docs vuln fmt fmt-check test integration maven-seed tailnet cover build

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

## Run the end-to-end tests against real Composer, pip, uv, twine, the go command, npm, pnpm, mvn, gradle and apt (needs composer 2.x, git, python3 with pip, uv and twine, go, node with npm and pnpm, a JDK, mvn, gradle, gpg, apt-get and apt-cache; the PyPI tests download pinned build backends once, the mvn tests need make maven-seed)
integration:
	TSP_TEST_MAVEN_SEED="$${TSP_TEST_MAVEN_SEED:-$(MAVEN_SEED)}" go test -timeout 30m -tags integration ./integration/...

## Fill the local Maven repository that the mvn tests' fake upstream serves: every plugin and dependency they use, fetched once from Maven Central
MAVEN_SEED ?= $(CURDIR)/.maven-seed

maven-seed:
	mvn -B -ntp -Dmaven.repo.local=$(MAVEN_SEED) -f integration/testdata/maven/seed/pom.xml package install:help deploy:help

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

lint-docs: .vale/styles/.synced
	vale $(VALE_FLAGS) $(DOCS)

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
