# syntax=docker/dockerfile:1
# The builder runs on the build platform and cross-compiles, so a multi-arch
# build doesn't emulate the compiler.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
# .git is not in the build context, so the revision is passed in.
ARG REVISION
ARG TARGETOS TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${REVISION}" \
    -o /out/tspackages ./cmd/tspackages

# Not distroless: git sources need the git and ssh binaries.
FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0
LABEL org.opencontainers.image.source="https://github.com/Radiergummi/tspackages" \
      org.opencontainers.image.description="A package registry that exists only on your tailnet" \
      org.opencontainers.image.licenses="Apache-2.0"
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/tspackages --shell /usr/sbin/nologin tspackages \
    && install -d -o tspackages -g tspackages -m 0700 /var/lib/tspackages
COPY --from=build /out/tspackages /usr/local/bin/tspackages
USER tspackages
VOLUME /var/lib/tspackages
ENTRYPOINT ["/usr/local/bin/tspackages", "-config", "/etc/tspackages/config.yaml"]
