FROM golang:1.27@sha256:e519d3b0a5b285e5aa53ab9eef02bc6bbb9cb04608389b743a136a9ce75f0d1e AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tspackages ./cmd/tspackages

FROM debian:stable-slim@sha256:fbfb4059d2127120aa05b6e6064523d2102552f0cf0026ddf0701c12f1f8f3e0
RUN apt-get update \
    && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/tspackages --shell /usr/sbin/nologin tspackages \
    && install -d -o tspackages -g tspackages -m 0700 /var/lib/tspackages
COPY --from=build /out/tspackages /usr/local/bin/tspackages
USER tspackages
VOLUME /var/lib/tspackages
ENTRYPOINT ["/usr/local/bin/tspackages", "-config", "/etc/tspackages/config.yaml"]
