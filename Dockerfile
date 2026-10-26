# syntax=docker/dockerfile:1
FROM golang:1.27.3-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/tds-proxy ./cmd/tds-proxy

# Minimal runtime: static binary, CA certificates, no shell, non-root user.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tds-proxy /usr/local/bin/tds-proxy
USER nonroot:nonroot
EXPOSE 14331 14332 14333
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
  CMD ["/usr/local/bin/tds-proxy", "healthcheck", "-url", "http://127.0.0.1:8080/healthz"]
ENTRYPOINT ["/usr/local/bin/tds-proxy"]
CMD ["run", "-config", "/etc/tds-proxy/config.yaml"]
