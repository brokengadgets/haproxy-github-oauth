# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/haproxy-github-oauth ./cmd/server/

FROM alpine:3.20
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S app && adduser -S -G app app
USER app
COPY --from=builder /bin/haproxy-github-oauth /usr/local/bin/haproxy-github-oauth
EXPOSE 4180
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD ["wget", "-qO-", "http://localhost:4180/healthz"]
ENTRYPOINT ["/usr/local/bin/haproxy-github-oauth"]
