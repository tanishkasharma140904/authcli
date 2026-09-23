# syntax=docker/dockerfile:1

# ---- Build stage -----------------------------------------------------------
FROM golang:1.26-alpine AS build
WORKDIR /src

# Download dependencies first so they are cached between source changes.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# The SQLite driver is pure Go, so CGO can stay off and the binary is static.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authcli ./cmd/authcli

# ---- Test stage (docker build --target test .) -----------------------------
FROM build AS test
RUN go vet ./... && go test ./...

# ---- Runtime stage ---------------------------------------------------------
FROM alpine:3.22
# tzdata lets users set TZ=Europe/Berlin etc. for displayed timestamps.
RUN apk add --no-cache tzdata \
 && addgroup -S -g 10001 app \
 && adduser -S -D -H -u 10001 -G app app \
 && mkdir -p /data \
 && chown app:app /data \
 && chmod 700 /data

COPY --from=build /out/authcli /usr/local/bin/authcli

USER app
ENV AUTH_DB_PATH=/data/auth.db \
    TERM=xterm-256color
# The database lives here; mount a volume to persist it.
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/authcli"]
