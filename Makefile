.PHONY: build test run docker-build docker-run docker-test docker-reset

# ---- Local (requires Go 1.26+) ---------------------------------------------
build:
	CGO_ENABLED=0 go build -o bin/authcli ./cmd/authcli

test:
	go vet ./... && go test ./...

run: build
	./bin/authcli

# ---- Docker (no local Go needed) --------------------------------------------
docker-build:
	docker compose build

docker-run: docker-build
	docker compose run --rm authcli

docker-test:
	docker build --target test .

# Deletes the persisted database volume. Irreversible!
docker-reset:
	docker compose down -v
