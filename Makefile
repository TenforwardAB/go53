TEST_PACKAGES := ./api/handlers/... ./config/... ./distributed/... ./dns/... ./internal/... ./memory/... ./security/... ./zone/... ./zone/rtypes/...

.PHONY: test badge build build-server build-ctl release

test:
	go test -coverprofile=coverage.out $(TEST_PACKAGES)

badge: test
	go run tools/genbadge.go

build: build-server build-ctl

build-server:
	go build -o go53 ./cmd/server

build-ctl:
	go build -o go53ctl ./cmd/go53ctl

release:
	goreleaser release --clean
