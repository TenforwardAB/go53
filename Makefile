TEST_PACKAGES := ./api/handlers/... ./config/... ./distributed/... ./dns/... ./internal/... ./memory/... ./security/... ./zone/... ./zone/rtypes/...

.PHONY: test badge

test:
	go test -coverprofile=coverage.out $(TEST_PACKAGES)

badge: test
	go run tools/genbadge.go
