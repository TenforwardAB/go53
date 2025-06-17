.PHONY: test badge

test:
	go test -coverprofile=coverage.out ./zone/rtypes/... ./config/... ./dns/dnsutils/...

badge: test
	go run tools/genbadge.go
