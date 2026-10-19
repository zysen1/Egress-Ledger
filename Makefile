.PHONY: build test vet demo

build:
	go build -o bin/egress-ledger ./cmd/egress-ledger

test:
	go test ./...

vet:
	go vet ./...

demo: build
	./bin/egress-ledger demo --out examples/demo-output --docs docs
