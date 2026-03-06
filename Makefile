BINARY := recon0
PKG := github.com/badchars/recon0
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test clean docker-build docker-push

build:
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/recon0

build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BINARY)-linux-amd64 ./cmd/recon0

test:
	go test ./... -v

clean:
	rm -f $(BINARY) $(BINARY)-linux-amd64
	rm -rf dist/

docker-build:
	docker build -t ghcr.io/badchars/$(BINARY):$(VERSION) -t ghcr.io/badchars/$(BINARY):latest .

docker-push:
	docker push ghcr.io/badchars/$(BINARY):$(VERSION)
	docker push ghcr.io/badchars/$(BINARY):latest

fmt:
	go fmt ./...

vet:
	go vet ./...
