.PHONY: all web build linux test integration dev clean

all: build

web:
	cd web && npm install --no-audit --no-fund && npm run build

build: web
	go build -o bin/mini-net-man ./cmd/mini-net-man

# Static Linux binaries to copy to the server.
linux: web
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/mini-net-man-linux-amd64 ./cmd/mini-net-man
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags "-s -w" -o bin/mini-net-man-linux-arm64 ./cmd/mini-net-man

test:
	go test ./...

# Real-kernel tests: netlink + nftables inside a privileged Linux container
# (needs Docker). Each test runs in its own network namespace.
# Run one with: make integration T=TestFirewallBehavior
integration:
	docker build -q -f Dockerfile.test -t mnm-test .
	docker run --rm --privileged -v "$(CURDIR)":/src -v mnm-gomod:/go/pkg/mod -v mnm-gobuild:/root/.cache/go-build \
		mnm-test sh scripts/integration.sh $(T)

# UI development: fake kernel on :8080, Vite with hot reload on :5173.
dev:
	go run ./cmd/mini-net-man -mock -config mock-config.yaml & cd web && npm run dev

clean:
	rm -rf bin web/dist/assets mock-config.yaml*
