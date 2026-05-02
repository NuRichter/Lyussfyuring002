.PHONY: all build clean install test

BINARY   = lyuss
GO_SRC   = ./cmd/lyuss/
C_SRC    = bin/payload_runner.c
C_BIN    = bin/payload_runner
LDFLAGS  = -ldflags="-s -w"

all: build

build: go_build c_build

go_build:
	@echo "[*] building Go binary..."
	go build $(LDFLAGS) -o $(BINARY) $(GO_SRC)
	@echo "[+] $(BINARY) ready"

c_build:
	@echo "[*] building C binary..."
	gcc -O2 -Wall -Wextra -o $(C_BIN) $(C_SRC)
	@echo "[+] $(C_BIN) ready"

install:
	@bash install.sh

test:
	go test ./... -v

clean:
	rm -f $(BINARY) $(C_BIN)
	rm -rf recon_out/

fmt:
	go fmt ./...
	rubocop -a ruby/ || true

deps:
	go mod tidy
	go mod download
