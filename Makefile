.PHONY: build run test clean wasm

PORT ?= 8088

build:
	go build -o bitwrap ./cmd/bitwrap

wasm:
	GOOS=js GOARCH=wasm go build -o public/prover.wasm ./cmd/prover-wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" public/wasm_exec.js

run: build
	./bitwrap -port $(PORT)

test:
	go test ./...

clean:
	rm -f bitwrap public/prover.wasm public/wasm_exec.js
