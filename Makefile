.PHONY: build run test test-e2e test-playwright validate clean wasm

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

test-e2e:
	go test -tags e2e -timeout 600s -v ./internal/server/ -run TestFoundryE2E

validate: build
	./bitwrap -validate $(BTW)

test-playwright:
	cd e2e && npm install --silent && npx playwright install chromium 2>/dev/null; cd e2e && npx playwright test

clean:
	rm -f bitwrap public/prover.wasm public/wasm_exec.js
