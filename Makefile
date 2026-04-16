.PHONY: build run test test-e2e test-playwright test-e2e-wallet validate clean wasm gen-circuits

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

# Real-wallet e2e: boots the server with -dev -no-prover, runs Synpress+MetaMask
# tests, then tears the server down. Requires e2e/.env with TEST_SEED_PHRASE.
test-e2e-wallet: build
	cd e2e && npm install --silent
	@set -e ; \
		./bitwrap -port $(PORT) -dev -no-prover & \
		SERVER_PID=$$! ; \
		trap "kill $$SERVER_PID 2>/dev/null || true" EXIT ; \
		until curl -sf http://localhost:$(PORT)/ > /dev/null; do sleep 0.5; done ; \
		cd e2e && npx playwright test --project=wallet

# Regenerate synthesized ZK circuits from the ERC templates. CI runs this
# and asserts `git diff --exit-code` so stale generated code fails the build.
# See prover/synth/ for the generator.
gen-circuits: build
	./bitwrap -synthesize erc020 -output prover/erc020_gen.go
	./bitwrap -synthesize erc05725 -output prover/erc05725_gen.go

clean:
	rm -f bitwrap public/prover.wasm public/wasm_exec.js
