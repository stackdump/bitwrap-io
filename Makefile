.PHONY: build run test check-pflow-js sync-pflow-js test-e2e test-playwright test-e2e-wallet test-wasm-prove validate clean wasm gen-circuits

PORT ?= 8088

build:
	go build -o bitwrap ./cmd/bitwrap

wasm:
	GOOS=js GOARCH=wasm go build -o public/prover.wasm ./cmd/prover-wasm
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" public/wasm_exec.js

run: build
	./bitwrap -port $(PORT)

test: check-pflow-js
	go test ./...

# Fail if a browser module vendored from pflow-xyz was edited here instead of
# upstream. Offline; see scripts/pflow-js.sh.
check-pflow-js:
	@./scripts/pflow-js.sh check

sync-pflow-js:
	@./scripts/pflow-js.sh sync

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
	./bitwrap -synthesize vote -output prover/vote_gen.go

# Regression check for issue #3 (gnark-crypto twisted-Edwards
# PointExtended.Add lazy-init bug). Builds wasm + native pk/vk for the
# v3 vote circuit and runs the wasm prover against the native bytes via
# the regular loadKeys path. The wasm prover applies the workaround
# (`_ = babyjubjub.GetEdwardsCurve()` at startup) so loadKeys+prove
# returns a real proof. Without that line — or without an upstream gnark-
# crypto fix — this fails with `constraint not satisfied` mid
# scalarMulFakeGLV. Requires a v3 witness dump at
# /tmp/v3-witness-dump.json (produced by `e2e/v3_dump_witness.spec.js`).
test-wasm-prove: wasm
	NATIVE_EXPORT_CIRCUIT=voteCastHomomorphic_8 go test -timeout 600s -run TestNativeExportKeys -v ./prover
	node public/wasm_load_native_diag.mjs voteCastHomomorphic_8
	go test -timeout 120s -run TestLoadKeysOnlyProveSubprocess -v ./prover

clean:
	rm -f bitwrap public/prover.wasm public/wasm_exec.js
