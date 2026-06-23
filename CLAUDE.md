# bitwrap-io

Petri Nets as ZK Containers. Visual editor + ZK prover + Solidity generation + .btw DSL.

## Quick Start

```bash
make run              # Serves on :8088
make build            # Build binary only
make test             # Run tests
```

### Bazel (Bzlmod, hermetic — opt-in alongside `go build`)

bitwrap-io also builds under pure-Bzlmod Bazel, mirroring [go-pflow](../go-pflow/CLAUDE.md#build-systems) and [beats-bitwrap-io](../beats-bitwrap-io/CLAUDE.md). `go.mod`/`go.sum` stay the source of truth (Gazelle's `go_deps` reads them), so `make build` / `go test ./...` keep working — Bazel is opt-in. Driven by bazelisk (pinned in `.bazelversion`).

```bash
bazel build //...     # build everything (runs nogo; builds prover.wasm hermetically)
bazel test //...      # all tests — Go targets + 6 pure-JS parity tests
bazel run //:gazelle  # regenerate BUILD.bazel after adding/moving .go files
bazel mod tidy        # sync go_deps use_repo after editing go.mod
```

Second cross-project consumer on the Bazel graph (go-pflow ROADMAP Phase 1 — confirms the pattern generalizes). Pins **mirror go-pflow exactly** (rules_go 0.55.1, gazelle 0.44.0, Go SDK 1.24.10, Bazel 7.6.1) since both share the Go 1.24 line — maximizing shared-cache hits once Phase 2 lands. Decisions specific to bitwrap:

- **go-pflow is an ordinary registry dep** (go.mod pins `v0.9.0`, no local `replace`), so `go_deps` fetches it like any module — no cross-repo wiring (simpler than beats, which uses a local replace).
- **`purego` tag** (`.bazelrc`) — gnark-crypto asm doesn't resolve in the sandbox; Bazel uses pure-Go field arithmetic. `go build`/Makefile keep the asm fast path.
- **Hermetic wasm.** `public/embed.go` embeds `prover.wasm`, a 23 MB gitignored artifact normally produced by `make wasm`. Under Bazel it's built **in the graph**: `//cmd/prover-wasm` carries `goos=js, goarch=wasm` (`# keep`) so it always cross-builds, and `//public:gen_prover_wasm` copies it to `prover.wasm` for the embed (`# gazelle:exclude prover.wasm` keeps Gazelle off the on-disk copy). So `bazel build //...` is self-contained — *more* hermetic than `go build`, which needs a prior `make wasm`. The small `wasm_exec.js` runtime shim is committed (tied to the Go 1.24 line; refreshed by `make wasm`).
- **JS in the graph.** `//public:*` `nodejs_test` targets run the 6 pure-JS parity/smoke checks (coercion, parity, pedersen, seal-cid, sk-creator-store, witness-v3) under a hermetic Node toolchain, via the shared `tools/nodejs_test.bzl` rule. The 6 WASM-dependent diagnostics (`v3_wasm_*`, `wasm_load_*`, `wasm_roundtrip`, `prover_wasm_circuits_smoke`) need a prover.wasm + Go runtime harness and are **not yet wired** — a known gap.
- After editing `go.mod` → `bazel mod tidy`; after adding/moving `.go` files → `bazel run //:gazelle`.

## Flags

```
-port 8088                  HTTP port (default 8088)
-data ./data                Data directory for CID storage
-no-prover                  Disable ZK prover (faster startup)
-no-solgen                  Disable Solidity generation endpoints
-key-dir ./keys             Persist circuit keys for fast restarts
-compile path/to/file.btw   Compile .btw file to JSON schema on stdout
```

## Architecture

- `cmd/bitwrap/main.go` — single binary entry point
- `dsl/` — .btw DSL lexer, parser, AST, builder
- `erc/` — ERC token standard templates (020, 0721, 01155, 04626, 05725)
- `prover/` — ZK circuits (Groth16 via gnark, re-exports from go-pflow)
- `solidity/` — Solidity contract generation from metamodel schemas
- `internal/server/` — HTTP handlers
- `internal/petri/` — Petri net model types + execution engine
- `internal/metamodel/` — Schema types (states, actions, arcs, events, constraints)
- `internal/metamodel/guard/` — Guard expression parser + evaluator
- `arc/` — Arc-level execution (MiMC Merkle state trees, firing, safe math)
- `internal/seal/` — CID computation (JSON-LD canonicalization)
- `internal/store/` — Filesystem storage
- `internal/svg/` — SVG generation from Petri net models
- `public/` — frontend JS/CSS/HTML (go:embed via public/embed.go)

## API

- `GET /` — landing page
- `GET /editor` — visual Petri net editor
- `GET /remix` — Remix IDE plugin
- `POST /api/save` — save JSON-LD, returns `{"cid": "..."}`
- `GET /o/{cid}` — get stored model by CID
- `GET /img/{cid}.svg` — render model as SVG
- `POST /api/svg` — generate SVG from posted JSON-LD
- `GET /api/templates` — list ERC templates
- `GET /api/templates/{id}` — get full template model
- `POST /api/solgen` — generate Solidity from template ID
- `POST /api/testgen` — generate Foundry tests from template ID
- `POST /api/genesisgen` — generate Foundry genesis script from template ID
- `POST /api/compile` — compile .btw DSL source to schema JSON
- `GET /api/circuits` — list available ZK circuits
- `POST /api/prove` — submit witness for ZK proof generation
- `GET /api/vk/{circuit}` — download verifying key (binary)
- `GET /api/vk/{circuit}/solidity` — download Solidity verifier contract

## Dependencies

- `github.com/pflow-xyz/go-pflow` — core prover infrastructure
- `github.com/consensys/gnark` — ZK proof system (Groth16)
- `github.com/ipfs/go-cid` — content addressing
- `github.com/piprate/json-gold` — JSON-LD canonicalization (URDNA2015)
- `github.com/holiman/uint256` — safe 256-bit arithmetic

## Subdomains

| URL | Port | Purpose |
|-----|------|---------|
| bitwrap.io | 8088 | Landing page |
| app.bitwrap.io | 8088 | Editor (redirects to /editor) |
| api.bitwrap.io | 8088 | API endpoints |
| solver.bitwrap.io | 8088 | Remix IDE plugin (redirects to /remix) |
| prover.bitwrap.io | 8088 | ZK prover |

## Deployment

```bash
ssh pflow.dev "cd ~/Workspace/bitwrap-io && git pull && make build && ~/services restart bitwrap"
```

## Testnet publishing

Generated Foundry deploy scripts read the deployer key from the **`PRIVATE_KEY`** env var
(`solidity/genesisgen.go` emits `vm.envUint("PRIVATE_KEY")` + `vm.startBroadcast`). To publish
a generated contract:

```bash
forge script script/Deploy.s.sol --rpc-url <testnet-rpc> --broadcast   # PRIVATE_KEY from env
```

- **Deployer wallet:** `0x762593292f543948CA9A9a290adC1770746d059a` — active on **Base Sepolia**
  (the live testnet for bitwrap publishing); also funded on Ethereum Sepolia.
- **Key storage:** never committed (no `.env` in the repo). On the **laptop** it's exported in
  the shell env; on **valoper** it lives at `~/.env-services/bitwrap` (mode 0600) — source with
  `set -a; . ~/.env-services/bitwrap` before running `forge`.
- **Not a real key:** the local verify flow in `cmd/bitwrap/main.go` (step 9) hardcodes the
  well-known public Anvil dev account `0xac09…ff80` and deploys to a throwaway `anvil`
  (chain-id 31337) — never use it against a real testnet.
