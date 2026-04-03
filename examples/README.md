# .btw DSL Reference

The `.btw` (bitwrap) DSL describes Petri net models that compile to Solidity smart contracts.

## Quick Start

```bash
# Validate a .btw file (parse → Solidity → compile → test → deploy)
./bitwrap -validate examples/erc20.btw

# Just compile to JSON schema
./bitwrap -compile examples/erc20.btw
```

## Syntax

### Schema Declaration

```
schema MyToken {
  version "1.0.0"
  domain "custody"       # optional
  asset "erc20"          # optional

  # ... registers, events, functions
}
```

### Registers (State Variables)

Registers declare the contract's state. Scalar types become `uint256` storage. Map types become Solidity `mapping(...)` storage.

```
register BALANCES map[address]uint256 observable
register ALLOWANCES map[address]map[address]uint256 observable
register TOTAL_SUPPLY uint256
register NEXT_ID uint256
```

- `observable` makes the variable `public` in Solidity (auto-generates a getter)
- Supported types: `uint256`, `address`, `bool`, `map[keyType]valueType`
- Nested maps: `map[address]map[address]uint256` for allowance-style patterns

### Events

```
event TransferEvent {
  from: address indexed
  to: address indexed
  amount: uint256
}
```

Events map to Solidity `event` declarations. `indexed` fields become indexed event parameters.

### Functions (Actions)

Functions are the transitions in the Petri net. They consume tokens from input places and produce tokens at output places.

```
fn(transfer) {
  var from address
  var to address
  var amount amount

  require(BALANCES[from] >= amount && to != address(0))
  @event TransferEvent

  BALANCES[from] -|amount|> transfer      # input arc: consume from BALANCES[from]
  transfer -|amount|> BALANCES[to]        # output arc: produce at BALANCES[to]
}
```

#### Variables

`var name type` declares a function parameter. The type `amount` is shorthand for `uint256`.

#### Guards

`require(expr)` adds a Solidity `require(...)` statement. The expression can reference registers, variables, and `caller` (maps to `msg.sender`).

#### Event Reference

`@event EventName` links the function to an event. The event is emitted when the function executes.

#### Arcs

Arcs define token flow using the syntax: `SOURCE -|WEIGHT|> TARGET`

- **Input arc** (consume): `REGISTER[key] -|weight|> functionName`
- **Output arc** (produce): `functionName -|weight|> REGISTER[key]`
- **Nested keys**: `ALLOWANCES[owner][spender] -|amount|> approve`
- **Literal weight**: `transfer -|1|> BALANCES[to]` (for NFTs — always moves exactly 1)

When the weight is a variable name (like `amount`), it becomes a function parameter.
When the weight is a number (like `1`), it's a literal.

## Examples

| File | Pattern | Description |
|------|---------|-------------|
| `counter.btw` | Scalar state | Simple increment/decrement counter |
| `erc20.btw` | Fungible token | ERC-20 with transfer, approve, transferFrom, mint, burn |
| `nft.btw` | Non-fungible token | Mint and transfer with ownership tracking |
| `escrow.btw` | Multi-step workflow | Deposit → lock → release escrow pattern |

## What Gets Generated

For each `.btw` file, `bitwrap -validate` generates:

1. **Contract** (`src/Name.sol`) — Solidity contract with state, functions, events, access control
2. **Tests** (`test/NameTest.t.sol`) — Foundry tests for each function and guard
3. **Deploy script** (`script/NameGenesis.s.sol`) — Foundry deployment script

The contract includes:
- `contractOwner` with `onlyOwner` modifier for privileged functions (mint, etc.)
- `transferOwnership` and `renounceOwnership` admin functions
- View functions for exported registers (`balanceOf`, `allowance`, etc.)
- Epoch counter and event sequencing for on-chain ordering

## Limitations

- `caller` in guards maps to `msg.sender` but can't be used as an arc index yet
- No array/batch operations (ERC-1155 batch patterns need manual extension)
- Struct types (VestingSchedule) are supported via templates but not yet in DSL
- Generated tests handle common patterns; complex multi-step workflows may need manual test setup
