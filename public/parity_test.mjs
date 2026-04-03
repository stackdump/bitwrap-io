// Petri net execution parity test — must match Go TestRuntimeSolidityParity.
// Run: node --experimental-vm-modules public/parity_test.mjs

import { Model } from './model.js';
import { State } from './state.js';

let failures = 0;

function assert(condition, msg) {
  if (!condition) {
    console.error('FAIL:', msg);
    failures++;
  }
}

// ============ ERC20: mint → transfer → burn ============
function testERC20() {
  const m = new Model('ERC20');
  m.addPlace({ id: 'BALANCES', schema: 'map[address]uint256', exported: true });
  m.addPlace({ id: 'TOTAL_SUPPLY', schema: 'uint256', initial: 0 });
  m.addTransition({ id: 'mint' });
  m.addTransition({ id: 'transfer' });
  m.addTransition({ id: 'burn' });

  // mint arcs: mint -|amount|> BALANCES[to], mint -|amount|> TOTAL_SUPPLY
  m.addArc({ source: 'mint', target: 'BALANCES', keys: ['to'], value: 'amount' });
  m.addArc({ source: 'mint', target: 'TOTAL_SUPPLY', value: 'amount' });

  // transfer arcs: BALANCES[from] -|amount|> transfer, transfer -|amount|> BALANCES[to]
  m.addArc({ source: 'BALANCES', target: 'transfer', keys: ['from'], value: 'amount' });
  m.addArc({ source: 'transfer', target: 'BALANCES', keys: ['to'], value: 'amount' });

  // burn arcs: BALANCES[from] -|amount|> burn, TOTAL_SUPPLY -|amount|> burn
  m.addArc({ source: 'BALANCES', target: 'burn', keys: ['from'], value: 'amount' });
  m.addArc({ source: 'TOTAL_SUPPLY', target: 'burn', value: 'amount' });

  const s = new State(m);

  // Mint 1000 to Alice
  s.executeWithBindings('mint', { to: 'Alice', amount: 1000 });
  assert(s.getDataMap('BALANCES')['Alice'] === 1000, `ERC20 mint: BALANCES[Alice]=${s.getDataMap('BALANCES')['Alice']}, want 1000`);
  assert(s.getTokens('TOTAL_SUPPLY') === 1000, `ERC20 mint: TOTAL_SUPPLY=${s.getTokens('TOTAL_SUPPLY')}, want 1000`);

  // Transfer 300 from Alice to Bob
  s.executeWithBindings('transfer', { from: 'Alice', to: 'Bob', amount: 300 });
  assert(s.getDataMap('BALANCES')['Alice'] === 700, `ERC20 transfer: BALANCES[Alice]=${s.getDataMap('BALANCES')['Alice']}, want 700`);
  assert(s.getDataMap('BALANCES')['Bob'] === 300, `ERC20 transfer: BALANCES[Bob]=${s.getDataMap('BALANCES')['Bob']}, want 300`);
  assert(s.getTokens('TOTAL_SUPPLY') === 1000, `ERC20 transfer: TOTAL_SUPPLY=${s.getTokens('TOTAL_SUPPLY')}, want 1000`);

  // Burn 100 from Alice
  s.executeWithBindings('burn', { from: 'Alice', amount: 100 });
  assert(s.getDataMap('BALANCES')['Alice'] === 600, `ERC20 burn: BALANCES[Alice]=${s.getDataMap('BALANCES')['Alice']}, want 600`);
  assert(s.getTokens('TOTAL_SUPPLY') === 900, `ERC20 burn: TOTAL_SUPPLY=${s.getTokens('TOTAL_SUPPLY')}, want 900`);

  console.log('ERC20 parity: OK');
}

// ============ Counter: increment → decrement ============
function testCounter() {
  const m = new Model('Counter');
  m.addPlace({ id: 'COUNT', schema: 'uint256', initial: 0 });
  m.addTransition({ id: 'increment' });
  m.addTransition({ id: 'decrement' });

  m.addArc({ source: 'increment', target: 'COUNT', value: 'amount' });
  m.addArc({ source: 'COUNT', target: 'decrement', value: 'amount' });

  const s = new State(m);

  // Increment by 5
  s.executeWithBindings('increment', { amount: 5 });
  assert(s.getTokens('COUNT') === 5, `Counter increment: COUNT=${s.getTokens('COUNT')}, want 5`);

  // Decrement by 2
  s.executeWithBindings('decrement', { amount: 2 });
  assert(s.getTokens('COUNT') === 3, `Counter decrement: COUNT=${s.getTokens('COUNT')}, want 3`);

  console.log('Counter parity: OK');
}

// ============ Nested maps: approve + transferFrom ============
function testAllowances() {
  const m = new Model('ERC20Approve');
  m.addPlace({ id: 'BALANCES', schema: 'map[address]uint256' });
  m.addPlace({ id: 'ALLOWANCES', schema: 'map[address]map[address]uint256' });
  m.addTransition({ id: 'mint' });
  m.addTransition({ id: 'approve' });
  m.addTransition({ id: 'transferFrom' });

  m.addArc({ source: 'mint', target: 'BALANCES', keys: ['to'], value: 'amount' });
  m.addArc({ source: 'approve', target: 'ALLOWANCES', keys: ['owner', 'spender'], value: 'amount' });
  m.addArc({ source: 'BALANCES', target: 'transferFrom', keys: ['from'], value: 'amount' });
  m.addArc({ source: 'ALLOWANCES', target: 'transferFrom', keys: ['from', 'spender'], value: 'amount' });
  m.addArc({ source: 'transferFrom', target: 'BALANCES', keys: ['to'], value: 'amount' });

  const s = new State(m);

  // Mint 1000 to Alice
  s.executeWithBindings('mint', { to: 'Alice', amount: 1000 });
  assert(s.getDataMap('BALANCES')['Alice'] === 1000, 'mint balance');

  // Alice approves Bob for 500
  s.executeWithBindings('approve', { owner: 'Alice', spender: 'Bob', amount: 500 });
  const allowances = s.getDataMap('ALLOWANCES');
  assert(allowances['Alice'] && allowances['Alice']['Bob'] === 500, `approve: ALLOWANCES[Alice][Bob]=${allowances['Alice']?.['Bob']}, want 500`);

  // Bob transfers 200 from Alice to Charlie
  s.executeWithBindings('transferFrom', { from: 'Alice', spender: 'Bob', to: 'Charlie', amount: 200 });
  assert(s.getDataMap('BALANCES')['Alice'] === 800, `transferFrom: BALANCES[Alice]=${s.getDataMap('BALANCES')['Alice']}, want 800`);
  assert(s.getDataMap('BALANCES')['Charlie'] === 200, `transferFrom: BALANCES[Charlie]=${s.getDataMap('BALANCES')['Charlie']}, want 200`);
  assert(s.getDataMap('ALLOWANCES')['Alice']['Bob'] === 300, `transferFrom: ALLOWANCES[Alice][Bob]=${s.getDataMap('ALLOWANCES')['Alice']['Bob']}, want 300`);

  console.log('Allowances parity: OK');
}

testERC20();
testCounter();
testAllowances();

if (failures > 0) {
  console.error(`\n${failures} parity failures`);
  process.exit(1);
} else {
  console.log('\nPetri net execution parity: all tests passed');
}
