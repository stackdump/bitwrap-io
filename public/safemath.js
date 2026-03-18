// Safe math for unsigned 256-bit integers using native BigInt
// Matches Go arc/safemath.go exactly

const MAX_U256 = (1n << 256n) - 1n;

export class SafeMathError extends Error {
  constructor(message) { super(message); this.name = 'SafeMathError'; }
}

export const ErrOverflow = () => new SafeMathError('arithmetic overflow');
export const ErrUnderflow = () => new SafeMathError('arithmetic underflow');
export const ErrDivisionByZero = () => new SafeMathError('division by zero');

// Clamp to U256 range [0, 2^256 - 1]
function toU256(v) {
  v = BigInt(v);
  if (v < 0n) throw ErrUnderflow();
  if (v > MAX_U256) throw ErrOverflow();
  return v;
}

// SafeAdd returns a + b, throws on overflow
export function safeAdd(a, b) {
  a = BigInt(a); b = BigInt(b);
  const result = a + b;
  if (result > MAX_U256) throw ErrOverflow();
  return result;
}

// SafeSub returns a - b, throws on underflow
export function safeSub(a, b) {
  a = BigInt(a); b = BigInt(b);
  if (b > a) throw ErrUnderflow();
  return a - b;
}

// SafeMul returns a * b, throws on overflow
export function safeMul(a, b) {
  a = BigInt(a); b = BigInt(b);
  const result = a * b;
  if (result > MAX_U256) throw ErrOverflow();
  return result;
}

// SafeDiv returns a / b, throws on division by zero
export function safeDiv(a, b) {
  a = BigInt(a); b = BigInt(b);
  if (b === 0n) throw ErrDivisionByZero();
  return a / b;
}

// SafeMod returns a % b, throws on division by zero
export function safeMod(a, b) {
  a = BigInt(a); b = BigInt(b);
  if (b === 0n) throw ErrDivisionByZero();
  return a % b;
}

// MulDiv computes (a * b) / c with full precision intermediate result
export function mulDiv(a, b, c) {
  a = BigInt(a); b = BigInt(b); c = BigInt(c);
  if (c === 0n) throw ErrDivisionByZero();
  return (a * b) / c;
}

// ConvertToShares computes shares = (assets * totalShares) / totalAssets
// Standard ERC-4626 conversion with rounding down
export function convertToShares(assets, totalShares, totalAssets) {
  assets = BigInt(assets);
  totalShares = BigInt(totalShares);
  totalAssets = BigInt(totalAssets);
  if (totalAssets === 0n) return assets; // First deposit: 1:1
  return mulDiv(assets, totalShares, totalAssets);
}

// ConvertToAssets computes assets = (shares * totalAssets) / totalShares
// Standard ERC-4626 conversion with rounding down
export function convertToAssets(shares, totalAssets, totalShares) {
  shares = BigInt(shares);
  totalAssets = BigInt(totalAssets);
  totalShares = BigInt(totalShares);
  if (totalShares === 0n) return shares; // No shares: 1:1
  return mulDiv(shares, totalAssets, totalShares);
}

// Min returns the smaller of a and b
export function min(a, b) {
  a = BigInt(a); b = BigInt(b);
  return a < b ? a : b;
}

// Max returns the larger of a and b
export function max(a, b) {
  a = BigInt(a); b = BigInt(b);
  return a > b ? a : b;
}

export { MAX_U256 };
