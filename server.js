/**
 * Bitcoin Script Debugger — local dev server
 * Endpoints:
 *   GET  /api/templates        — predefined script examples
 *   POST /api/execute          — run a script, return full step trace
 *   GET  /api/opcodes          — opcode reference list
 *   GET  /*                    — static files from ./public
 */

import http from 'http';
import fs   from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { executeScript, parseScript, computeHash160, computeSha256, OPCODE_DESCRIPTIONS, OPCODES } from './interpreter.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOST      = process.env.HOST || '127.0.0.1';
const PORT      = parseInt(process.env.PORT || '3009');

// ─── Transaction Parser (server-side) ────────────────────────────────────────

// Build opcode value→name map from the interpreter's OPCODES table
const OPCODE_NAME = {};
for (const [name, code] of Object.entries(OPCODES)) {
  if (!OPCODE_NAME[code]) OPCODE_NAME[code] = name;
}
OPCODE_NAME[0xb1] = 'OP_CHECKLOCKTIMEVERIFY';
OPCODE_NAME[0xb2] = 'OP_CHECKSEQUENCEVERIFY';

function txHexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  return out;
}

function txBytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function txReverseHex(hex) {
  const out = [];
  for (let i = hex.length - 2; i >= 0; i -= 2) out.push(hex.substr(i, 2));
  return out.join('');
}

function txReadLE32(b, o) {
  return ((b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0);
}

function txReadLE64(b, o) {
  const lo = ((b[o]   | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0);
  const hi = ((b[o+4] | (b[o+5]<<8) | (b[o+6]<<16) | (b[o+7]<<24)) >>> 0);
  return hi * 0x100000000 + lo;
}

function txReadVarInt(b, o) {
  const f = b[o];
  if (f < 0xfd) return { value: f, size: 1 };
  if (f === 0xfd) return { value: b[o+1] | (b[o+2]<<8), size: 3 };
  if (f === 0xfe) return { value: txReadLE32(b, o+1), size: 5 };
  return { value: txReadLE32(b, o+1), size: 9 };
}

function txScriptHexToAsm(scriptHex) {
  if (!scriptHex) return '';
  const bytes = txHexToBytes(scriptHex);
  const tokens = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    if (op === 0x00) { tokens.push('OP_0'); i++; }
    else if (op >= 0x01 && op <= 0x4b) {
      tokens.push(txBytesToHex(bytes.slice(i+1, i+1+op)));
      i += 1 + op;
    }
    else if (op === 0x4c) { const n = bytes[i+1]; tokens.push(txBytesToHex(bytes.slice(i+2, i+2+n))); i += 2 + n; }
    else if (op === 0x4d) { const n = bytes[i+1] | (bytes[i+2]<<8); tokens.push(txBytesToHex(bytes.slice(i+3, i+3+n))); i += 3 + n; }
    else if (op === 0x4e) { const n = txReadLE32(bytes, i+1); tokens.push(txBytesToHex(bytes.slice(i+5, i+5+n))); i += 5 + n; }
    else { tokens.push(OPCODE_NAME[op] || `OP_UNKNOWN(0x${op.toString(16).padStart(2,'0')})`); i++; }
  }
  return tokens.join(' ');
}

function txDetectOutputType(scriptHex) {
  if (!scriptHex) return 'EMPTY';
  const b = txHexToBytes(scriptHex);
  const n = b.length;
  if (b[0] === 0x6a) return 'OP_RETURN';
  if (n===25 && b[0]===0x76 && b[1]===0xa9 && b[2]===0x14 && b[23]===0x88 && b[24]===0xac) return 'P2PKH';
  if (n===23 && b[0]===0xa9 && b[1]===0x14 && b[22]===0x87) return 'P2SH';
  if (n===67 && b[0]===0x41 && b[66]===0xac) return 'P2PK';
  if (n===35 && b[0]===0x21 && b[34]===0xac) return 'P2PK';
  if (n===22 && b[0]===0x00 && b[1]===0x14) return 'P2WPKH';
  if (n===34 && b[0]===0x00 && b[1]===0x20) return 'P2WSH';
  if (n===34 && b[0]===0x51 && b[1]===0x20) return 'P2TR';
  if (b[n-1]===0xae && b[0]>=0x51 && b[0]<=0x60) { const m=b[0]-0x50, k=b[n-2]-0x50; return `P2MS ${m}-of-${k}`; }
  return 'Unknown';
}

function classifyInput(scriptSigHex, scriptSigAsm, witness) {
  // SegWit P2WPKH: empty scriptSig + 2-item witness [sig, 33-byte-pubkey]
  if (!scriptSigHex && witness.length === 2 && witness[1].length === 66) {
    let lockHash;
    try { lockHash = computeHash160(witness[1]); } catch { lockHash = null; }
    return {
      inputType: 'P2WPKH (SegWit)',
      suggestedUnlocking: witness.join(' '),
      suggestedLocking: lockHash
        ? `OP_DUP OP_HASH160 ${lockHash} OP_EQUALVERIFY OP_CHECKSIG`
        : '',
      note: lockHash
        ? 'SegWit P2WPKH: sig+pubkey from witness; locking script auto-reconstructed from pubkey'
        : 'SegWit P2WPKH input — paste the scriptPubKey from the previous output',
    };
  }

  // SegWit P2WSH: empty scriptSig + witness ending in a script
  if (!scriptSigHex && witness.length >= 2) {
    const witnessScript = witness[witness.length - 1];
    const witnessAsm = txScriptHexToAsm(witnessScript);
    return {
      inputType: 'P2WSH (SegWit)',
      suggestedUnlocking: witness.slice(0, -1).join(' '),
      suggestedLocking: witnessAsm,
      note: 'SegWit P2WSH: witness items as unlocking; last witness item (redeemScript) as locking',
    };
  }

  if (!scriptSigHex) {
    return {
      inputType: 'Coinbase / Unknown',
      suggestedUnlocking: witness.join(' '),
      suggestedLocking: '',
      note: 'Coinbase or unknown input type — no script to debug',
    };
  }

  const parts = scriptSigAsm.trim().split(/\s+/).filter(Boolean);

  // P2PKH: exactly 2 tokens — DER sig + 33 or 65-byte pubkey
  if (
    parts.length === 2 &&
    /^30[0-9a-f]{2}/.test(parts[0]) &&
    (parts[1].length === 66 || parts[1].length === 130) &&
    (parts[1].startsWith('02') || parts[1].startsWith('03') || parts[1].startsWith('04'))
  ) {
    let lockHash;
    try { lockHash = computeHash160(parts[1]); } catch { lockHash = null; }
    return {
      inputType: 'P2PKH',
      suggestedUnlocking: scriptSigAsm,
      suggestedLocking: lockHash
        ? `OP_DUP OP_HASH160 ${lockHash} OP_EQUALVERIFY OP_CHECKSIG`
        : '',
      note: lockHash
        ? 'P2PKH input: sig+pubkey from scriptSig; locking script auto-reconstructed'
        : 'P2PKH input — paste the scriptPubKey from the previous output',
    };
  }

  // P2PK: single DER sig
  if (parts.length === 1 && /^30[0-9a-f]{2}/.test(parts[0])) {
    return {
      inputType: 'P2PK',
      suggestedUnlocking: scriptSigAsm,
      suggestedLocking: '',
      note: 'P2PK input: signature extracted; paste the scriptPubKey (<pubkey> OP_CHECKSIG) from the previous output',
    };
  }

  // P2MS: OP_0 <sig1> [<sig2>...]
  if (parts[0] === 'OP_0' && parts.length >= 2) {
    return {
      inputType: 'P2MS / P2SH',
      suggestedUnlocking: scriptSigAsm,
      suggestedLocking: '',
      note: 'Multisig or P2SH input: unlocking script extracted; paste the locking script from the previous output',
    };
  }

  return {
    inputType: 'Unknown',
    suggestedUnlocking: scriptSigAsm,
    suggestedLocking: '',
    note: 'Could not identify input type — paste the locking script (scriptPubKey) from the previous output',
  };
}

function parseTxForDebug(hex) {
  hex = hex.replace(/\s/g, '').toLowerCase();
  if (hex.length < 20)  throw new Error('Input too short — paste a full raw transaction hex');
  if (hex.length % 2)   throw new Error('Odd number of hex characters');
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error('Invalid characters — only hex digits allowed');

  const bytes = txHexToBytes(hex);
  let o = 0;

  const version = txReadLE32(bytes, o); o += 4;

  let isSegwit = false;
  if (bytes[o] === 0x00 && bytes[o+1] === 0x01) { isSegwit = true; o += 2; }

  const icVI = txReadVarInt(bytes, o); o += icVI.size;
  const inputCount = icVI.value;
  if (inputCount > 500) throw new Error('Unusually high input count — check your hex');

  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxid  = txReverseHex(txBytesToHex(bytes.slice(o, o+32))); o += 32;
    const prevIndex = txReadLE32(bytes, o); o += 4;
    const slVI = txReadVarInt(bytes, o); o += slVI.size;
    const scriptSigHex = txBytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;
    const seq = txReadLE32(bytes, o).toString(16).padStart(8,'0'); o += 4;
    inputs.push({ index: i, prevTxid, prevIndex, scriptSigHex, scriptSigAsm: txScriptHexToAsm(scriptSigHex), sequence: seq, witness: [] });
  }

  const ocVI = txReadVarInt(bytes, o); o += ocVI.size;
  const outputCount = ocVI.value;
  if (outputCount > 5000) throw new Error('Unusually high output count — check your hex');

  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const sats = txReadLE64(bytes, o); o += 8;
    const slVI = txReadVarInt(bytes, o); o += slVI.size;
    const scriptPubKeyHex = txBytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;
    const scriptPubKeyAsm = txScriptHexToAsm(scriptPubKeyHex);
    outputs.push({ index: i, sats, btc: (sats/1e8).toFixed(8), scriptPubKeyHex, scriptPubKeyAsm, outputType: txDetectOutputType(scriptPubKeyHex) });
  }

  if (isSegwit) {
    for (let i = 0; i < inputCount; i++) {
      const wcVI = txReadVarInt(bytes, o); o += wcVI.size;
      const items = [];
      for (let j = 0; j < wcVI.value; j++) {
        const ilVI = txReadVarInt(bytes, o); o += ilVI.size;
        items.push(txBytesToHex(bytes.slice(o, o+ilVI.value))); o += ilVI.value;
      }
      inputs[i].witness = items;
    }
  }

  const locktime = txReadLE32(bytes, o);

  // Classify each input
  for (const inp of inputs) {
    Object.assign(inp, classifyInput(inp.scriptSigHex, inp.scriptSigAsm, inp.witness));
  }

  return { version, isSegwit, inputCount, outputCount, inputs, outputs, locktime, byteSize: hex.length/2 };
}

// ─── Execute result shaper ────────────────────────────────────────────────────
// The raw interpreter output uses different field names than the frontend expects.
// This maps: stackAfter→stack, altAfter→altStack, tokenRaw→token, index→tokenIndex
// and builds the tokens[] array (with boundary marker) for the token row.

function shapeExecuteResult(raw, unlocking, locking) {
  const unlockTokens = parseScript(unlocking);
  const lockTokens   = parseScript(locking);
  const boundary     = unlockTokens.length;

  // Build the token list the frontend renders in the token row
  const tokens = [];
  for (const t of unlockTokens) {
    tokens.push({ type: t.type, value: t.raw, desc: OPCODE_DESCRIPTIONS[t.value.toUpperCase()] || '' });
  }
  tokens.push({ type: 'boundary', value: '│' });
  for (const t of lockTokens) {
    tokens.push({ type: t.type, value: t.raw, desc: OPCODE_DESCRIPTIONS[t.value.toUpperCase()] || '' });
  }

  // Map each step to the shape main.js expects
  const steps = raw.steps.map(s => ({
    ...s,
    stack:      s.stackAfter || [],
    altStack:   s.altAfter   || [],
    token:      s.tokenRaw   ?? '',
    // s.index is position in allTokens (no boundary gap); shift lock tokens by +1
    tokenIndex: s.index < 0
                  ? -1
                  : s.index < boundary
                    ? s.index
                    : s.index + 1,  // +1 accounts for the boundary marker in tokens[]
  }));

  return {
    ...raw,
    tokens,
    steps,
    reason: raw.error || '',
  };
}

// ─── Script Templates ─────────────────────────────────────────────────────────

// Realistic but fake test data
const FAKE_PUBKEY  = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const FAKE_PUBKEY2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const FAKE_PUBKEY3 = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const FAKE_SIG     = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802202222222222222222222222222222222222222222222222222222222222222222220101';
const FAKE_SIG2    = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802203333333333333333333333333333333333333333333333333333333333333333330101';

const HELLO_HEX    = '68656c6c6f'; // "hello" in hex
const HELLO_SHA256 = computeSha256(HELLO_HEX);

let PUBKEY_HASH160;
try { PUBKEY_HASH160 = computeHash160(FAKE_PUBKEY); }
catch { PUBKEY_HASH160 = '89abcdefabbaabbaabbaabbaabbaabbaabbaabba'; }

const TEMPLATES = [
  {
    id: 'p2pkh',
    name: 'P2PKH — Pay to Public Key Hash',
    type: 'Legacy',
    description: 'The most common Bitcoin script. Locks funds to a hash of a public key. Spending requires the public key and a valid signature.',
    unlocking: `${FAKE_SIG} ${FAKE_PUBKEY}`,
    locking: `OP_DUP OP_HASH160 ${PUBKEY_HASH160} OP_EQUALVERIFY OP_CHECKSIG`,
    note: 'ScriptSig = <sig> <pubkey>  |  ScriptPubKey = OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG',
  },
  {
    id: 'p2pk',
    name: 'P2PK — Pay to Public Key',
    type: 'Legacy',
    description: 'Older, simpler format used in early Bitcoin and coinbase transactions. Locks directly to a public key.',
    unlocking: `${FAKE_SIG}`,
    locking: `${FAKE_PUBKEY} OP_CHECKSIG`,
    note: 'ScriptSig = <sig>  |  ScriptPubKey = <pubkey> OP_CHECKSIG',
  },
  {
    id: 'p2ms',
    name: 'P2MS — 2-of-3 Multisig',
    type: 'Legacy',
    description: 'Requires signatures from any 2 out of 3 public keys. Note: Bitcoin has an off-by-one bug requiring a dummy OP_0.',
    unlocking: `OP_0 ${FAKE_SIG} ${FAKE_SIG2}`,
    locking: `OP_2 ${FAKE_PUBKEY} ${FAKE_PUBKEY2} ${FAKE_PUBKEY3} OP_3 OP_CHECKMULTISIG`,
    note: 'ScriptSig = OP_0 <sig1> <sig2>  |  ScriptPubKey = OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG',
  },
  {
    id: 'p2wpkh',
    name: 'P2WPKH — Pay to Witness Public Key Hash (SegWit)',
    type: 'SegWit',
    description: 'SegWit version of P2PKH. The ScriptPubKey is simply OP_0 <20-byte-hash>. The witness field carries the sig and pubkey. Shown here as the implicit equivalent script.',
    unlocking: `${FAKE_SIG} ${FAKE_PUBKEY}`,
    locking: `OP_DUP OP_HASH160 ${PUBKEY_HASH160} OP_EQUALVERIFY OP_CHECKSIG`,
    note: 'Real ScriptPubKey: OP_0 <20-byte-hash>  |  Witness: [<sig>, <pubkey>]  |  This shows the equivalent implicit validation logic.',
  },
  {
    id: 'p2wsh',
    name: 'P2WSH — Pay to Witness Script Hash (SegWit)',
    type: 'SegWit',
    description: 'SegWit version of P2SH. Uses a 32-byte SHA256 hash. Shown here as an equivalent 2-of-2 multisig validation.',
    unlocking: `OP_0 ${FAKE_SIG} ${FAKE_SIG2}`,
    locking: `OP_2 ${FAKE_PUBKEY} ${FAKE_PUBKEY2} OP_2 OP_CHECKMULTISIG`,
    note: 'Real ScriptPubKey: OP_0 <32-byte-SHA256-hash>  |  Witness: [<items...>, <witnessScript>]  |  This shows the equivalent implicit validation.',
  },
  {
    id: 'hash_puzzle',
    name: 'Hash Puzzle (SHA-256)',
    type: 'Puzzle',
    description: 'Anyone who can provide the preimage that hashes to the target value can spend the output. "hello" is the preimage here.',
    unlocking: HELLO_HEX,
    locking: `OP_SHA256 ${HELLO_SHA256} OP_EQUAL`,
    note: `Preimage: "hello" (hex: ${HELLO_HEX})  |  SHA256("hello") = ${HELLO_SHA256.slice(0,16)}…`,
  },
  {
    id: 'math_puzzle',
    name: 'Math Puzzle (Add)',
    type: 'Puzzle',
    description: 'Spend by providing two numbers that sum to 8. Demonstrates arithmetic opcodes.',
    unlocking: '3 5',
    locking: 'OP_ADD 8 OP_EQUAL',
    note: 'Unlocking: 3 5  |  Locking: OP_ADD 8 OP_EQUAL  |  3 + 5 = 8 ✓',
  },
  {
    id: 'hash_collision',
    name: 'Hash Collision Puzzle',
    type: 'Puzzle',
    description: 'Spend by providing two DIFFERENT values that produce the same SHA1 hash — a Bitcoin bounty for SHA1 collision. (Simulated with matching hex here.)',
    unlocking: `${HELLO_HEX} ${HELLO_HEX}`,
    locking: `OP_2DUP OP_EQUAL OP_NOT OP_VERIFY OP_SHA1 OP_SWAP OP_SHA1 OP_EQUAL`,
    note: 'In production: provide two different byte strings with the same SHA1 hash. Here both are identical so OP_NOT OP_VERIFY will fail — intentional for demonstration.',
  },
  {
    id: 'op_return',
    name: 'OP_RETURN (Data Carrier)',
    type: 'Legacy',
    description: 'Makes an output unspendable. Used to embed arbitrary data in the blockchain (e.g. OP_RETURN metadata).',
    unlocking: '',
    locking: `OP_RETURN ${HELLO_HEX}`,
    note: 'ScriptPubKey: OP_RETURN <data>  |  No valid unlocking script exists — output is provably unspendable.',
  },
  {
    id: 'timelock',
    name: 'Conditional / IF-ELSE',
    type: 'Advanced',
    description: 'Demonstrates OP_IF / OP_ELSE / OP_ENDIF flow control.',
    unlocking: '01',
    locking: 'OP_IF 5 3 OP_ADD 8 OP_EQUAL OP_ELSE OP_0 OP_ENDIF',
    note: 'If top is 1: executes 5 + 3 == 8 path. If top is 0: pushes OP_0 (fails).',
  },
];

// ─── MIME types ───────────────────────────────────────────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json',
  '.ico':  'image/x-icon',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function json(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', chunk => { buf += chunk; if (buf.length > 1e6) reject(new Error('body too large')); });
    req.on('end',  () => resolve(buf));
    req.on('error', reject);
  });
}

function log(req, status) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`[${ts}] ${req.method.padEnd(4)} ${String(status).padStart(3)}  ${req.url}`);
}

// ─── Request handler ──────────────────────────────────────────────────────────

async function handleRequest(req, res) {
  // Top-level safety net — prevents unhandled rejections from crashing the process
  try {
  const url = new URL(req.url, `http://${HOST}`);

  // CORS pre-flight
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end(); return;
  }

  // ── API routes ─────────────────────────────────────────────────────────────

  if (url.pathname === '/api/templates' && req.method === 'GET') {
    log(req, 200);
    return json(res, 200, TEMPLATES);
  }

  if (url.pathname === '/api/opcodes' && req.method === 'GET') {
    log(req, 200);
    const list = Object.entries(OPCODE_DESCRIPTIONS).map(([op, desc]) => ({ op, desc }));
    return json(res, 200, list);
  }

  if (url.pathname === '/api/fetch-tx' && req.method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { log(req, 400); return json(res, 400, { error: 'Invalid JSON body' }); }

    const txid    = String(body.txid    ?? '').trim();
    const network = String(body.network ?? 'mainnet').trim();

    if (!txid || !/^[0-9a-fA-F]{64}$/.test(txid)) {
      log(req, 400); return json(res, 400, { error: 'Invalid txid — must be 64 hex characters' });
    }

    const base = network === 'testnet'
      ? 'https://blockstream.info/testnet/api'
      : 'https://blockstream.info/api';

    try {
      const resp = await fetch(`${base}/tx/${txid}/hex`, { signal: AbortSignal.timeout(10000) });
      if (resp.status === 404) {
        log(req, 404);
        return json(res, 404, { error: `Transaction not found on ${network}: ${txid}` });
      }
      if (!resp.ok) {
        log(req, 502);
        return json(res, 502, { error: `Blockstream API error: HTTP ${resp.status}` });
      }
      const hex = (await resp.text()).trim();
      log(req, 200);
      return json(res, 200, { hex });
    } catch (e) {
      log(req, 502);
      return json(res, 502, { error: `Failed to fetch transaction: ${e.message}` });
    }
  }

  if (url.pathname === '/api/parse-tx' && req.method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { log(req, 400); return json(res, 400, { error: 'Invalid JSON body' }); }

    // Strip btcdeb-style prefixes and all whitespace
    let hex     = String(body.hex     ?? '').replace(/^.*--tx=/i,   '').replace(/\s/g, '');
    let txinHex = String(body.txinHex ?? '').replace(/^.*--txin=/i, '').replace(/\s/g, '');

    if (!hex) { log(req, 400); return json(res, 400, { error: 'hex is required' }); }

    try {
      const result = parseTxForDebug(hex);

      // If a previous tx was provided, use its outputs as locking scripts
      if (txinHex) {
        const prevTx = parseTxForDebug(txinHex);
        for (const inp of result.inputs) {
          const prevOut = prevTx.outputs[inp.prevIndex];
          if (prevOut) {
            inp.suggestedLocking = prevOut.scriptPubKeyAsm;
            inp.inputType        = inp.inputType !== 'Unknown' ? inp.inputType : prevOut.outputType;
            inp.note             = `Locking script pulled from txin output #${inp.prevIndex} (${prevOut.outputType}, ${prevOut.btc} BTC)`;
          }
        }
      }

      log(req, 200);
      return json(res, 200, result);
    } catch (e) {
      log(req, 400);
      return json(res, 400, { error: e.message });
    }
  }

  if (url.pathname === '/api/execute' && req.method === 'POST') {
    let body;
    try { body = JSON.parse(await readBody(req)); }
    catch { log(req, 400); return json(res, 400, { error: 'Invalid JSON body' }); }

    const unlocking      = String(body.unlocking      ?? '').trim();
    const locking        = String(body.locking        ?? '').trim();
    const checksigResult = String(body.checksigResult ?? 'valid');

    if (!locking) { log(req, 400); return json(res, 400, { error: 'locking script is required' }); }

    try {
      const raw    = executeScript(unlocking, locking, { checksigResult });
      const result = shapeExecuteResult(raw, unlocking, locking);
      log(req, 200);
      return json(res, 200, result);
    } catch (e) {
      log(req, 500);
      return json(res, 500, { error: e.message });
    }
  }

  // ── Static file serving ───────────────────────────────────────────────────

  let filePath = path.join(__dirname, 'public', url.pathname === '/' ? 'index.html' : url.pathname);
  filePath = path.normalize(filePath);

  // Path traversal guard
  if (!filePath.startsWith(path.join(__dirname, 'public'))) {
    log(req, 403); res.writeHead(403); res.end('Forbidden'); return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fall back to index.html for SPA-style navigation
      fs.readFile(path.join(__dirname, 'public', 'index.html'), (err2, html) => {
        if (err2) { log(req, 404); res.writeHead(404); res.end('Not Found'); return; }
        log(req, 200);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(html);
      });
      return;
    }
    const ext  = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    log(req, 200);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });

  } catch (e) {
    // Catch synchronous errors (e.g. malformed URL) before they crash the process
    if (!res.headersSent) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
    console.error('[ERROR]', e.message);
  }
}

// ─── Start ─────────────────────────────────────────────────────────────────

const server = http.createServer(handleRequest);

server.on('error', err => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n  ✗  Port ${PORT} is already in use. Kill the existing process first:\n     pkill -f "node server.js"\n`);
  } else {
    console.error('\n  ✗  Server error:', err.message, '\n');
  }
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  console.log('');
  console.log('  ₿  Bitcoin Script Debugger');
  console.log('  ─────────────────────────────────────────');
  console.log(`  URL   →  http://${HOST}:${PORT}`);
  console.log(`  API   →  http://${HOST}:${PORT}/api/templates`);
  console.log('');
  console.log('  Supported script types:');
  console.log('    Legacy  — P2PK, P2PKH, P2MS, P2SH pattern, OP_RETURN');
  console.log('    SegWit  — P2WPKH (equivalent), P2WSH (equivalent)');
  console.log('    Puzzles — Hash Puzzle, Math Puzzle, Hash Collision');
  console.log('    Control — IF/ELSE/ENDIF, arithmetic');
  console.log('');
});
