# Bitcoin Script Debugger — Teaching Guide

A complete walkthrough of how this project works: the concepts, the architecture, and every file explained.

---

## What Is Bitcoin Script?

Bitcoin doesn't use a typical programming language to control who can spend funds. Instead, every transaction output carries a small program called a **script**. To spend that output, the spender must provide inputs that, when combined with the script, execute successfully.

Bitcoin Script is a **stack-based language** — there are no variables, no loops, no functions. Instructions push data onto a stack or pop items off it and operate on them. At the end of execution, if the top of the stack is a non-zero value and only one item remains, the script is valid and the funds can be spent.

### The Two Halves of Every Script Execution

Every spend in Bitcoin combines two scripts:

| Script | Also Called | Lives In | Written By |
|---|---|---|---|
| Locking Script | ScriptPubKey | Previous transaction output | Recipient |
| Unlocking Script | ScriptSig / Witness | Current transaction input | Spender |

Execution runs the **unlocking script first**, then the **locking script**, sharing the same stack. If the final stack has a single truthy value, the spend is valid.

```
[Unlocking Script]  →  [Locking Script]  →  Final Stack
 <sig> <pubkey>         OP_DUP OP_HASH160     [1]  ✅
                        <hash>
                        OP_EQUALVERIFY
                        OP_CHECKSIG
```

---

## Script Types This Debugger Supports

### P2PK — Pay to Public Key (Legacy)
The oldest format. Locks directly to a public key.
```
Unlocking:  <sig>
Locking:    <pubkey> OP_CHECKSIG
```

### P2PKH — Pay to Public Key Hash (Legacy)
Most common legacy format. Locks to a hash of the public key — the hash is smaller and the actual key is only revealed at spend time.
```
Unlocking:  <sig> <pubkey>
Locking:    OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
```
Step by step:
1. `<sig>` → pushed onto stack
2. `<pubkey>` → pushed onto stack
3. `OP_DUP` → duplicates pubkey (stack now has sig, pubkey, pubkey)
4. `OP_HASH160` → hashes the top pubkey with SHA256 then RIPEMD160
5. `<hash>` → pushes the expected hash
6. `OP_EQUALVERIFY` → checks both hashes match (fails if not)
7. `OP_CHECKSIG` → verifies the signature against the pubkey

### P2MS — Pay to Multisig (Legacy)
Requires M signatures out of N public keys (e.g. 2-of-3).
```
Unlocking:  OP_0 <sig1> <sig2>
Locking:    OP_2 <pk1> <pk2> <pk3> OP_3 OP_CHECKMULTISIG
```
The `OP_0` at the start is required due to a known off-by-one bug in Bitcoin Core that was never fixed.

### P2WPKH — Pay to Witness Public Key Hash (SegWit v0)
The SegWit upgrade (2017) moved the unlocking data into a separate **witness** field, outside the transaction body. The locking script is just `OP_0 <20-byte-hash>`. The validator implicitly runs the equivalent P2PKH logic using the witness items.
```
ScriptPubKey:  OP_0 <hash160(pubkey)>
Witness:       [<sig>, <pubkey>]
```
This debugger shows the **equivalent P2PKH execution** since the implicit validation is identical.

### P2WSH — Pay to Witness Script Hash (SegWit v0)
Like P2WPKH but for arbitrary scripts (e.g. multisig). The last witness item is the **witness script** (the actual locking logic). The validator hashes it and checks against the 32-byte SHA256 in the ScriptPubKey.
```
ScriptPubKey:  OP_0 <sha256(witnessScript)>
Witness:       [<item1>, ..., <witnessScript>]
```

### Hash Puzzle
Anyone who knows the preimage of a hash can spend the output.
```
Unlocking:  <preimage>
Locking:    OP_SHA256 <expected_hash> OP_EQUAL
```
Used in Hash Time Locked Contracts (HTLCs) and Lightning Network payment channels.

### Math Puzzle
Arithmetic-based script — rarely used in production but useful for teaching.
```
Unlocking:  3 5
Locking:    OP_ADD 8 OP_EQUAL
```

### OP_RETURN
Marks an output as permanently unspendable. Used to embed arbitrary data in the blockchain (timestamps, NFT metadata, etc.).
```
Locking:    OP_RETURN <data>
```

---

## Project Architecture

```
script-debugger/
│
├── interpreter.js          ← Core engine: tokenizer + stack machine
│
├── api/                    ← Vercel serverless functions (production)
│   ├── templates.js        ← GET  /api/templates
│   ├── opcodes.js          ← GET  /api/opcodes
│   ├── execute.js          ← POST /api/execute
│   ├── parse-tx.js         ← POST /api/parse-tx
│   └── fetch-tx.js         ← POST /api/fetch-tx
│
├── public/                 ← Static frontend (served as-is)
│   ├── index.html          ← Layout and HTML structure
│   ├── style.css           ← Glassmorphism dark theme
│   ├── main.js             ← UI logic, step navigation, rendering
│   └── parser.js           ← Client-side raw transaction parser
│
├── server.js               ← Local dev server (wraps same logic as api/)
├── vercel.json             ← Vercel config: public/ as static root
└── package.json
```

---

## File-by-File Breakdown

---

### `interpreter.js` — The Core Engine

This is the most important file. Everything else just feeds data into it and displays the results.

#### `parseScript(scriptStr)`
Tokenizes a raw script string into typed tokens:
```
"OP_DUP OP_HASH160 ab12cd..." 
  → [
      { type: 'opcode', raw: 'OP_DUP',      value: 'OP_DUP' },
      { type: 'opcode', raw: 'OP_HASH160',  value: 'OP_HASH160' },
      { type: 'data',   raw: 'ab12cd...',   value: 'ab12cd...' }
    ]
```
Token types:
- `opcode` — known Bitcoin opcode (OP_DUP, OP_HASH160, etc.)
- `data` — hex bytes (signature, pubkey, hash, etc.)
- `integer` — a raw number (3, 5, -1)
- `label` — placeholder like `<sig>` or `<pubkey>`

#### `executeScript(unlockingStr, lockingStr, options)`
The stack machine. Runs every token in order and records a step for each one.

**Stack truthiness rules (Bitcoin consensus):**
- Empty byte array → false
- All-zero bytes → false
- Negative zero (0x80) → false
- Everything else → true

**IF/ELSE handling:**
The interpreter maintains an `ifStack` — a list of frames tracking whether we're in an executing or skipped branch. Every opcode checks this before running.

**Return value:**
```javascript
{
  valid: true,               // whether script succeeded
  error: null,               // error message if failed
  steps: [...],              // array of step objects (see below)
  finalStack: ['01'],        // stack state at end
  tokenCount: 7
}
```

**Each step object:**
```javascript
{
  index: 2,                         // position in token array
  tokenRaw: 'OP_HASH160',           // raw token string
  tokenType: 'opcode',
  description: 'RIPEMD160(SHA256(top)) → [ab12...]',
  stackBefore: ['<sig>', '<pubkey>'],
  stackAfter:  ['<sig>', '<pubkey>', '<pubkey>', 'ab12...'],
  altBefore: [],
  altAfter: [],
  status: 'ok',              // 'initial'|'push'|'ok'|'success'|'warning'|'error'|'skipped'
  boundary: 2,               // index where locking script starts
  isBoundary: false
}
```

#### Crypto helpers
- `hash160(val)` → SHA256 then RIPEMD160 (used in P2PKH)
- `hash256(val)` → double-SHA256 (used in OP_HASH256)
- `computeHash160(hexPubkey)` → exported for use in template generation and tx parsing

#### `OPCODES` map
Maps opcode names to their byte values:
```javascript
{ OP_DUP: 0x76, OP_HASH160: 0xa9, OP_CHECKSIG: 0xac, ... }
```

#### `OPCODE_DESCRIPTIONS` map
Human-readable description for every opcode — used in the opcode reference panel and in step descriptions.

---

### `api/execute.js` — Script Execution Endpoint

`POST /api/execute`

Receives `{ unlocking, locking, checksigResult }`, calls `executeScript`, then **reshapes the result** to match what the frontend expects:

```javascript
function shapeExecuteResult(raw, unlocking, locking) {
  // 1. Build tokens[] array with a boundary marker for the token row display
  // 2. Map step.stackAfter  → step.stack
  //    Map step.altAfter    → step.altStack
  //    Map step.tokenRaw    → step.token
  //    Map step.index       → step.tokenIndex  (+1 shift for boundary marker)
  // 3. Map raw.error        → result.reason
}
```

Why the reshape? The interpreter returns internal field names (`stackAfter`, `tokenRaw`, etc.). The frontend was written expecting simpler names (`stack`, `token`). The shaping layer bridges them without changing either side.

---

### `api/parse-tx.js` — Raw Transaction Decoder

`POST /api/parse-tx` — accepts `{ hex, txinHex }`

Decodes the binary structure of a Bitcoin transaction:

**Transaction binary layout (legacy):**
```
[version: 4 bytes LE]
[input count: varint]
  for each input:
    [prevTxid: 32 bytes, reversed]
    [prevIndex: 4 bytes LE]
    [scriptSig length: varint]
    [scriptSig: N bytes]
    [sequence: 4 bytes]
[output count: varint]
  for each output:
    [value: 8 bytes LE]
    [scriptPubKey length: varint]
    [scriptPubKey: N bytes]
[locktime: 4 bytes LE]
```

**SegWit detection:** if bytes[4]=0x00 and bytes[5]=0x01, the transaction has a witness. After all outputs, witness items are read for each input.

**`classifyInput(scriptSigHex, scriptSigAsm, witness)`**
Identifies what kind of input this is and auto-reconstructs the locking script where possible:

| Input pattern | Detected as | Locking reconstruction |
|---|---|---|
| Empty scriptSig + 2-item witness with 33-byte second item | P2WPKH (SegWit) | `OP_DUP OP_HASH160 hash160(witness[1]) OP_EQUALVERIFY OP_CHECKSIG` |
| Empty scriptSig + multi-item witness | P2WSH (SegWit) | Last witness item decoded as ASM |
| scriptSig = `<DER sig> <pubkey>` | P2PKH | `OP_DUP OP_HASH160 hash160(pubkey) OP_EQUALVERIFY OP_CHECKSIG` |
| scriptSig = `<DER sig>` only | P2PK | Cannot reconstruct |
| scriptSig starts with OP_0 | P2MS / P2SH | Cannot reconstruct |

**`txinHex` support:** if the previous transaction is also provided, the output at `prevIndex` is extracted and its `scriptPubKeyAsm` becomes the locking script — overriding whatever was auto-reconstructed.

---

### `api/fetch-tx.js` — TxID Lookup

`POST /api/fetch-tx` — accepts `{ txid, network }`

Fetches raw transaction hex from public block explorers. Uses two APIs with automatic fallback:

1. **Blockstream** (`blockstream.info`) — tried first
2. **mempool.space** — fallback if Blockstream fails or times out

Timeout is 8 seconds per attempt (within Vercel's 10-second function limit). Uses `AbortController` + `setTimeout` (not `AbortSignal.timeout()` which is unreliable in Lambda environments).

---

### `api/templates.js` — Preset Script Examples

`GET /api/templates`

Returns the 10 built-in examples. All use deterministic fake keys/signatures so execution is predictable. Real hash values are computed at startup using `computeHash160` and `computeSha256` from `interpreter.js` so they always match.

---

### `public/main.js` — Frontend Logic

**State:**
```javascript
let steps       = [];   // execution steps from /api/execute
let currentStep = -1;   // which step is currently shown
let playTimer   = null; // auto-play interval
```

**Key functions:**

`runScript()` — sends unlocking + locking to `/api/execute`, calls `loadResult()`.

`loadResult(result)` — builds the token row and execution log from `result.tokens` and `result.steps`.

`renderStep(step, idx)` — renders a single step:
- Updates the stack panel with `step.stack`
- Updates the alt stack panel with `step.altStack`
- Highlights the current token in the token row using `step.tokenIndex`
- Shows step description, status badge, progress bar

`parseTx()` — reads the raw hex textarea, extracts `tx=` and `txin=` prefixes, sends to `/api/parse-tx`, calls `renderParsedTx()`.

`fetchByTxid()` — reads the txid inputs, fetches both transactions via `/api/fetch-tx`, pipes the raw hex through the same `/api/parse-tx` flow.

`renderParsedTx(tx)` — renders transaction info with debug buttons for each input and output. For P2WPKH outputs, converts `OP_0 <hash>` to the equivalent `OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_CHECKSIG` before loading into the debugger.

`loadScriptsForDebug(unlocking, locking, label)` — populates the script textareas and auto-executes.

---

### `public/parser.js` — Client-side Transaction Parser

A self-contained vanilla JS module (no dependencies, IIFE pattern) that exposes `window.BitcoinParser`. Provides the same transaction parsing functionality as `api/parse-tx.js` but runs entirely in the browser. Used for any future client-side parsing without a server round-trip.

Functions:
- `parseRawTx(hex)` — full transaction decoder
- `detectScriptType(scriptHex)` — identifies P2PKH, P2WPKH, P2TR, etc.
- `scriptHexToAsm(scriptHex)` — converts raw hex script to ASM text

---

### `server.js` — Local Development Server

A plain Node.js `http.createServer` server (no Express or other frameworks). Handles all the same routes as the `api/` functions, plus serves static files from `public/`.

Run with:
```bash
node server.js
# → http://127.0.0.1:3009
```

The response shaping (`shapeExecuteResult`) lives in both `server.js` and `api/execute.js` because they serve the same data format but run in different environments. Any change to the execution format needs to be updated in both.

---

## Data Flow: Debugging a Script

```
User types script
        ↓
main.js: runScript()
        ↓
POST /api/execute
  { unlocking: "3 5", locking: "OP_ADD 8 OP_EQUAL" }
        ↓
interpreter.js: executeScript()
  → tokenize both scripts
  → run each token through the switch statement
  → record a step snapshot after every token
  → final validity check
        ↓
api/execute.js: shapeExecuteResult()
  → build tokens[] with boundary marker
  → map field names for frontend
        ↓
main.js: loadResult()
  → build token row HTML
  → build log panel entries
  → goStep(0) → renderStep()
        ↓
User navigates steps (← → keys, buttons, auto-play)
  → renderStep() updates stack panel, token highlight, description
```

## Data Flow: Debugging from a TxID

```
User pastes TxID(s)
        ↓
main.js: fetchByTxid()
        ↓
POST /api/fetch-tx  (× 2 in parallel)
  → Blockstream API → raw hex
  (fallback: mempool.space)
        ↓
POST /api/parse-tx
  { hex: <spending tx>, txinHex: <prev tx> }
        ↓
api/parse-tx.js: parseTx()
  → decode binary transaction
  → extract scriptSig / witness per input
  → extract scriptPubKey per output
  → classifyInput() → auto-reconstruct locking scripts
  → if txinHex: override with actual prev output scriptPubKey
        ↓
main.js: renderParsedTx()
  → show inputs/outputs with type badges
  → "Debug" button → loadScriptsForDebug() → runScript()
        ↓
(same flow as above from POST /api/execute)
```

---

## Key Concepts Summary

| Concept | Where It's Implemented |
|---|---|
| Script tokenization | `interpreter.js: parseScript()` |
| Stack machine execution | `interpreter.js: executeScript()` |
| HASH160 (SHA256 + RIPEMD160) | `interpreter.js: hash160()` |
| OP_CHECKSIG simulation | `interpreter.js: case 'OP_CHECKSIG'` |
| IF/ELSE branch tracking | `interpreter.js: ifStk[]` array |
| Transaction binary decoding | `api/parse-tx.js: parseTx()` |
| SegWit witness extraction | `api/parse-tx.js: isSegwit` block |
| Input type classification | `api/parse-tx.js: classifyInput()` |
| P2WPKH locking reconstruction | `api/parse-tx.js: classifyInput()` + `public/main.js: renderParsedTx()` |
| TxID → raw hex lookup | `api/fetch-tx.js` |
| Step trace rendering | `public/main.js: renderStep()` |
| Token row with boundary marker | `api/execute.js: shapeExecuteResult()` |
