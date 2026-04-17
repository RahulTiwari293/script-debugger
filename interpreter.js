/**
 * Bitcoin Script Interpreter — Lab 9
 * Supports: P2PK, P2PKH, P2MS, P2SH (locking pattern), P2WPKH (equivalent),
 *           P2TR Key Path (equivalent), P2TR Script Path (Tapscript),
 *           Hash Puzzle, Math Puzzle, OP_RETURN, and all standard opcodes.
 *
 * Stack convention: stack[stack.length - 1] is the TOP.
 * OP_CHECKSIG is simulated (no real ECDSA) — controlled by checksigResult option.
 */

import { createHash } from 'crypto';

// ─── Opcode table ─────────────────────────────────────────────────────────────

export const OPCODES = {
  OP_0: 0x00, OP_FALSE: 0x00,
  OP_PUSHDATA1: 0x4c, OP_PUSHDATA2: 0x4d, OP_PUSHDATA4: 0x4e,
  OP_1NEGATE: 0x4f,
  OP_1: 0x51, OP_TRUE: 0x51,
  OP_2: 0x52, OP_3: 0x53, OP_4: 0x54, OP_5: 0x55,
  OP_6: 0x56, OP_7: 0x57, OP_8: 0x58, OP_9: 0x59,
  OP_10: 0x5a, OP_11: 0x5b, OP_12: 0x5c, OP_13: 0x5d,
  OP_14: 0x5e, OP_15: 0x5f, OP_16: 0x60,
  OP_NOP: 0x61,
  OP_IF: 0x63, OP_NOTIF: 0x64, OP_ELSE: 0x67, OP_ENDIF: 0x68,
  OP_VERIFY: 0x69, OP_RETURN: 0x6a,
  OP_TOALTSTACK: 0x6b, OP_FROMALTSTACK: 0x6c,
  OP_2DROP: 0x6d, OP_2DUP: 0x6e, OP_3DUP: 0x6f,
  OP_2OVER: 0x70, OP_2ROT: 0x71, OP_2SWAP: 0x72,
  OP_IFDUP: 0x73, OP_DEPTH: 0x74, OP_DROP: 0x75, OP_DUP: 0x76,
  OP_NIP: 0x77, OP_OVER: 0x78, OP_PICK: 0x79, OP_ROLL: 0x7a,
  OP_ROT: 0x7b, OP_SWAP: 0x7c, OP_TUCK: 0x7d,
  OP_SIZE: 0x82,
  OP_EQUAL: 0x87, OP_EQUALVERIFY: 0x88,
  OP_1ADD: 0x8b, OP_1SUB: 0x8c,
  OP_NEGATE: 0x8f, OP_ABS: 0x90, OP_NOT: 0x91, OP_0NOTEQUAL: 0x92,
  OP_ADD: 0x93, OP_SUB: 0x94,
  OP_BOOLAND: 0x9a, OP_BOOLOR: 0x9b,
  OP_NUMEQUAL: 0x9c, OP_NUMEQUALVERIFY: 0x9d, OP_NUMNOTEQUAL: 0x9e,
  OP_LESSTHAN: 0x9f, OP_GREATERTHAN: 0xa0,
  OP_LESSTHANOREQUAL: 0xa1, OP_GREATERTHANOREQUAL: 0xa2,
  OP_MIN: 0xa3, OP_MAX: 0xa4, OP_WITHIN: 0xa5,
  OP_RIPEMD160: 0xa6, OP_SHA1: 0xa7, OP_SHA256: 0xa8,
  OP_HASH160: 0xa9, OP_HASH256: 0xaa,
  OP_CODESEPARATOR: 0xab,
  OP_CHECKSIG: 0xac, OP_CHECKSIGVERIFY: 0xad,
  OP_CHECKMULTISIG: 0xae, OP_CHECKMULTISIGVERIFY: 0xaf,
  // Tapscript (BIP342) — SegWit v1 / P2TR
  OP_CHECKSIGADD: 0xba,
};

export const OPCODE_DESCRIPTIONS = {
  OP_0:                  'Pushes an empty byte array (false / 0) onto the stack.',
  OP_1NEGATE:            'Pushes the number -1 onto the stack.',
  OP_NOP:                'Does nothing. Used as a no-operation placeholder.',
  OP_IF:                 'If the top stack value is not 0, executes the following statements.',
  OP_NOTIF:              'If the top stack value IS 0, executes the following statements.',
  OP_ELSE:               'Executes the opposite branch of the preceding IF.',
  OP_ENDIF:              'Ends an IF/ELSE block.',
  OP_VERIFY:             'Marks script invalid if top value is false; removes the top value.',
  OP_RETURN:             'Marks output as unspendable. Script exits immediately.',
  OP_TOALTSTACK:         'Moves the top item from the main stack to the alternate stack.',
  OP_FROMALTSTACK:       'Moves the top item from the alternate stack to the main stack.',
  OP_2DROP:              'Removes the top two stack items.',
  OP_2DUP:               'Duplicates the top two stack items.',
  OP_3DUP:               'Duplicates the top three stack items.',
  OP_2OVER:              'Copies the pair of items two spots back to the top.',
  OP_2ROT:               'Moves the fifth and sixth items to the top of the stack.',
  OP_2SWAP:              'Swaps the top two pairs of items.',
  OP_IFDUP:              'Duplicates top item only if it is not zero.',
  OP_DEPTH:              'Pushes the current number of stack items.',
  OP_DROP:               'Removes the top stack item.',
  OP_DUP:                'Duplicates the top stack item. Core of P2PKH.',
  OP_NIP:                'Removes the second-to-top item.',
  OP_OVER:               'Copies the second-to-top item to the top.',
  OP_PICK:               'Copies the Nth item (0-indexed from top) to the top.',
  OP_ROLL:               'Moves the Nth item to the top.',
  OP_ROT:                'Rotates the third item to the top.',
  OP_SWAP:               'Swaps the top two items.',
  OP_TUCK:               'Copies the top item before the second-to-top item.',
  OP_SIZE:               'Pushes the byte length of the top item (without popping it).',
  OP_EQUAL:              'Pushes 1 if the top two items are equal, else 0.',
  OP_EQUALVERIFY:        'Like OP_EQUAL but marks script invalid if they are not equal.',
  OP_1ADD:               'Adds 1 to the top stack number.',
  OP_1SUB:               'Subtracts 1 from the top stack number.',
  OP_NEGATE:             'Negates the top stack number.',
  OP_ABS:                'Absolute value of the top stack number.',
  OP_NOT:                'Flips 0 → 1, and any non-zero → 0.',
  OP_0NOTEQUAL:          'Pushes 1 if top is non-zero, else pushes 0.',
  OP_ADD:                'Pops two numbers and pushes their sum.',
  OP_SUB:                'Pops a then b; pushes (b − a).',
  OP_BOOLAND:            'Pushes 1 if both top two items are non-zero.',
  OP_BOOLOR:             'Pushes 1 if either of the top two items is non-zero.',
  OP_NUMEQUAL:           'Pushes 1 if the top two numbers are equal.',
  OP_NUMEQUALVERIFY:     'Like OP_NUMEQUAL but fails script if they differ.',
  OP_NUMNOTEQUAL:        'Pushes 1 if the top two numbers are not equal.',
  OP_LESSTHAN:           'Pushes 1 if (second < top).',
  OP_GREATERTHAN:        'Pushes 1 if (second > top).',
  OP_LESSTHANOREQUAL:    'Pushes 1 if (second ≤ top).',
  OP_GREATERTHANOREQUAL: 'Pushes 1 if (second ≥ top).',
  OP_MIN:                'Pushes the minimum of the top two numbers.',
  OP_MAX:                'Pushes the maximum of the top two numbers.',
  OP_WITHIN:             'Pushes 1 if x is within [min, max). Pops x, min, max.',
  OP_RIPEMD160:          'Hashes the top item with RIPEMD-160.',
  OP_SHA1:               'Hashes the top item with SHA-1.',
  OP_SHA256:             'Hashes the top item with SHA-256.',
  OP_HASH160:            'Hashes the top item with SHA-256 then RIPEMD-160. Used in P2PKH.',
  OP_HASH256:            'Hashes the top item with SHA-256 twice (double-SHA256).',
  OP_CODESEPARATOR:      'Marks the current position — affects CHECKSIG (advanced). No stack effect.',
  OP_CHECKSIG:           'Pops pubkey and sig. Pushes 1 if signature is valid, 0 otherwise. In Tapscript uses Schnorr instead of ECDSA. (Simulated here)',
  OP_CHECKSIGVERIFY:     'Like OP_CHECKSIG but fails script if signature is invalid. (Simulated)',
  OP_CHECKMULTISIG:      'Verifies M-of-N multisig. Pops N pubkeys, M sigs, an extra dummy value. Pushes 1/0. Legacy only — DISABLED in Tapscript. (Simulated)',
  OP_CHECKMULTISIGVERIFY:'Like OP_CHECKMULTISIG but fails if invalid. Legacy only — DISABLED in Tapscript. (Simulated)',
  OP_CHECKSIGADD:        'Tapscript (BIP342): Pops pubkey, n, sig. If sig is non-empty and valid pushes n+1, else pushes n unchanged. Used for threshold Schnorr multisig without the legacy off-by-one bug. (Simulated)',
};

// ─── Crypto helpers ────────────────────────────────────────────────────────────

function toBuffer(val) {
  if (typeof val === 'string' && /^[0-9a-fA-F]+$/.test(val) && val.length % 2 === 0) {
    return Buffer.from(val, 'hex');
  }
  return Buffer.from(val, 'utf8');
}

function doHash(algo, val) {
  try { return createHash(algo).update(toBuffer(val)).digest('hex'); }
  catch { return createHash('sha256').update(toBuffer(val)).digest('hex'); } // RIPEMD fallback
}

function hash160(val) {
  const sha = createHash('sha256').update(toBuffer(val)).digest();
  try { return createHash('ripemd160').update(sha).digest('hex'); }
  catch { return createHash('sha256').update(sha).digest('hex'); } // RIPEMD fallback
}

function hash256(val) {
  const first = createHash('sha256').update(toBuffer(val)).digest();
  return createHash('sha256').update(first).digest('hex');
}

export function computeHash160(hexPubkey) { return hash160(hexPubkey); }
export function computeSha256(hexStr)     { return doHash('sha256', hexStr); }

// ─── Script tokenizer ─────────────────────────────────────────────────────────

export function parseScript(scriptStr) {
  const tokens = [];
  const parts = scriptStr.trim().split(/\s+/).filter(Boolean);

  for (const raw of parts) {
    const up = raw.toUpperCase();

    if (up in OPCODES || up === 'OP_TRUE' || up === 'OP_FALSE') {
      tokens.push({ type: 'opcode', raw, value: up });
    } else if (/^[0-9a-fA-F]+$/.test(raw) && raw.length >= 2 && raw.length % 2 === 0) {
      tokens.push({ type: 'data', raw, value: raw.toLowerCase() });
    } else if (/^-?\d+$/.test(raw)) {
      tokens.push({ type: 'integer', raw, value: raw });
    } else {
      // Treat as a labelled placeholder (e.g. <sig>, <pubkey>)
      tokens.push({ type: 'label', raw, value: raw });
    }
  }

  return tokens;
}

// ─── Stack truthiness (Bitcoin rules) ─────────────────────────────────────────

function isTruthy(item) {
  if (item === null || item === undefined || item === '') return false;
  if (item === '0' || item === '-0') return false;
  if (typeof item === 'string' && /^[0-9a-fA-F]+$/.test(item) && item.length % 2 === 0) {
    const bytes = item.match(/.{2}/g) || [];
    // All-zero bytes → false
    if (bytes.every(b => b === '00')) return false;
    // Negative zero: last byte 0x80, rest 0x00
    if (bytes[bytes.length - 1] === '80' && bytes.slice(0, -1).every(b => b === '00')) return false;
  }
  return true;
}

function fmt(item) {
  if (item === null || item === undefined || item === '') return '(empty)';
  if (typeof item === 'string' && item.length > 20) return item.slice(0, 8) + '…' + item.slice(-6);
  return String(item);
}

// ─── Main interpreter ─────────────────────────────────────────────────────────

/**
 * executeScript(unlockingStr, lockingStr, options)
 *
 * options:
 *   checksigResult  — 'valid' | 'invalid' | 'auto' (default: 'valid')
 *
 * Returns:
 *   { valid, error, steps, finalStack, tokenCount }
 *
 * Each step:
 *   { index, tokenRaw, tokenType, opcode?, description, stackBefore, stackAfter, altBefore, altAfter, status }
 *   status: 'initial' | 'push' | 'ok' | 'success' | 'warning' | 'skipped' | 'error'
 */
export function executeScript(unlockingStr, lockingStr, options = {}) {
  const checksigResult = options.checksigResult ?? 'valid';

  const unlockTokens = parseScript(unlockingStr);
  const lockTokens   = parseScript(lockingStr);
  const allTokens    = [...unlockTokens, ...lockTokens];
  const boundary     = unlockTokens.length; // index where locking script starts

  const steps  = [];
  const stack  = [];
  const alt    = [];
  const ifStk  = []; // { executing, seenElse }

  let valid = true;
  let error = null;

  const snap = () => ({
    stack: stack.map(s => s),
    alt:   alt.map(s => s),
  });

  // ── Initial step ──────────────────────────────────────────────────────────
  steps.push({
    index: -1, tokenRaw: null, tokenType: 'initial',
    description: 'Execution starts — stack is empty. Unlocking script runs first, then locking script.',
    stackBefore: [], stackAfter: [], altBefore: [], altAfter: [],
    status: 'initial', boundary,
  });

  for (let i = 0; i < allTokens.length; i++) {
    const token = allTokens[i];
    const { stack: sBefore, alt: aBefore } = snap();

    const executing = ifStk.every(f => f.executing);
    let description = '';
    let status = 'ok';

    const pushStep = () => steps.push({
      index: i, tokenRaw: token.raw, tokenType: token.type,
      description, stackBefore: sBefore, stackAfter: snap().stack,
      altBefore: aBefore, altAfter: snap().alt,
      status, boundary,
      isBoundary: i === boundary,
    });

    try {
      if (token.type !== 'opcode') {
        // ── Data / label / integer ─────────────────────────────────────────
        if (executing) {
          stack.push(token.value);
          status = 'push';
          description = i < boundary
            ? `[ScriptSig] Push "${fmt(token.value)}" onto the stack.`
            : `[ScriptPubKey] Push "${fmt(token.value)}" onto the stack.`;
        } else {
          status = 'skipped';
          description = `Push skipped — inside a non-executing IF branch.`;
        }
        pushStep();
        continue;
      }

      const op = token.value;

      // ── Flow control (handled even in non-executing branches) ────────────
      if (op === 'OP_IF' || op === 'OP_NOTIF') {
        if (executing) {
          if (!stack.length) throw new Error(`${op}: stack underflow`);
          const top = stack.pop();
          const cond = isTruthy(top);
          const enter = op === 'OP_IF' ? cond : !cond;
          ifStk.push({ executing: enter, seenElse: false });
          description = `${op}: condition is ${cond ? 'TRUE' : 'FALSE'} → ${enter ? 'entering' : 'skipping'} block.`;
          status = enter ? 'ok' : 'skipped';
        } else {
          ifStk.push({ executing: false, seenElse: false });
          description = `${op}: nested inside non-executing branch — skipped.`;
          status = 'skipped';
        }
        pushStep(); continue;
      }
      if (op === 'OP_ELSE') {
        if (!ifStk.length) throw new Error('OP_ELSE without OP_IF');
        const frame = ifStk[ifStk.length - 1];
        if (!frame.seenElse) { frame.executing = !frame.executing; frame.seenElse = true; }
        description = `OP_ELSE: switching to ${frame.executing ? 'executing' : 'skipping'} branch.`;
        status = frame.executing ? 'ok' : 'skipped';
        pushStep(); continue;
      }
      if (op === 'OP_ENDIF') {
        if (!ifStk.length) throw new Error('OP_ENDIF without OP_IF');
        ifStk.pop();
        description = 'OP_ENDIF: closing IF block.';
        pushStep(); continue;
      }

      // ── All other opcodes only execute if we're in an executing branch ───
      if (!executing) {
        description = `${op}: skipped — inside OP_IF false branch.`;
        status = 'skipped';
        pushStep(); continue;
      }

      // ── Opcode execution ──────────────────────────────────────────────────
      switch (op) {

        case 'OP_NOP': case 'OP_CODESEPARATOR':
          description = OPCODE_DESCRIPTIONS[op];
          break;

        case 'OP_0': case 'OP_FALSE':
          stack.push('');
          description = 'OP_0: pushed empty byte array (false) onto stack.';
          status = 'push';
          break;

        case 'OP_TRUE':
          stack.push('01');
          description = 'OP_TRUE: pushed 1 (true) onto stack.';
          status = 'push';
          break;

        case 'OP_1NEGATE':
          stack.push('-1');
          description = 'OP_1NEGATE: pushed -1 onto stack.';
          status = 'push';
          break;

        case 'OP_RETURN':
          throw new Error('OP_RETURN: script terminated — this output is unspendable (e.g. data carrier).');

        // ── Stack manipulation ──────────────────────────────────────────────
        case 'OP_DUP': {
          if (!stack.length) throw new Error('OP_DUP: stack underflow');
          const top = stack[stack.length - 1];
          stack.push(top);
          description = `OP_DUP: duplicated top item → [${fmt(top)}].`;
          break;
        }
        case 'OP_2DUP': {
          if (stack.length < 2) throw new Error('OP_2DUP: need ≥ 2 items');
          stack.push(stack[stack.length - 2], stack[stack.length - 1]);
          description = 'OP_2DUP: duplicated top two items.';
          break;
        }
        case 'OP_3DUP': {
          if (stack.length < 3) throw new Error('OP_3DUP: need ≥ 3 items');
          stack.push(stack[stack.length - 3], stack[stack.length - 2], stack[stack.length - 1]);
          description = 'OP_3DUP: duplicated top three items.';
          break;
        }
        case 'OP_DROP': {
          if (!stack.length) throw new Error('OP_DROP: stack underflow');
          const d = stack.pop();
          description = `OP_DROP: removed [${fmt(d)}] from top.`;
          break;
        }
        case 'OP_2DROP': {
          if (stack.length < 2) throw new Error('OP_2DROP: need ≥ 2 items');
          stack.pop(); stack.pop();
          description = 'OP_2DROP: removed top two items.';
          break;
        }
        case 'OP_OVER': {
          if (stack.length < 2) throw new Error('OP_OVER: need ≥ 2 items');
          stack.push(stack[stack.length - 2]);
          description = `OP_OVER: copied second item [${fmt(stack[stack.length - 1])}] to top.`;
          break;
        }
        case 'OP_2OVER': {
          if (stack.length < 4) throw new Error('OP_2OVER: need ≥ 4 items');
          stack.push(stack[stack.length - 4], stack[stack.length - 3]);
          description = 'OP_2OVER: copied third and fourth items to top.';
          break;
        }
        case 'OP_SWAP': {
          if (stack.length < 2) throw new Error('OP_SWAP: need ≥ 2 items');
          const n = stack.length;
          [stack[n - 1], stack[n - 2]] = [stack[n - 2], stack[n - 1]];
          description = 'OP_SWAP: swapped top two items.';
          break;
        }
        case 'OP_2SWAP': {
          if (stack.length < 4) throw new Error('OP_2SWAP: need ≥ 4 items');
          const n = stack.length;
          [stack[n - 1], stack[n - 3]] = [stack[n - 3], stack[n - 1]];
          [stack[n - 2], stack[n - 4]] = [stack[n - 4], stack[n - 2]];
          description = 'OP_2SWAP: swapped top two pairs.';
          break;
        }
        case 'OP_ROT': {
          if (stack.length < 3) throw new Error('OP_ROT: need ≥ 3 items');
          stack.push(stack.splice(stack.length - 3, 1)[0]);
          description = 'OP_ROT: rotated third item to top.';
          break;
        }
        case 'OP_2ROT': {
          if (stack.length < 6) throw new Error('OP_2ROT: need ≥ 6 items');
          stack.push(...stack.splice(stack.length - 6, 2));
          description = 'OP_2ROT: moved fifth and sixth items to top.';
          break;
        }
        case 'OP_NIP': {
          if (stack.length < 2) throw new Error('OP_NIP: need ≥ 2 items');
          const nipped = stack.splice(stack.length - 2, 1)[0];
          description = `OP_NIP: removed second-to-top [${fmt(nipped)}].`;
          break;
        }
        case 'OP_TUCK': {
          if (stack.length < 2) throw new Error('OP_TUCK: need ≥ 2 items');
          stack.splice(stack.length - 2, 0, stack[stack.length - 1]);
          description = 'OP_TUCK: copied top item before second item.';
          break;
        }
        case 'OP_PICK': {
          if (!stack.length) throw new Error('OP_PICK: stack underflow');
          const n = parseInt(stack.pop());
          if (isNaN(n) || n < 0 || n >= stack.length) throw new Error(`OP_PICK: invalid depth ${n}`);
          stack.push(stack[stack.length - 1 - n]);
          description = `OP_PICK: copied item at depth ${n} to top.`;
          break;
        }
        case 'OP_ROLL': {
          if (!stack.length) throw new Error('OP_ROLL: stack underflow');
          const n = parseInt(stack.pop());
          if (isNaN(n) || n < 0 || n >= stack.length) throw new Error(`OP_ROLL: invalid depth ${n}`);
          stack.push(stack.splice(stack.length - 1 - n, 1)[0]);
          description = `OP_ROLL: moved item at depth ${n} to top.`;
          break;
        }
        case 'OP_IFDUP': {
          if (!stack.length) throw new Error('OP_IFDUP: stack underflow');
          const top = stack[stack.length - 1];
          if (isTruthy(top)) { stack.push(top); description = `OP_IFDUP: top is truthy → duplicated [${fmt(top)}].`; }
          else                { description = 'OP_IFDUP: top is falsy (0) → no duplication.'; }
          break;
        }
        case 'OP_DEPTH':
          stack.push(stack.length.toString());
          description = `OP_DEPTH: pushed stack depth → ${stack[stack.length - 1]}.`;
          break;

        case 'OP_SIZE': {
          if (!stack.length) throw new Error('OP_SIZE: stack underflow');
          const top = stack[stack.length - 1];
          let byteLen;
          if (/^[0-9a-fA-F]+$/.test(top) && top.length % 2 === 0) byteLen = top.length / 2;
          else byteLen = Buffer.from(top, 'utf8').length;
          stack.push(byteLen.toString());
          description = `OP_SIZE: top item is ${byteLen} byte(s) → pushed ${byteLen}.`;
          break;
        }

        case 'OP_TOALTSTACK': {
          if (!stack.length) throw new Error('OP_TOALTSTACK: stack underflow');
          alt.push(stack.pop());
          description = 'OP_TOALTSTACK: moved top item to the alternate stack.';
          break;
        }
        case 'OP_FROMALTSTACK': {
          if (!alt.length) throw new Error('OP_FROMALTSTACK: alt stack underflow');
          stack.push(alt.pop());
          description = 'OP_FROMALTSTACK: moved top of alt stack to main stack.';
          break;
        }

        // ── Equality ────────────────────────────────────────────────────────
        case 'OP_EQUAL': {
          if (stack.length < 2) throw new Error('OP_EQUAL: need ≥ 2 items');
          const b = stack.pop(), a = stack.pop();
          const eq = a === b;
          stack.push(eq ? '01' : '');
          description = `OP_EQUAL: [${fmt(a)}] == [${fmt(b)}] → ${eq ? 'TRUE (1)' : 'FALSE (0)'}.`;
          status = eq ? 'ok' : 'warning';
          break;
        }
        case 'OP_EQUALVERIFY': {
          if (stack.length < 2) throw new Error('OP_EQUALVERIFY: need ≥ 2 items');
          const b = stack.pop(), a = stack.pop();
          if (a !== b) throw new Error(`OP_EQUALVERIFY FAILED: [${fmt(a)}] ≠ [${fmt(b)}]. Script is invalid.`);
          description = `OP_EQUALVERIFY: [${fmt(a)}] == [${fmt(b)}] ✓ — values match, continuing.`;
          status = 'success';
          break;
        }

        // ── Verify ──────────────────────────────────────────────────────────
        case 'OP_VERIFY': {
          if (!stack.length) throw new Error('OP_VERIFY: stack underflow');
          const top = stack.pop();
          if (!isTruthy(top)) throw new Error(`OP_VERIFY FAILED: top value [${fmt(top)}] is false.`);
          description = `OP_VERIFY: top [${fmt(top)}] is truthy — script continues.`;
          status = 'success';
          break;
        }

        // ── Crypto ──────────────────────────────────────────────────────────
        case 'OP_SHA256': {
          if (!stack.length) throw new Error('OP_SHA256: stack underflow');
          const top = stack.pop();
          const h = doHash('sha256', top);
          stack.push(h);
          description = `OP_SHA256: SHA256([${fmt(top)}]) → [${fmt(h)}].`;
          break;
        }
        case 'OP_HASH256': {
          if (!stack.length) throw new Error('OP_HASH256: stack underflow');
          const top = stack.pop();
          const h = hash256(top);
          stack.push(h);
          description = `OP_HASH256: SHA256(SHA256([${fmt(top)}])) → [${fmt(h)}].`;
          break;
        }
        case 'OP_RIPEMD160': {
          if (!stack.length) throw new Error('OP_RIPEMD160: stack underflow');
          const top = stack.pop();
          const h = doHash('ripemd160', top);
          stack.push(h);
          description = `OP_RIPEMD160: RIPEMD160([${fmt(top)}]) → [${fmt(h)}].`;
          break;
        }
        case 'OP_SHA1': {
          if (!stack.length) throw new Error('OP_SHA1: stack underflow');
          const top = stack.pop();
          const h = doHash('sha1', top);
          stack.push(h);
          description = `OP_SHA1: SHA1([${fmt(top)}]) → [${fmt(h)}].`;
          break;
        }
        case 'OP_HASH160': {
          if (!stack.length) throw new Error('OP_HASH160: stack underflow');
          const top = stack.pop();
          const h = hash160(top);
          stack.push(h);
          description = `OP_HASH160: RIPEMD160(SHA256([${fmt(top)}])) → [${fmt(h)}].`;
          break;
        }

        // ── Checksig ────────────────────────────────────────────────────────
        case 'OP_CHECKSIG': {
          if (stack.length < 2) throw new Error('OP_CHECKSIG: need ≥ 2 items (sig, pubkey)');
          const pubkey = stack.pop();
          const sig    = stack.pop();
          const ok = checksigResult !== 'invalid';
          stack.push(ok ? '01' : '');
          description = `OP_CHECKSIG: verified sig [${fmt(sig)}] against pubkey [${fmt(pubkey)}] → ${ok ? 'VALID ✓ (1)' : 'INVALID ✗ (0)'} (simulated).`;
          status = ok ? 'ok' : 'warning';
          break;
        }
        case 'OP_CHECKSIGVERIFY': {
          if (stack.length < 2) throw new Error('OP_CHECKSIGVERIFY: need ≥ 2 items');
          const pubkey = stack.pop();
          const sig    = stack.pop();
          const ok = checksigResult !== 'invalid';
          if (!ok) throw new Error('OP_CHECKSIGVERIFY FAILED: signature invalid (simulated).');
          description = `OP_CHECKSIGVERIFY: sig verified against pubkey ✓ (simulated).`;
          status = 'success';
          break;
        }
        case 'OP_CHECKMULTISIG': {
          if (!stack.length) throw new Error('OP_CHECKMULTISIG: stack underflow');
          const n = parseInt(stack.pop());
          if (isNaN(n) || stack.length < n) throw new Error(`OP_CHECKMULTISIG: need ${n} pubkeys on stack`);
          const pubkeys = [];
          for (let j = 0; j < n; j++) pubkeys.push(stack.pop());
          if (!stack.length) throw new Error('OP_CHECKMULTISIG: missing m value');
          const m = parseInt(stack.pop());
          if (isNaN(m) || stack.length < m) throw new Error(`OP_CHECKMULTISIG: need ${m} signatures on stack`);
          const sigs = [];
          for (let j = 0; j < m; j++) sigs.push(stack.pop());
          if (stack.length) stack.pop(); // Bitcoin off-by-one bug: consumes one extra dummy value
          const ok = checksigResult !== 'invalid';
          stack.push(ok ? '01' : '');
          description = `OP_CHECKMULTISIG: ${m}-of-${n} multisig → ${ok ? 'VALID ✓ (1)' : 'INVALID ✗ (0)'} (simulated). Note: one extra dummy value consumed (Bitcoin bug).`;
          status = ok ? 'ok' : 'warning';
          break;
        }
        case 'OP_CHECKMULTISIGVERIFY': {
          if (!stack.length) throw new Error('OP_CHECKMULTISIGVERIFY: stack underflow');
          const n = parseInt(stack.pop());
          const pubkeys = [];
          for (let j = 0; j < n; j++) pubkeys.push(stack.pop());
          const m = parseInt(stack.pop());
          const sigs = [];
          for (let j = 0; j < m; j++) sigs.push(stack.pop());
          if (stack.length) stack.pop();
          const ok = checksigResult !== 'invalid';
          if (!ok) throw new Error('OP_CHECKMULTISIGVERIFY FAILED: multisig invalid (simulated).');
          description = `OP_CHECKMULTISIGVERIFY: ${m}-of-${n} multisig VALID ✓ (simulated).`;
          status = 'success';
          break;
        }
        // ── Tapscript (BIP342) ────────────────────────────────────────────────
        case 'OP_CHECKSIGADD': {
          // Stack (top→bottom): pubkey | n | sig
          if (stack.length < 3) throw new Error('OP_CHECKSIGADD: need ≥ 3 items (pubkey, n, sig)');
          const pubkey = stack.pop();
          const n      = parseInt(stack.pop());
          const sig    = stack.pop();
          if (isNaN(n)) throw new Error('OP_CHECKSIGADD: n is not a number');
          const sigPresent = sig !== '' && sig !== '00';
          const ok = sigPresent && checksigResult !== 'invalid';
          const result = ok ? n + 1 : n;
          stack.push(String(result));
          description = `OP_CHECKSIGADD (Tapscript): sig [${fmt(sig)}] vs pubkey [${fmt(pubkey)}] — ${ok ? 'valid Schnorr sig ✓' : 'no/invalid sig'} → n ${n} + ${ok ? 1 : 0} = ${result}. (simulated)`;
          status = ok ? 'ok' : 'warning';
          break;
        }

        // ── Arithmetic ──────────────────────────────────────────────────────
        case 'OP_ADD': {
          if (stack.length < 2) throw new Error('OP_ADD: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          if (isNaN(a) || isNaN(b)) throw new Error('OP_ADD: non-numeric operands');
          stack.push(String(a + b));
          description = `OP_ADD: ${a} + ${b} = ${a + b}.`;
          break;
        }
        case 'OP_SUB': {
          if (stack.length < 2) throw new Error('OP_SUB: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          if (isNaN(a) || isNaN(b)) throw new Error('OP_SUB: non-numeric operands');
          stack.push(String(a - b));
          description = `OP_SUB: ${a} − ${b} = ${a - b}.`;
          break;
        }
        case 'OP_1ADD': {
          if (!stack.length) throw new Error('OP_1ADD: stack underflow');
          const a = Number(stack.pop());
          stack.push(String(a + 1));
          description = `OP_1ADD: ${a} + 1 = ${a + 1}.`;
          break;
        }
        case 'OP_1SUB': {
          if (!stack.length) throw new Error('OP_1SUB: stack underflow');
          const a = Number(stack.pop());
          stack.push(String(a - 1));
          description = `OP_1SUB: ${a} − 1 = ${a - 1}.`;
          break;
        }
        case 'OP_NEGATE': {
          if (!stack.length) throw new Error('OP_NEGATE: stack underflow');
          const a = Number(stack.pop());
          stack.push(String(-a));
          description = `OP_NEGATE: −(${a}) = ${-a}.`;
          break;
        }
        case 'OP_ABS': {
          if (!stack.length) throw new Error('OP_ABS: stack underflow');
          const a = Number(stack.pop());
          stack.push(String(Math.abs(a)));
          description = `OP_ABS: |${a}| = ${Math.abs(a)}.`;
          break;
        }
        case 'OP_NOT': {
          if (!stack.length) throw new Error('OP_NOT: stack underflow');
          const a = stack.pop();
          stack.push(isTruthy(a) ? '' : '01');
          description = `OP_NOT: !truthy([${fmt(a)}]) = ${isTruthy(a) ? '0' : '1'}.`;
          break;
        }
        case 'OP_0NOTEQUAL': {
          if (!stack.length) throw new Error('OP_0NOTEQUAL: stack underflow');
          const a = stack.pop();
          stack.push(isTruthy(a) ? '01' : '');
          description = `OP_0NOTEQUAL: [${fmt(a)}] ≠ 0 → ${isTruthy(a) ? 1 : 0}.`;
          break;
        }
        case 'OP_BOOLAND': {
          if (stack.length < 2) throw new Error('OP_BOOLAND: need ≥ 2 items');
          const b = stack.pop(), a = stack.pop();
          stack.push(isTruthy(a) && isTruthy(b) ? '01' : '');
          description = `OP_BOOLAND: ${isTruthy(a)} AND ${isTruthy(b)} = ${isTruthy(a) && isTruthy(b) ? 1 : 0}.`;
          break;
        }
        case 'OP_BOOLOR': {
          if (stack.length < 2) throw new Error('OP_BOOLOR: need ≥ 2 items');
          const b = stack.pop(), a = stack.pop();
          stack.push(isTruthy(a) || isTruthy(b) ? '01' : '');
          description = `OP_BOOLOR: ${isTruthy(a)} OR ${isTruthy(b)} = ${isTruthy(a) || isTruthy(b) ? 1 : 0}.`;
          break;
        }
        case 'OP_NUMEQUAL': {
          if (stack.length < 2) throw new Error('OP_NUMEQUAL: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a === b ? '01' : '');
          description = `OP_NUMEQUAL: ${a} == ${b} → ${a === b ? 1 : 0}.`;
          break;
        }
        case 'OP_NUMEQUALVERIFY': {
          if (stack.length < 2) throw new Error('OP_NUMEQUALVERIFY: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          if (a !== b) throw new Error(`OP_NUMEQUALVERIFY FAILED: ${a} ≠ ${b}.`);
          description = `OP_NUMEQUALVERIFY: ${a} == ${b} ✓.`;
          status = 'success';
          break;
        }
        case 'OP_NUMNOTEQUAL': {
          if (stack.length < 2) throw new Error('OP_NUMNOTEQUAL: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a !== b ? '01' : '');
          description = `OP_NUMNOTEQUAL: ${a} ≠ ${b} → ${a !== b ? 1 : 0}.`;
          break;
        }
        case 'OP_LESSTHAN': {
          if (stack.length < 2) throw new Error('OP_LESSTHAN: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a < b ? '01' : '');
          description = `OP_LESSTHAN: ${a} < ${b} → ${a < b ? 1 : 0}.`;
          break;
        }
        case 'OP_GREATERTHAN': {
          if (stack.length < 2) throw new Error('OP_GREATERTHAN: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a > b ? '01' : '');
          description = `OP_GREATERTHAN: ${a} > ${b} → ${a > b ? 1 : 0}.`;
          break;
        }
        case 'OP_LESSTHANOREQUAL': {
          if (stack.length < 2) throw new Error('OP_LESSTHANOREQUAL: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a <= b ? '01' : '');
          description = `OP_LESSTHANOREQUAL: ${a} ≤ ${b} → ${a <= b ? 1 : 0}.`;
          break;
        }
        case 'OP_GREATERTHANOREQUAL': {
          if (stack.length < 2) throw new Error('OP_GREATERTHANOREQUAL: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(a >= b ? '01' : '');
          description = `OP_GREATERTHANOREQUAL: ${a} ≥ ${b} → ${a >= b ? 1 : 0}.`;
          break;
        }
        case 'OP_MIN': {
          if (stack.length < 2) throw new Error('OP_MIN: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(String(Math.min(a, b)));
          description = `OP_MIN: min(${a}, ${b}) = ${Math.min(a, b)}.`;
          break;
        }
        case 'OP_MAX': {
          if (stack.length < 2) throw new Error('OP_MAX: need ≥ 2 items');
          const b = Number(stack.pop()), a = Number(stack.pop());
          stack.push(String(Math.max(a, b)));
          description = `OP_MAX: max(${a}, ${b}) = ${Math.max(a, b)}.`;
          break;
        }
        case 'OP_WITHIN': {
          if (stack.length < 3) throw new Error('OP_WITHIN: need ≥ 3 items');
          const max = Number(stack.pop()), min = Number(stack.pop()), x = Number(stack.pop());
          stack.push(x >= min && x < max ? '01' : '');
          description = `OP_WITHIN: ${min} ≤ ${x} < ${max} → ${x >= min && x < max ? 1 : 0}.`;
          break;
        }

        default: {
          // OP_1 … OP_16
          const m = op.match(/^OP_(\d+)$/);
          if (m) {
            const n = parseInt(m[1]);
            stack.push(String(n));
            description = `${op}: pushed ${n} onto stack.`;
            status = 'push';
          } else {
            description = `${op}: opcode executed (no stack effect defined in this simulator).`;
          }
          break;
        }
      }

    } catch (err) {
      error  = err.message;
      valid  = false;
      status = 'error';
      description = description || err.message;
      steps.push({
        index: i, tokenRaw: token.raw, tokenType: token.type,
        description, stackBefore: sBefore, stackAfter: snap().stack,
        altBefore: aBefore, altAfter: snap().alt,
        status, boundary,
        isBoundary: i === boundary,
      });
      break;
    }

    pushStep();
  }

  // ── Final validity check ─────────────────────────────────────────────────
  if (valid) {
    if (stack.length === 0)        { valid = false; error = 'Script INVALID: stack is empty at end of execution.'; }
    else if (stack.length > 1)     { valid = false; error = 'Script INVALID: more than one item remains on the stack.'; }
    else if (!isTruthy(stack[0]))  { valid = false; error = `Script INVALID: top of stack is false/zero — [${fmt(stack[0])}].`; }
  }

  return { valid, error, steps, finalStack: [...stack], tokenCount: allTokens.length };
}
