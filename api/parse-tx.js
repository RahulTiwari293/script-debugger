import { computeHash160, OPCODES } from '../interpreter.js';

const OPCODE_NAME = {};
for (const [name, code] of Object.entries(OPCODES)) {
  if (!OPCODE_NAME[code]) OPCODE_NAME[code] = name;
}
OPCODE_NAME[0xb1] = 'OP_CHECKLOCKTIMEVERIFY';
OPCODE_NAME[0xb2] = 'OP_CHECKSEQUENCEVERIFY';
OPCODE_NAME[0xba] = 'OP_CHECKSIGADD';        // Tapscript BIP342

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i / 2] = parseInt(hex.substr(i, 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function reverseHex(hex) {
  const out = [];
  for (let i = hex.length - 2; i >= 0; i -= 2) out.push(hex.substr(i, 2));
  return out.join('');
}

function readLE32(b, o) {
  return ((b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0);
}

function readLE64(b, o) {
  const lo = ((b[o]   | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0);
  const hi = ((b[o+4] | (b[o+5]<<8) | (b[o+6]<<16) | (b[o+7]<<24)) >>> 0);
  return hi * 0x100000000 + lo;
}

function readVarInt(b, o) {
  const f = b[o];
  if (f < 0xfd) return { value: f, size: 1 };
  if (f === 0xfd) return { value: b[o+1] | (b[o+2]<<8), size: 3 };
  if (f === 0xfe) return { value: readLE32(b, o+1), size: 5 };
  return { value: readLE32(b, o+1), size: 9 };
}

function scriptHexToAsm(scriptHex) {
  if (!scriptHex) return '';
  const bytes = hexToBytes(scriptHex);
  const tokens = [];
  let i = 0;
  while (i < bytes.length) {
    const op = bytes[i];
    if (op === 0x00) { tokens.push('OP_0'); i++; }
    else if (op >= 0x01 && op <= 0x4b) { tokens.push(bytesToHex(bytes.slice(i+1, i+1+op))); i += 1+op; }
    else if (op === 0x4c) { const n=bytes[i+1]; tokens.push(bytesToHex(bytes.slice(i+2, i+2+n))); i+=2+n; }
    else if (op === 0x4d) { const n=bytes[i+1]|(bytes[i+2]<<8); tokens.push(bytesToHex(bytes.slice(i+3, i+3+n))); i+=3+n; }
    else if (op === 0x4e) { const n=readLE32(bytes,i+1); tokens.push(bytesToHex(bytes.slice(i+5, i+5+n))); i+=5+n; }
    else { tokens.push(OPCODE_NAME[op] || `OP_UNKNOWN(0x${op.toString(16).padStart(2,'0')})`); i++; }
  }
  return tokens.join(' ');
}

function detectOutputType(scriptHex) {
  if (!scriptHex) return 'EMPTY';
  const b = hexToBytes(scriptHex), n = b.length;
  if (b[0]===0x6a) return 'OP_RETURN';
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

// ── P2TR control-block detector ───────────────────────────────────────────────
// Control block layout: <leaf_version|parity: 1 byte> <internal_pubkey: 32 bytes> [<merkle_path: 32 bytes each>...]
// Tapscript leaf version = 0xc0, so first byte is 0xc0 (even) or 0xc1 (odd)
function isControlBlock(hex) {
  if (!hex) return false;
  const byteLen = hex.length / 2;
  if (byteLen < 33) return false;
  if ((byteLen - 33) % 32 !== 0) return false;
  const firstByte = parseInt(hex.slice(0, 2), 16);
  return (firstByte & 0xfe) === 0xc0;
}

function classifyInput(scriptSigHex, scriptSigAsm, witness) {
  // ── P2TR Script Path (Taproot script spend) ──────────────────────────────
  // Witness: [<stack_items...>, <tapscript>, <control_block>]
  // Control block = last item, tapscript = second-to-last
  if (!scriptSigHex && witness.length >= 3 && isControlBlock(witness[witness.length - 1])) {
    const tapscript    = witness[witness.length - 2];
    const stackItems   = witness.slice(0, -2);
    const tapscriptAsm = scriptHexToAsm(tapscript);
    return {
      inputType: 'P2TR Script Path (Taproot)',
      suggestedUnlocking: stackItems.join(' '),
      suggestedLocking:   tapscriptAsm,
      note: 'Taproot script path: stack items from witness as unlocking; tapscript (witness[-2]) decoded as locking. Control block (witness[-1]) omitted — used for Merkle proof only.',
    };
  }
  // ── P2TR Key Path (Taproot key spend) ────────────────────────────────────
  // Witness: [<64-byte-schnorr-sig>]  (single item)
  if (!scriptSigHex && witness.length === 1 && witness[0].length === 128) {
    return {
      inputType: 'P2TR Key Path (Taproot)',
      suggestedUnlocking: witness[0],
      suggestedLocking:   '',
      note: 'Taproot key path spend: single 64-byte Schnorr signature in witness. The actual validation is implicit — paste the ScriptPubKey (<tweaked_pubkey> OP_CHECKSIG) from the previous output to simulate.',
    };
  }
  if (!scriptSigHex && witness.length === 2 && witness[1].length === 66) {
    let lockHash;
    try { lockHash = computeHash160(witness[1]); } catch { lockHash = null; }
    return {
      inputType: 'P2WPKH (SegWit)',
      suggestedUnlocking: witness.join(' '),
      suggestedLocking: lockHash ? `OP_DUP OP_HASH160 ${lockHash} OP_EQUALVERIFY OP_CHECKSIG` : '',
      note: lockHash
        ? 'SegWit P2WPKH: sig+pubkey from witness; locking script auto-reconstructed from pubkey'
        : 'SegWit P2WPKH input — paste the scriptPubKey from the previous output',
    };
  }
  if (!scriptSigHex && witness.length >= 2) {
    const witnessAsm = scriptHexToAsm(witness[witness.length - 1]);
    return {
      inputType: 'P2WSH (SegWit)',
      suggestedUnlocking: witness.slice(0, -1).join(' '),
      suggestedLocking: witnessAsm,
      note: 'SegWit P2WSH: witness items as unlocking; last witness item (redeemScript) as locking',
    };
  }
  if (!scriptSigHex) {
    return { inputType: 'Coinbase / Unknown', suggestedUnlocking: witness.join(' '), suggestedLocking: '', note: 'Coinbase or unknown input type' };
  }
  const parts = scriptSigAsm.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 2 && /^30[0-9a-f]{2}/.test(parts[0]) &&
      (parts[1].length === 66 || parts[1].length === 130) &&
      (parts[1].startsWith('02') || parts[1].startsWith('03') || parts[1].startsWith('04'))) {
    let lockHash;
    try { lockHash = computeHash160(parts[1]); } catch { lockHash = null; }
    return {
      inputType: 'P2PKH',
      suggestedUnlocking: scriptSigAsm,
      suggestedLocking: lockHash ? `OP_DUP OP_HASH160 ${lockHash} OP_EQUALVERIFY OP_CHECKSIG` : '',
      note: lockHash ? 'P2PKH input: locking script auto-reconstructed from pubkey' : 'P2PKH input — paste the scriptPubKey from the previous output',
    };
  }
  if (parts.length === 1 && /^30[0-9a-f]{2}/.test(parts[0]))
    return { inputType: 'P2PK', suggestedUnlocking: scriptSigAsm, suggestedLocking: '', note: 'P2PK input: paste the scriptPubKey (<pubkey> OP_CHECKSIG) from the previous output' };
  if (parts[0] === 'OP_0' && parts.length >= 2)
    return { inputType: 'P2MS / P2SH', suggestedUnlocking: scriptSigAsm, suggestedLocking: '', note: 'Multisig or P2SH input: paste the locking script from the previous output' };
  return { inputType: 'Unknown', suggestedUnlocking: scriptSigAsm, suggestedLocking: '', note: 'Could not identify input type — paste the locking script from the previous output' };
}

function parseTx(hex) {
  hex = hex.replace(/\s/g, '').toLowerCase();
  if (hex.length < 20)  throw new Error('Input too short — paste a full raw transaction hex');
  if (hex.length % 2)   throw new Error('Odd number of hex characters');
  if (!/^[0-9a-f]+$/.test(hex)) throw new Error('Invalid characters — only hex digits allowed');

  const bytes = hexToBytes(hex);
  let o = 0;

  const version = readLE32(bytes, o); o += 4;
  let isSegwit = false;
  if (bytes[o] === 0x00 && bytes[o+1] === 0x01) { isSegwit = true; o += 2; }

  const icVI = readVarInt(bytes, o); o += icVI.size;
  const inputCount = icVI.value;
  if (inputCount > 500) throw new Error('Unusually high input count — check your hex');

  const inputs = [];
  for (let i = 0; i < inputCount; i++) {
    const prevTxid  = reverseHex(bytesToHex(bytes.slice(o, o+32))); o += 32;
    const prevIndex = readLE32(bytes, o); o += 4;
    const slVI = readVarInt(bytes, o); o += slVI.size;
    const scriptSigHex = bytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;
    const seq = readLE32(bytes, o).toString(16).padStart(8,'0'); o += 4;
    inputs.push({ index: i, prevTxid, prevIndex, scriptSigHex, scriptSigAsm: scriptHexToAsm(scriptSigHex), sequence: seq, witness: [] });
  }

  const ocVI = readVarInt(bytes, o); o += ocVI.size;
  const outputCount = ocVI.value;
  if (outputCount > 5000) throw new Error('Unusually high output count — check your hex');

  const outputs = [];
  for (let i = 0; i < outputCount; i++) {
    const sats = readLE64(bytes, o); o += 8;
    const slVI = readVarInt(bytes, o); o += slVI.size;
    const scriptPubKeyHex = bytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;
    const scriptPubKeyAsm = scriptHexToAsm(scriptPubKeyHex);
    outputs.push({ index: i, sats, btc: (sats/1e8).toFixed(8), scriptPubKeyHex, scriptPubKeyAsm, outputType: detectOutputType(scriptPubKeyHex) });
  }

  if (isSegwit) {
    for (let i = 0; i < inputCount; i++) {
      const wcVI = readVarInt(bytes, o); o += wcVI.size;
      const items = [];
      for (let j = 0; j < wcVI.value; j++) {
        const ilVI = readVarInt(bytes, o); o += ilVI.size;
        items.push(bytesToHex(bytes.slice(o, o+ilVI.value))); o += ilVI.value;
      }
      inputs[i].witness = items;
    }
  }

  const locktime = readLE32(bytes, o);
  for (const inp of inputs) Object.assign(inp, classifyInput(inp.scriptSigHex, inp.scriptSigAsm, inp.witness));

  return { version, isSegwit, inputCount, outputCount, inputs, outputs, locktime, byteSize: hex.length/2 };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  let hex     = String((req.body || {}).hex     ?? '').replace(/^.*--tx=/i,   '').replace(/\s/g, '');
  let txinHex = String((req.body || {}).txinHex ?? '').replace(/^.*--txin=/i, '').replace(/\s/g, '');

  if (!hex) { res.status(400).json({ error: 'hex is required' }); return; }

  try {
    const result = parseTx(hex);
    if (txinHex) {
      const prevTx = parseTx(txinHex);
      for (const inp of result.inputs) {
        const prevOut = prevTx.outputs[inp.prevIndex];
        if (prevOut) {
          inp.suggestedLocking = prevOut.scriptPubKeyAsm;
          inp.inputType        = inp.inputType !== 'Unknown' ? inp.inputType : prevOut.outputType;
          inp.note             = `Locking script pulled from txin output #${inp.prevIndex} (${prevOut.outputType}, ${prevOut.btc} BTC)`;
        }
      }
    }
    res.status(200).json(result);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
}
