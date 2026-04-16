/**
 * parser.js — Client-side Bitcoin Raw Transaction Parser
 * Decodes raw hex transactions, extracts scripts, identifies types.
 * No dependencies — pure vanilla JS.
 */

'use strict';

(function (window) {

  // ─── Opcode map ────────────────────────────────────────────────────────────

  const OPCODE_MAP = {
    0x00:'OP_0', 0x4c:'OP_PUSHDATA1', 0x4d:'OP_PUSHDATA2', 0x4e:'OP_PUSHDATA4',
    0x4f:'OP_1NEGATE',
    0x51:'OP_1',  0x52:'OP_2',  0x53:'OP_3',  0x54:'OP_4',
    0x55:'OP_5',  0x56:'OP_6',  0x57:'OP_7',  0x58:'OP_8',
    0x59:'OP_9',  0x5a:'OP_10', 0x5b:'OP_11', 0x5c:'OP_12',
    0x5d:'OP_13', 0x5e:'OP_14', 0x5f:'OP_15', 0x60:'OP_16',
    0x61:'OP_NOP', 0x63:'OP_IF', 0x64:'OP_NOTIF', 0x67:'OP_ELSE', 0x68:'OP_ENDIF',
    0x69:'OP_VERIFY', 0x6a:'OP_RETURN',
    0x6b:'OP_TOALTSTACK', 0x6c:'OP_FROMALTSTACK',
    0x6d:'OP_2DROP', 0x6e:'OP_2DUP', 0x6f:'OP_3DUP',
    0x70:'OP_2OVER', 0x71:'OP_2ROT', 0x72:'OP_2SWAP',
    0x73:'OP_IFDUP', 0x74:'OP_DEPTH', 0x75:'OP_DROP', 0x76:'OP_DUP',
    0x77:'OP_NIP', 0x78:'OP_OVER', 0x79:'OP_PICK', 0x7a:'OP_ROLL',
    0x7b:'OP_ROT', 0x7c:'OP_SWAP', 0x7d:'OP_TUCK',
    0x82:'OP_SIZE',
    0x87:'OP_EQUAL', 0x88:'OP_EQUALVERIFY',
    0x8b:'OP_1ADD', 0x8c:'OP_1SUB',
    0x8f:'OP_NEGATE', 0x90:'OP_ABS', 0x91:'OP_NOT', 0x92:'OP_0NOTEQUAL',
    0x93:'OP_ADD', 0x94:'OP_SUB',
    0x9a:'OP_BOOLAND', 0x9b:'OP_BOOLOR',
    0x9c:'OP_NUMEQUAL', 0x9d:'OP_NUMEQUALVERIFY', 0x9e:'OP_NUMNOTEQUAL',
    0x9f:'OP_LESSTHAN', 0xa0:'OP_GREATERTHAN',
    0xa1:'OP_LESSTHANOREQUAL', 0xa2:'OP_GREATERTHANOREQUAL',
    0xa3:'OP_MIN', 0xa4:'OP_MAX', 0xa5:'OP_WITHIN',
    0xa6:'OP_RIPEMD160', 0xa7:'OP_SHA1', 0xa8:'OP_SHA256',
    0xa9:'OP_HASH160', 0xaa:'OP_HASH256',
    0xab:'OP_CODESEPARATOR',
    0xac:'OP_CHECKSIG', 0xad:'OP_CHECKSIGVERIFY',
    0xae:'OP_CHECKMULTISIG', 0xaf:'OP_CHECKMULTISIGVERIFY',
    0xb1:'OP_CHECKLOCKTIMEVERIFY', 0xb2:'OP_CHECKSEQUENCEVERIFY',
  };

  // ─── Byte utilities ────────────────────────────────────────────────────────

  function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
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
    const lo = ((b[o] | (b[o+1]<<8) | (b[o+2]<<16) | (b[o+3]<<24)) >>> 0);
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

  // ─── Script → ASM ──────────────────────────────────────────────────────────

  function scriptHexToAsm(scriptHex) {
    if (!scriptHex) return '';
    const bytes = hexToBytes(scriptHex);
    const tokens = [];
    let i = 0;

    while (i < bytes.length) {
      const op = bytes[i];

      if (op === 0x00) { tokens.push('OP_0'); i++; }
      else if (op >= 0x01 && op <= 0x4b) {
        tokens.push(bytesToHex(bytes.slice(i+1, i+1+op)));
        i += 1 + op;
      }
      else if (op === 0x4c) {
        const n = bytes[i+1];
        tokens.push(bytesToHex(bytes.slice(i+2, i+2+n)));
        i += 2 + n;
      }
      else if (op === 0x4d) {
        const n = bytes[i+1] | (bytes[i+2]<<8);
        tokens.push(bytesToHex(bytes.slice(i+3, i+3+n)));
        i += 3 + n;
      }
      else if (op === 0x4e) {
        const n = readLE32(bytes, i+1);
        tokens.push(bytesToHex(bytes.slice(i+5, i+5+n)));
        i += 5 + n;
      }
      else {
        tokens.push(OPCODE_MAP[op] || `OP_UNKNOWN(0x${op.toString(16).padStart(2,'0')})`);
        i++;
      }
    }
    return tokens.join(' ');
  }

  // ─── Script type detection ──────────────────────────────────────────────────

  function detectScriptType(scriptHex) {
    if (!scriptHex || scriptHex.length === 0)
      return { type:'EMPTY', label:'Empty', color:'muted', desc:'No script data', icon:'○' };

    const b = hexToBytes(scriptHex);
    const n = b.length;

    // OP_RETURN
    if (b[0] === 0x6a)
      return { type:'OP_RETURN', label:'OP_RETURN', color:'yellow', desc:'Unspendable data carrier — embeds arbitrary data in blockchain', icon:'⛔' };

    // P2PKH: 76 a9 14 <20> 88 ac
    if (n===25 && b[0]===0x76 && b[1]===0xa9 && b[2]===0x14 && b[23]===0x88 && b[24]===0xac)
      return { type:'P2PKH', label:'P2PKH', color:'orange', desc:'Pay to Public Key Hash — most common legacy format', icon:'🔑' };

    // P2SH: a9 14 <20> 87
    if (n===23 && b[0]===0xa9 && b[1]===0x14 && b[22]===0x87)
      return { type:'P2SH', label:'P2SH', color:'orange', desc:'Pay to Script Hash — legacy script wrapping', icon:'📜' };

    // P2PK uncompressed: 41 <65> ac
    if (n===67 && b[0]===0x41 && b[66]===0xac)
      return { type:'P2PK', label:'P2PK', color:'orange', desc:'Pay to Public Key — early Bitcoin format (uncompressed pubkey)', icon:'🗝️' };

    // P2PK compressed: 21 <33> ac
    if (n===35 && b[0]===0x21 && b[34]===0xac)
      return { type:'P2PK', label:'P2PK', color:'orange', desc:'Pay to Public Key — early Bitcoin format (compressed pubkey)', icon:'🗝️' };

    // P2WPKH: 00 14 <20>
    if (n===22 && b[0]===0x00 && b[1]===0x14)
      return { type:'P2WPKH', label:'P2WPKH', color:'blue', desc:'Pay to Witness Public Key Hash — SegWit v0', icon:'⚡' };

    // P2WSH: 00 20 <32>
    if (n===34 && b[0]===0x00 && b[1]===0x20)
      return { type:'P2WSH', label:'P2WSH', color:'blue', desc:'Pay to Witness Script Hash — SegWit v0 multisig', icon:'⚡' };

    // P2TR: 51 20 <32>
    if (n===34 && b[0]===0x51 && b[1]===0x20)
      return { type:'P2TR', label:'P2TR', color:'purple', desc:'Pay to Taproot — SegWit v1 (Schnorr signatures)', icon:'🌿' };

    // P2MS: OP_M <pubkeys...> OP_N OP_CHECKMULTISIG
    if (b[n-1]===0xae && b[0]>=0x51 && b[0]<=0x60 && b[n-2]>=0x51 && b[n-2]<=0x60) {
      const m = b[0] - 0x50, k = b[n-2] - 0x50;
      return { type:'P2MS', label:`P2MS ${m}-of-${k}`, color:'orange', desc:`${m}-of-${k} Multisig — requires ${m} of ${k} signatures`, icon:'👥' };
    }

    return { type:'UNKNOWN', label:'Non-standard', color:'muted', desc:'Non-standard or unknown script pattern', icon:'?' };
  }

  // ─── Main parser ────────────────────────────────────────────────────────────

  function parseRawTx(hex) {
    hex = hex.replace(/\s|\n/g, '').toLowerCase();

    if (hex.length < 20)  throw new Error('Input too short — paste a full raw transaction hex');
    if (hex.length % 2)   throw new Error('Odd number of hex characters');
    if (!/^[0-9a-f]+$/.test(hex)) throw new Error('Invalid characters — only hex digits allowed');

    const bytes = hexToBytes(hex);
    let o = 0;

    // Version
    const version = readLE32(bytes, o); o += 4;

    // SegWit marker check
    let isSegwit = false;
    if (bytes[o] === 0x00 && bytes[o+1] === 0x01) {
      isSegwit = true; o += 2;
    }

    // Inputs
    const icVI = readVarInt(bytes, o); o += icVI.size;
    const inputCount = icVI.value;
    if (inputCount > 500) throw new Error('Unusually high input count — check your hex');

    const inputs = [];
    for (let i = 0; i < inputCount; i++) {
      const prevTxid = reverseHex(bytesToHex(bytes.slice(o, o+32))); o += 32;
      const prevIndex = readLE32(bytes, o); o += 4;

      const slVI = readVarInt(bytes, o); o += slVI.size;
      const scriptSigHex = bytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;

      const seq = readLE32(bytes, o).toString(16).padStart(8,'0'); o += 4;

      inputs.push({
        index: i,
        prevTxid,
        prevIndex,
        scriptSigHex,
        scriptSigAsm: scriptHexToAsm(scriptSigHex),
        sequence: seq,
        isCoinbase: prevTxid === '0'.repeat(64),
        witness: [],
      });
    }

    // Outputs
    const ocVI = readVarInt(bytes, o); o += ocVI.size;
    const outputCount = ocVI.value;
    if (outputCount > 5000) throw new Error('Unusually high output count — check your hex');

    const outputs = [];
    for (let i = 0; i < outputCount; i++) {
      const sats = readLE64(bytes, o); o += 8;
      const slVI = readVarInt(bytes, o); o += slVI.size;
      const scriptPubKeyHex = bytesToHex(bytes.slice(o, o+slVI.value)); o += slVI.value;
      const asm = scriptHexToAsm(scriptPubKeyHex);
      const scriptType = detectScriptType(scriptPubKeyHex);

      outputs.push({
        index: i,
        sats,
        btc: (sats / 1e8).toFixed(8),
        scriptPubKeyHex,
        scriptPubKeyAsm: asm,
        scriptType,
      });
    }

    // SegWit witness
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

    return { version, isSegwit, inputCount, outputCount, inputs, outputs, locktime, byteSize: hex.length/2 };
  }

  // ─── Export ─────────────────────────────────────────────────────────────────

  window.BitcoinParser = { parseRawTx, detectScriptType, scriptHexToAsm };

})(window);
