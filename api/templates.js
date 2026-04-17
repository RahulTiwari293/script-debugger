import { computeHash160, computeSha256 } from '../interpreter.js';

const FAKE_PUBKEY  = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const FAKE_PUBKEY2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const FAKE_PUBKEY3 = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const FAKE_SIG     = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802202222222222222222222222222222222222222222222222222222222222222222220101';
const FAKE_SIG2    = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802203333333333333333333333333333333333333333333333333333333333333333330101';
// Taproot uses 32-byte x-only public keys (no 02/03 prefix) and 64-byte Schnorr signatures
const FAKE_XONLY_PUBKEY  = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const FAKE_XONLY_PUBKEY2 = 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const FAKE_TWEAKED_PUBKEY = 'e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f';
const FAKE_SCHNORR_SIG   = 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca82157f87e6bbf9b899d32d897fcec9c6e7c4b5e3f3b55fbf0078fd5e9e4f26cfb76c';
const FAKE_SCHNORR_SIG2  = 'a1b2c3d4e5f678901234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12';
const HELLO_HEX    = '68656c6c6f';
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
    id: 'p2tr_keypath',
    name: 'P2TR Key Path — Pay to Taproot (SegWit v1)',
    type: 'Taproot',
    description: 'Taproot key path spending (BIP341). The ScriptPubKey is OP_1 <32-byte-tweaked-pubkey>. Spending requires a single 64-byte Schnorr signature. Shown as the equivalent single-key CHECKSIG to simulate the implicit validation.',
    unlocking: FAKE_SCHNORR_SIG,
    locking: `${FAKE_TWEAKED_PUBKEY} OP_CHECKSIG`,
    note: `Real ScriptPubKey: OP_1 <32-byte-tweaked-pubkey>  |  Witness: [<64-byte-schnorr-sig>]  |  Key path: spends directly with a single Schnorr sig against the tweaked internal key. No visible script — all logic hidden in the key tweak.`,
  },
  {
    id: 'p2tr_scriptpath',
    name: 'P2TR Script Path — Tapscript 2-of-2 (SegWit v1)',
    type: 'Taproot',
    description: 'Taproot script path via Tapscript (BIP342). Uses OP_CHECKSIGADD — the new Schnorr multisig accumulator. Unlike legacy OP_CHECKMULTISIG, there is no off-by-one bug. 2-of-2 requires both signatures; uses OP_NUMEQUAL to check the accumulated count.',
    unlocking: `${FAKE_SCHNORR_SIG2} ${FAKE_SCHNORR_SIG}`,
    locking: `${FAKE_XONLY_PUBKEY} OP_CHECKSIG ${FAKE_XONLY_PUBKEY2} OP_CHECKSIGADD OP_2 OP_NUMEQUAL`,
    note: `Tapscript 2-of-2: <sig1> <sig2> | <pk1> OP_CHECKSIG pushes 0 or 1; <pk2> OP_CHECKSIGADD adds to counter; OP_2 OP_NUMEQUAL checks counter == 2. No dummy OP_0 needed (legacy bug fixed).`,
  },
  {
    id: 'p2tr_scriptpath_threshold',
    name: 'P2TR Script Path — Tapscript 2-of-3 Threshold (SegWit v1)',
    type: 'Taproot',
    description: 'Tapscript 2-of-3 threshold signature using OP_CHECKSIGADD. Any 2 of 3 keys can sign. Non-signing keys provide empty signatures. OP_NUMEQUAL checks the accumulated valid signature count.',
    unlocking: `${FAKE_SCHNORR_SIG} ${FAKE_SCHNORR_SIG2} ""`,
    locking: `${FAKE_XONLY_PUBKEY} OP_CHECKSIG ${FAKE_XONLY_PUBKEY2} OP_CHECKSIGADD ${FAKE_TWEAKED_PUBKEY} OP_CHECKSIGADD OP_2 OP_NUMEQUAL`,
    note: 'Tapscript 2-of-3: non-signing key provides empty string (""); OP_CHECKSIGADD accumulates count; OP_2 OP_NUMEQUAL verifies exactly 2 valid sigs.',
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

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'GET') { res.status(405).json({ error: 'Method not allowed' }); return; }
  res.status(200).json(TEMPLATES);
}
