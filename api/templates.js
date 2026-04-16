import { computeHash160, computeSha256 } from '../interpreter.js';

const FAKE_PUBKEY  = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const FAKE_PUBKEY2 = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';
const FAKE_PUBKEY3 = '02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const FAKE_SIG     = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802202222222222222222222222222222222222222222222222222222222222222222220101';
const FAKE_SIG2    = '3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802203333333333333333333333333333333333333333333333333333333333333333330101';
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
