import { executeScript, parseScript, OPCODE_DESCRIPTIONS } from '../interpreter.js';

function shapeExecuteResult(raw, unlocking, locking) {
  const unlockTokens = parseScript(unlocking);
  const lockTokens   = parseScript(locking);
  const boundary     = unlockTokens.length;

  const tokens = [];
  for (const t of unlockTokens)
    tokens.push({ type: t.type, value: t.raw, desc: OPCODE_DESCRIPTIONS[t.value.toUpperCase()] || '' });
  tokens.push({ type: 'boundary', value: '│' });
  for (const t of lockTokens)
    tokens.push({ type: t.type, value: t.raw, desc: OPCODE_DESCRIPTIONS[t.value.toUpperCase()] || '' });

  const steps = raw.steps.map(s => ({
    ...s,
    stack:      s.stackAfter || [],
    altStack:   s.altAfter   || [],
    token:      s.tokenRaw   ?? '',
    tokenIndex: s.index < 0 ? -1 : s.index < boundary ? s.index : s.index + 1,
  }));

  return { ...raw, tokens, steps, reason: raw.error || '' };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  const { unlocking = '', locking = '', checksigResult = 'valid' } = req.body || {};

  if (!locking) { res.status(400).json({ error: 'locking script is required' }); return; }

  try {
    const raw    = executeScript(String(unlocking).trim(), String(locking).trim(), { checksigResult: String(checksigResult) });
    const result = shapeExecuteResult(raw, String(unlocking).trim(), String(locking).trim());
    res.status(200).json(result);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
