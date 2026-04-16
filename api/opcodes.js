import { OPCODE_DESCRIPTIONS } from '../interpreter.js';

export default function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'GET') { res.status(405).json({ error: 'Method not allowed' }); return; }
  const list = Object.entries(OPCODE_DESCRIPTIONS).map(([op, desc]) => ({ op, desc }));
  res.status(200).json(list);
}
