export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  const { txid = '', network = 'mainnet' } = req.body || {};
  const id = String(txid).trim();

  if (!id || !/^[0-9a-fA-F]{64}$/.test(id)) {
    res.status(400).json({ error: 'Invalid txid — must be 64 hex characters' });
    return;
  }

  const base = String(network) === 'testnet'
    ? 'https://blockstream.info/testnet/api'
    : 'https://blockstream.info/api';

  try {
    const resp = await fetch(`${base}/tx/${id}/hex`, { signal: AbortSignal.timeout(10000) });
    if (resp.status === 404) {
      res.status(404).json({ error: `Transaction not found on ${network}: ${id}` });
      return;
    }
    if (!resp.ok) {
      res.status(502).json({ error: `Blockstream API error: HTTP ${resp.status}` });
      return;
    }
    const hex = (await resp.text()).trim();
    res.status(200).json({ hex });
  } catch (e) {
    res.status(502).json({ error: `Failed to fetch transaction: ${e.message}` });
  }
}
