// Try multiple block explorer APIs in order — if one fails, fall through to the next
const EXPLORERS = {
  mainnet: [
    id => `https://blockstream.info/api/tx/${id}/hex`,
    id => `https://mempool.space/api/tx/${id}/hex`,
  ],
  testnet: [
    id => `https://blockstream.info/testnet/api/tx/${id}/hex`,
    id => `https://mempool.space/testnet/api/tx/${id}/hex`,
  ],
};

async function fetchWithTimeout(url, ms = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    return await fetch(url, {
      signal: controller.signal,
      headers: { 'User-Agent': 'bitcoin-script-debugger/1.0' },
    });
  } finally {
    clearTimeout(timer);
  }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  const { txid = '', network = 'mainnet' } = req.body || {};
  const id  = String(txid).trim();
  const net = String(network) === 'testnet' ? 'testnet' : 'mainnet';

  if (!id || !/^[0-9a-fA-F]{64}$/.test(id)) {
    res.status(400).json({ error: 'Invalid txid — must be 64 hex characters' });
    return;
  }

  const urls = EXPLORERS[net];
  let lastError = '';

  for (const buildUrl of urls) {
    const url = buildUrl(id);
    try {
      const resp = await fetchWithTimeout(url);

      if (resp.status === 404) {
        // Definitive not found — no point trying other explorers
        res.status(404).json({ error: `Transaction not found on ${net}: ${id}` });
        return;
      }

      if (!resp.ok) {
        lastError = `HTTP ${resp.status} from ${new URL(url).hostname}`;
        continue; // try next explorer
      }

      const hex = (await resp.text()).trim();
      if (!/^[0-9a-fA-F]+$/.test(hex)) {
        lastError = `Invalid hex response from ${new URL(url).hostname}`;
        continue;
      }

      res.status(200).json({ hex });
      return;

    } catch (e) {
      lastError = e.name === 'AbortError'
        ? `Timeout reaching ${new URL(url).hostname}`
        : e.message;
      // try next explorer
    }
  }

  res.status(502).json({ error: `Could not fetch transaction: ${lastError}` });
}
