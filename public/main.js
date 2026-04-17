/**
 * main.js — Bitcoin Script Debugger Frontend
 * Lab 9 — Digital Currencies and Blockchain
 *
 * Connects to the Node.js backend:
 *   GET  /api/templates  — prebuilt script examples
 *   GET  /api/opcodes    — opcode reference
 *   POST /api/execute    — run script, get step trace
 */

'use strict';

// ─── State ──────────────────────────────────────────────────────────────────

let steps        = [];
let currentStep  = -1;
let playTimer    = null;
let playSpeed    = 700;
let allOpcodes   = [];

// ─── DOM refs ────────────────────────────────────────────────────────────────

const $ = id => document.getElementById(id);

const tplGrid       = $('tplGrid');
const opcodeList    = $('opcodeList');
const unlockInput   = $('unlockingInput');
const lockInput     = $('lockingInput');
const checksigSel   = $('checksigSel');
const execBtn       = $('execBtn');
const execBtnText   = $('execBtnText');
const spinner       = $('spinner');
const noteBox       = $('noteBox');
const noteGap       = $('noteGap');

const tokenRow         = $('tokenRow');
const tokenCountLabel  = $('tokenCountLabel');
const logPanel         = $('logPanel');
const stackContainer   = $('stackContainer');
const stackEmpty       = $('stackEmpty');
const stackDepthLabel  = $('stackDepthLabel');
const altStackItems    = $('altStackItems');
const resultBanner     = $('resultBanner');
const resultIcon       = $('resultIcon');
const resultText       = $('resultText');
const resultDetail     = $('resultDetail');

const stepCounter      = $('stepCounter');
const stepStatusBadge  = $('stepStatusBadge');
const stepStatusIcon   = $('stepStatusIcon');
const stepStatusText   = $('stepStatusText');
const stepDescText     = $('stepDescText');
const progressFill     = $('progressFill');
const stepLabel        = $('stepLabel');
const tokenLabel       = $('tokenLabel');

const btnFirst = $('btnFirst');
const btnPrev  = $('btnPrev');
const btnPlay  = $('btnPlay');
const btnNext  = $('btnNext');
const btnLast  = $('btnLast');

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  await Promise.all([loadTemplates(), loadOpcodes()]);
  updateControls();
}

// ─── Templates ────────────────────────────────────────────────────────────────

async function loadTemplates() {
  try {
    const res  = await fetch('/api/templates');
    const list = await res.json();
    renderTemplates(list);
  } catch {
    tplGrid.innerHTML = '<span style="color:var(--red);font-size:11px">Failed to load templates</span>';
  }
}

function renderTemplates(list) {
  const typeColor = { Legacy: 'badge-orange', SegWit: 'badge-blue', Taproot: 'badge-taproot', Puzzle: 'badge-purple', Advanced: 'badge-yellow' };
  tplGrid.innerHTML = '';
  list.forEach(tpl => {
    const btn = document.createElement('button');
    btn.className    = 'tpl-btn';
    btn.dataset.id   = tpl.id;
    btn.innerHTML    = `${tpl.name.split('—')[0].trim()}<span class="tpl-type badge ${typeColor[tpl.type] || 'badge-blue'}">${tpl.type}</span>`;
    btn.title        = tpl.description || '';
    btn.onclick      = () => selectTemplate(tpl, btn);
    tplGrid.appendChild(btn);
  });
}

function selectTemplate(tpl, btn) {
  // Highlight active
  tplGrid.querySelectorAll('.tpl-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');

  unlockInput.value  = tpl.unlocking || '';
  lockInput.value    = tpl.locking   || '';

  if (tpl.note) {
    noteBox.textContent = tpl.note;
    noteBox.classList.remove('hidden');
    noteGap.style.display = '';
  } else {
    noteBox.classList.add('hidden');
    noteGap.style.display = 'none';
  }

  // Reset display
  resetDisplay();
  showToast(`Loaded: ${tpl.name}`);
}

// ─── Opcode Reference ─────────────────────────────────────────────────────────

async function loadOpcodes() {
  try {
    const res  = await fetch('/api/opcodes');
    allOpcodes = await res.json();
    renderOpcodes(allOpcodes);
  } catch {
    opcodeList.innerHTML = '<span style="color:var(--red);font-size:11px">Failed to load opcodes</span>';
  }
}

function renderOpcodes(list) {
  opcodeList.innerHTML = '';
  list.forEach(({ op, desc }) => {
    const row  = document.createElement('div');
    row.className = 'opcode-row';
    row.innerHTML = `<span class="opcode-name">${escHtml(op)}</span><span class="opcode-desc">${escHtml(desc)}</span>`;
    opcodeList.appendChild(row);
  });
}

function filterOpcodes(q) {
  const term = q.toLowerCase();
  const filtered = allOpcodes.filter(({ op, desc }) =>
    op.toLowerCase().includes(term) || desc.toLowerCase().includes(term)
  );
  renderOpcodes(filtered);
}

// ─── Execute ──────────────────────────────────────────────────────────────────

async function runScript() {
  const unlocking = unlockInput.value.trim();
  const locking   = lockInput.value.trim();

  if (!locking) { showToast('Enter a locking script first'); return; }

  stopPlay();
  setLoading(true);
  resetDisplay();

  try {
    const res  = await fetch('/api/execute', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ unlocking, locking, checksigResult: checksigSel.value }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const result = await res.json();
    loadResult(result);
  } catch (e) {
    showToast(`Error: ${e.message}`);
  } finally {
    setLoading(false);
  }
}

function loadResult(result) {
  steps = result.steps || [];

  // ── Token row ───────────────────────────────────────────────
  tokenRow.innerHTML = '';
  if (result.tokens && result.tokens.length) {
    tokenCountLabel.textContent = `${result.tokens.length} token${result.tokens.length !== 1 ? 's' : ''}`;
    result.tokens.forEach((tok, i) => {
      if (tok.type === 'boundary') {
        const sep = document.createElement('span');
        sep.className   = 'token boundary-marker';
        sep.textContent = '│';
        tokenRow.appendChild(sep);
        return;
      }
      const el = document.createElement('span');
      el.className = `token token-${tok.type || 'label'}`;
      el.dataset.idx  = i;
      el.textContent  = tok.value;
      el.title        = tok.desc || '';
      tokenRow.appendChild(el);
    });
  } else {
    tokenCountLabel.textContent = 'No tokens';
  }

  // ── Execution log ────────────────────────────────────────────
  logPanel.innerHTML = '';
  steps.forEach((s, i) => {
    const row = document.createElement('div');
    row.className  = 'log-entry';
    row.dataset.idx = i;
    row.onclick    = () => goStep(i);
    row.innerHTML  = `
      <span class="log-idx">${i + 1}</span>
      <span class="log-icon status-${s.status || 'ok'}">${statusIcon(s.status)}</span>
      <span class="log-token">${escHtml(s.token || '')}</span>
      <span class="log-desc">${escHtml(s.description || '')}</span>`;
    logPanel.appendChild(row);
  });

  if (steps.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'log-entry';
    empty.style.cursor = 'default';
    empty.innerHTML = `<span class="log-idx"></span><span class="log-icon status-ok">○</span><span class="log-token" style="color:var(--text-muted)">No steps to show</span>`;
    logPanel.appendChild(empty);
  }

  currentStep = -1;
  updateControls();

  // Auto-jump to first step
  if (steps.length > 0) {
    goStep(0);
  }

  // Show final result after all steps
  if (result.valid !== undefined) {
    const isValid = result.valid;
    resultBanner.className  = `result-banner ${isValid ? 'valid' : 'invalid'}`;
    resultIcon.textContent  = isValid ? '✅' : '❌';
    resultText.textContent  = isValid ? 'Script VALID — Transaction would be accepted' : 'Script INVALID — Transaction would be rejected';
    resultDetail.textContent = result.reason || '';
  }
}

// ─── Step Navigation ──────────────────────────────────────────────────────────

function goStep(idx) {
  if (steps.length === 0) return;
  if (idx < 0) idx = steps.length - 1;
  idx = Math.max(0, Math.min(idx, steps.length - 1));
  currentStep = idx;
  renderStep(steps[idx], idx);
  updateControls();
}

function nextStep() {
  if (currentStep < steps.length - 1) goStep(currentStep + 1);
  else { stopPlay(); }
}

function prevStep() { goStep(currentStep - 1); }

function togglePlay() {
  if (playTimer) {
    stopPlay();
  } else {
    btnPlay.textContent = '⏸ Pause';
    btnPlay.classList.add('active');
    playTimer = setInterval(() => {
      if (currentStep >= steps.length - 1) { stopPlay(); return; }
      nextStep();
    }, playSpeed);
  }
}

function stopPlay() {
  clearInterval(playTimer);
  playTimer = null;
  btnPlay.textContent = '▶ Auto';
  btnPlay.classList.remove('active');
}

function updateSpeed(val) {
  playSpeed = Number(val);
  $('speedLabel').textContent = `${val} ms`;
  if (playTimer) { stopPlay(); togglePlay(); }
}

// ─── Render a step ────────────────────────────────────────────────────────────

function renderStep(step, idx) {
  if (!step) return;

  // Stack
  const stack = step.stack || [];
  renderStack(stack);
  stackDepthLabel.textContent = `depth: ${stack.length}`;

  // Alt stack
  const altStack = step.altStack || [];
  altStackItems.innerHTML = '';
  if (altStack.length === 0) {
    altStackItems.innerHTML = '<span class="altstack-empty">empty</span>';
  } else {
    altStack.forEach(v => {
      const el = document.createElement('span');
      el.className   = 'altstack-item';
      el.textContent = formatVal(v);
      altStackItems.appendChild(el);
    });
  }

  // Step description
  stepCounter.textContent = `STEP ${idx + 1} / ${steps.length}`;
  stepDescText.textContent = step.description || '';
  stepDescText.style.color = 'var(--text)';

  // Step status badge
  const s = step.status || 'ok';
  stepStatusBadge.style.display = 'inline-flex';
  stepStatusBadge.className  = `step-status-badge badge-${statusColor(s)}`;
  stepStatusIcon.textContent = statusIcon(s);
  stepStatusText.textContent = s.toUpperCase();

  // Token highlight
  tokenRow.querySelectorAll('.token').forEach(el => {
    el.classList.remove('current', 'executed', 'error-token');
    const ti = Number(el.dataset.idx);
    if (ti === step.tokenIndex) {
      el.classList.add(s === 'error' ? 'error-token' : 'current');
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    } else if (ti < step.tokenIndex) {
      el.classList.add('executed');
    }
  });

  // Log entry highlight
  logPanel.querySelectorAll('.log-entry').forEach(el => {
    el.classList.remove('current', 'error');
    if (Number(el.dataset.idx) === idx) {
      el.classList.add('current');
      if (s === 'error') el.classList.add('error');
      el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  });

  // Progress bar
  const pct = steps.length > 1 ? (idx / (steps.length - 1)) * 100 : 100;
  progressFill.style.width = `${pct}%`;
  stepLabel.textContent    = `Step ${idx + 1}/${steps.length}`;
  tokenLabel.textContent   = step.token ? `Token: ${step.token}` : '';

  // Result banner: only show on last step
  if (idx === steps.length - 1) {
    resultBanner.classList.remove('hidden');
  } else {
    resultBanner.classList.add('hidden');
  }
}

function renderStack(stack) {
  stackContainer.innerHTML = '';
  if (stack.length === 0) {
    stackContainer.appendChild(stackEmpty);
    stackEmpty.style.display = '';
    return;
  }
  stackEmpty.style.display = 'none';

  // Render top-first (stack[last] = top)
  const reversed = [...stack].reverse();
  reversed.forEach((val, i) => {
    const el  = document.createElement('div');
    const top = i === 0;
    el.className = `stack-item${top ? ' top' : ''}`;

    const valStr  = formatVal(val);
    const valClass = classifyVal(val);

    el.innerHTML = `
      <span class="stack-item-val ${valClass}">${escHtml(valStr)}</span>
      <span class="stack-idx">${top ? 'TOP' : `[${stack.length - 1 - i}]`}</span>`;
    stackContainer.appendChild(el);
  });
}

// ─── Controls state ───────────────────────────────────────────────────────────

function updateControls() {
  const hasSteps = steps.length > 0;
  const atFirst  = currentStep <= 0;
  const atLast   = currentStep >= steps.length - 1;

  btnFirst.disabled = !hasSteps || atFirst;
  btnPrev.disabled  = !hasSteps || atFirst;
  btnNext.disabled  = !hasSteps || atLast;
  btnLast.disabled  = !hasSteps || atLast;
  btnPlay.disabled  = !hasSteps;
}

// ─── Reset ────────────────────────────────────────────────────────────────────

function resetDisplay() {
  stopPlay();
  steps       = [];
  currentStep = -1;

  tokenRow.innerHTML       = '<span style="color:var(--text-muted);font-size:12px;font-family:var(--mono)">Load a template or enter a script and click Execute.</span>';
  tokenCountLabel.textContent = 'No script loaded';
  logPanel.innerHTML       = '<div class="log-entry" style="cursor:default"><span class="log-idx"></span><span class="log-icon status-initial">○</span><span class="log-token" style="color:var(--text-muted)">Execute a script to see the log</span></div>';
  stackContainer.innerHTML = '';
  stackContainer.appendChild(stackEmpty);
  stackEmpty.style.display = '';
  stackDepthLabel.textContent = 'depth: 0';
  altStackItems.innerHTML  = '<span class="altstack-empty">empty</span>';
  resultBanner.className   = 'result-banner hidden';
  stepCounter.textContent  = 'STEP 0 / 0';
  stepStatusBadge.style.display = 'none';
  stepDescText.textContent = 'Execute a script to start debugging.';
  stepDescText.style.color = 'var(--text-muted)';
  progressFill.style.width = '0%';
  stepLabel.textContent    = '–';
  tokenLabel.textContent   = '–';

  updateControls();
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function setLoading(on) {
  execBtn.disabled          = on;
  spinner.className         = on ? 'spinner show' : 'spinner';
  execBtnText.textContent   = on ? 'Executing…' : '▶ Execute Script';
}

function formatVal(v) {
  if (v === null || v === undefined) return '(empty)';
  if (typeof v === 'boolean') return v ? 'true (1)' : 'false (0)';
  if (typeof v === 'number')  return String(v);
  const s = String(v);
  // Truncate long hex
  if (/^[0-9a-f]+$/i.test(s) && s.length > 24) {
    return s.slice(0, 12) + '…' + s.slice(-8);
  }
  return s;
}

function classifyVal(v) {
  if (v === null || v === undefined || v === '' || v === '00') return 'empty-val';
  if (v === true  || v === 1 || v === '01') return 'bool-true';
  if (v === false || v === 0 || v === '00') return 'bool-false';
  if (typeof v === 'number') return 'num-val';
  return '';
}

function statusIcon(s) {
  const map = {
    push:    '→',
    ok:      '✓',
    success: '✓',
    warning: '⚠',
    error:   '✗',
    skipped: '—',
    initial: '○',
  };
  return map[s] || '·';
}

function statusColor(s) {
  const map = { push: 'blue', ok: 'blue', success: 'green', warning: 'yellow', error: 'red', skipped: '' };
  return map[s] || 'blue';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

let toastTimer;
function showToast(msg, dur = 2800) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), dur);
}

// ─── Keyboard shortcuts ───────────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  // Don't fire when typing in inputs
  if (e.target.tagName === 'TEXTAREA' || e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT') return;

  if (e.key === 'ArrowRight' || e.key === 'n') { e.preventDefault(); nextStep(); }
  if (e.key === 'ArrowLeft'  || e.key === 'p') { e.preventDefault(); prevStep(); }
  if (e.key === ' ')                            { e.preventDefault(); togglePlay(); }
  if (e.key === 'Home')                         { e.preventDefault(); goStep(0); }
  if (e.key === 'End')                          { e.preventDefault(); goStep(-1); }
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); runScript(); }
});

// ─── Raw Transaction Decode ───────────────────────────────────────────────────

async function fetchByTxid() {
  const spendingTxid = $('spendingTxid').value.trim();
  const prevTxid     = $('prevTxid').value.trim();
  const network      = $('networkSel').value;

  if (!spendingTxid) { showToast('Enter the spending TxID first'); return; }
  if (!/^[0-9a-fA-F]{64}$/.test(spendingTxid)) { showToast('Spending TxID must be 64 hex characters'); return; }
  if (prevTxid && !/^[0-9a-fA-F]{64}$/.test(prevTxid)) { showToast('Previous TxID must be 64 hex characters'); return; }

  const btn  = $('fetchBtnText');
  const spin = $('fetchSpinner');
  btn.textContent = 'Fetching…';
  spin.className  = 'spinner show';
  $('txResult').style.display = 'none';

  try {
    // Fetch both in parallel when prevTxid is provided
    const fetches = [fetchTxHex(spendingTxid, network)];
    if (prevTxid) fetches.push(fetchTxHex(prevTxid, network));

    const [hex, txinHex = ''] = await Promise.all(fetches);

    // Show the fetched hex in the textarea for reference
    $('rawTxInput').value = hex;

    // Parse via existing endpoint
    const res  = await fetch('/api/parse-tx', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ hex, txinHex }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);

    renderParsedTx(data);
    showToast(`Fetched from ${network} ✓`);
  } catch (e) {
    showToast(`Error: ${e.message}`, 5000);
  } finally {
    btn.textContent = '🔍 Fetch & Decode';
    spin.className  = 'spinner';
  }
}

async function fetchTxHex(txid, network) {
  const res  = await fetch('/api/fetch-tx', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ txid, network }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data.hex;
}

async function parseTx() {
  const raw = $('rawTxInput').value.trim();
  if (!raw) { showToast('Paste a raw transaction hex first'); return; }

  // Extract tx= and optional txin= from btcdeb-style input
  let hex     = raw.replace(/\s/g, '');
  let txinHex = '';

  const txMatch   = raw.match(/(?:--)?tx=([0-9a-fA-F]+)/i);
  const txinMatch = raw.match(/(?:--)?txin=([0-9a-fA-F]+)/i);
  if (txMatch)   hex     = txMatch[1];
  if (txinMatch) txinHex = txinMatch[1];

  const btn  = $('txBtnText');
  const spin = $('txSpinner');
  btn.textContent  = 'Parsing…';
  spin.className   = 'spinner show';
  $('txResult').style.display = 'none';

  try {
    const res  = await fetch('/api/parse-tx', {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ hex, txinHex }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
    renderParsedTx(data);
  } catch (e) {
    showToast(`Parse error: ${e.message}`, 4000);
  } finally {
    btn.textContent = '⚡ Parse Transaction';
    spin.className  = 'spinner';
  }
}

function renderParsedTx(tx) {
  const el = $('txResult');

  const typeColor = {
    P2PKH:'#f97316', 'P2PKH (SegWit)':'#3b82f6', 'P2WPKH (SegWit)':'#3b82f6',
    P2PK:'#f97316', P2SH:'#f97316', P2WPKH:'#3b82f6', P2WSH:'#3b82f6',
    P2TR:'#a855f7', 'P2TR Key Path (Taproot)':'#a855f7', 'P2TR Script Path (Taproot)':'#7c3aed',
    'OP_RETURN':'#eab308', 'P2MS / P2SH':'#f97316',
  };
  const badgeStyle = type => {
    const c = typeColor[type] || '#6b7280';
    return `display:inline-block;padding:1px 6px;border-radius:4px;font-size:10px;font-weight:700;font-family:var(--mono);background:${c}22;color:${c};border:1px solid ${c}44`;
  };

  const shortHex = h => h.length > 24 ? h.slice(0,10)+'…'+h.slice(-8) : h;
  const truncAsm = s => {
    if (!s) return '<span style="color:var(--text-muted);font-style:italic">empty</span>';
    if (s.length > 60) return escHtml(s.slice(0, 57)) + '…';
    return escHtml(s);
  };

  let html = `
    <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;font-family:var(--mono)">
      v${tx.version} &nbsp;·&nbsp; ${tx.inputCount} input${tx.inputCount!==1?'s':''} &nbsp;·&nbsp; ${tx.outputCount} output${tx.outputCount!==1?'s':''}
      &nbsp;·&nbsp; ${tx.byteSize} bytes ${tx.isSegwit ? '&nbsp;<span style="color:#3b82f6">SegWit</span>' : ''}
    </div>`;

  // Inputs
  html += `<div style="font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--text-muted);margin-bottom:6px">Inputs</div>`;
  for (const inp of tx.inputs) {
    const canDebug = !!(inp.suggestedUnlocking || inp.suggestedLocking);
    html += `
      <div style="background:var(--panel-bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin-bottom:6px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="font-size:11px;font-weight:600;font-family:var(--mono);color:var(--text-muted)">
            Input #${inp.index} &nbsp;←&nbsp; <span title="${inp.prevTxid}">${shortHex(inp.prevTxid)}:${inp.prevIndex}</span>
          </span>
          <span style="${badgeStyle(inp.inputType)}">${escHtml(inp.inputType)}</span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);font-family:var(--mono);margin-bottom:6px">
          ${inp.scriptSigAsm ? truncAsm(inp.scriptSigAsm) : (inp.witness.length ? `witness[${inp.witness.length}]` : 'no scriptSig')}
        </div>
        ${canDebug
          ? `<button onclick='loadScriptsForDebug(${JSON.stringify(inp.suggestedUnlocking)},${JSON.stringify(inp.suggestedLocking)},${JSON.stringify('Input #'+inp.index+' — '+inp.inputType)})'
               style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;background:var(--accent);color:#fff;border:none;font-weight:600">
               ▶ Debug this input
             </button>`
          : `<span style="font-size:11px;color:var(--text-muted);font-style:italic">${escHtml(inp.note || 'Cannot debug — locking script unknown')}</span>`
        }
      </div>`;
  }

  // Outputs
  html += `<div style="font-size:11px;font-weight:700;letter-spacing:.6px;text-transform:uppercase;color:var(--text-muted);margin:8px 0 6px">Outputs</div>`;
  for (const out of tx.outputs) {
    html += `
      <div style="background:var(--panel-bg);border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin-bottom:6px">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">
          <span style="font-size:11px;font-weight:600;font-family:var(--mono);color:var(--text-muted)">Output #${out.index}</span>
          <span style="display:flex;gap:6px;align-items:center">
            <span style="font-size:11px;font-family:var(--mono);color:var(--text)">${out.btc} BTC</span>
            <span style="${badgeStyle(out.outputType)}">${escHtml(out.outputType)}</span>
          </span>
        </div>
        <div style="font-size:11px;color:var(--text-muted);font-family:var(--mono);margin-bottom:6px">${truncAsm(out.scriptPubKeyAsm)}</div>
        ${out.scriptPubKeyAsm
          ? (() => {
              let debugLocking   = out.scriptPubKeyAsm;
              let debugUnlocking = '';
              let debugNote      = `Output #${out.index} — ${out.outputType} (${out.btc} BTC)`;
              const asmParts     = out.scriptPubKeyAsm.trim().split(/\s+/);

              // P2WPKH: OP_0 <20-byte-hash> → equivalent P2PKH locking script
              if (out.outputType === 'P2WPKH') {
                const hash    = asmParts[1] || '';
                debugLocking  = `OP_DUP OP_HASH160 ${hash} OP_EQUALVERIFY OP_CHECKSIG`;
                debugNote    += ' [SegWit v0 equivalent]';
              }
              // P2TR: OP_1 <32-byte-tweaked-pubkey> → equivalent single-key Schnorr CHECKSIG
              if (out.outputType === 'P2TR') {
                const tweakedPubkey = asmParts[1] || '';
                debugLocking  = `${tweakedPubkey} OP_CHECKSIG`;
                debugNote    += ' [Taproot key path equivalent]';
              }

              // For P2TR outputs show two debug options: key path and explanation
              if (out.outputType === 'P2TR') {
                const tweakedPubkey = asmParts[1] || '';
                const keyPathLock   = `${tweakedPubkey} OP_CHECKSIG`;
                return `
                  <div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center">
                    <button onclick='loadScriptsForDebug("<schnorr_sig>",${JSON.stringify(keyPathLock)},${JSON.stringify(debugNote + ' — Key Path')})'
                      style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;background:#7c3aed;color:#fff;border:none;font-weight:600">
                      ▶ Key Path
                    </button>
                    <span style="font-size:10px;color:var(--text-muted)">Tweaked key: ${tweakedPubkey.slice(0,12)}… · Script path: provide tapscript manually</span>
                  </div>`;
              }

              return `<button onclick='loadScriptsForDebug(${JSON.stringify(debugUnlocking)},${JSON.stringify(debugLocking)},${JSON.stringify(debugNote)})'
               style="font-size:11px;padding:3px 10px;border-radius:5px;cursor:pointer;background:var(--accent);color:#fff;border:none;font-weight:600">
               ▶ Debug this output
             </button>`;
            })()
          : `<span style="font-size:11px;color:var(--text-muted);font-style:italic">No spendable script</span>`
        }
      </div>`;
  }

  el.innerHTML = html;
  el.style.display = 'block';
  showToast(`Parsed: ${tx.inputCount} input${tx.inputCount!==1?'s':''}, ${tx.outputCount} output${tx.outputCount!==1?'s':''}`);
}

function loadScriptsForDebug(unlocking, locking, label) {
  // Clear any active template highlight
  document.querySelectorAll('.tpl-btn').forEach(b => b.classList.remove('active'));

  unlockInput.value = unlocking || '';
  lockInput.value   = locking  || '';

  if (label) {
    noteBox.textContent = label;
    noteBox.classList.remove('hidden');
    noteGap.style.display = '';
  } else {
    noteBox.classList.add('hidden');
    noteGap.style.display = 'none';
  }

  resetDisplay();

  // Auto-execute so the debugger starts immediately
  if (locking) {
    runScript();
  } else {
    showToast(`Loaded: ${label || 'scripts from transaction'}`);
    unlockInput.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

// ─── Start ────────────────────────────────────────────────────────────────────

init();
