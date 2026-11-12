/* ML Flow Detector tab: model info, PCAP analysis, feature-JSON scoring. Uses textContent only. */
(function () {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  };
  const pct = (b) => (b && b.value != null ? (b.value * 100).toFixed(1) + '%' : 'n/a');
  const range = (b) => (b && b.ci95 ? ` (95% CI ${(b.ci95[0] * 100).toFixed(0)}–${(b.ci95[1] * 100).toFixed(0)}%)` : '');

  async function api(path, opts) {
    const res = await fetch('/api/v1' + path, opts);
    let body = null;
    try { body = await res.json(); } catch (e) { /* non-JSON error */ }
    if (!res.ok) throw new Error((body && (body.error || body.detail)) || `HTTP ${res.status}`);
    return body;
  }

  function renderModel(info) {
    const card = $('mlModelCard');
    card.replaceChildren();
    card.append(el('h3', '', 'Trained model'));
    const rows = [
      ['Version', info.version], ['Profile', info.profile], ['Estimator', info.estimator],
      ['Decision threshold', info.threshold], ['Features', info.n_features],
      ['Training flows', info.training_samples],
    ];
    const dl = el('dl', 'ml-dl');
    rows.forEach(([k, v]) => { dl.append(el('dt', '', k), el('dd', '', v == null ? '—' : String(v))); });
    card.append(dl);
    const t = info.clean_test;
    if (t) {
      card.append(el('p', 'ml-metric',
        `Held-out test: recall ${pct(t.recall)}${range(t.recall)} · false-positive rate ${pct(t.false_positive_rate)}${range(t.false_positive_rate)}`));
      if (t.caveat) card.append(el('p', 'ml-warn', t.caveat));
    }
    if (info.sklearn_mismatch || info.cicflowmeter_mismatch) {
      card.append(el('p', 'ml-warn', 'Library versions differ from training time; results may shift. Retrain with `veritas-train fit`.'));
    }
    card.append(el('p', 'ml-note', info.limitations));
    $('mlBadge').textContent = info.profile || 'Model';
  }

  function renderResults(data) {
    const box = $('mlResults');
    box.replaceChildren();
    const rows = data.flows || data.results || [];
    const s = data.summary || {};
    box.append(el('p', 'ml-summary', `${s.flows ?? rows.length} flows · ${s.malicious ?? 0} malicious`));
    if (data.note) box.append(el('p', 'ml-note', data.note));
    rows.forEach((r) => {
      const card = el('div', 'ml-flow ' + (r.verdict === 'malicious' ? 'bad' : 'ok'));
      const head = el('div', 'ml-flow-head');
      head.append(el('strong', '', r.flow_id), el('span', 'ml-verdict', `${r.verdict} · ${(r.malicious_probability * 100).toFixed(1)}%`));
      card.append(head);
      if (r.warning) card.append(el('p', 'ml-warn', r.warning));
      (r.top_features || []).forEach((f) => {
        const dir = f.contribution >= 0 ? '→ malicious' : '→ benign';
        card.append(el('div', 'ml-feat', `${f.feature} = ${f.value}  (${dir}, ${f.contribution.toFixed(3)})`));
      });
      box.append(card);
    });
  }

  async function run(btn, fn) {
    const label = btn.textContent;
    btn.disabled = true; btn.textContent = 'Working…';
    try { renderResults(await fn()); }
    catch (e) { const box = $('mlResults'); box.replaceChildren(el('p', 'ml-warn', e.message)); }
    finally { btn.disabled = false; btn.textContent = label; }
  }

  async function loadModel() {
    try { renderModel(await api('/model')); }
    catch (e) { const c = $('mlModelCard'); c.replaceChildren(el('h3', '', 'Trained model'), el('p', 'ml-warn', e.message)); }
  }

  $('mlRefresh').addEventListener('click', loadModel);
  $('mlPcapBtn').addEventListener('click', () => run($('mlPcapBtn'), async () => {
    const f = $('mlPcapFile').files[0];
    if (!f) throw new Error('Choose a .pcap or .pcapng file first.');
    const fd = new FormData(); fd.append('file', f);
    return api('/analyze/pcap', { method: 'POST', body: fd });
  }));
  $('mlJsonBtn').addEventListener('click', () => run($('mlJsonBtn'), async () => {
    let flows;
    try { flows = JSON.parse($('mlJson').value); } catch (e) { throw new Error('That is not valid JSON.'); }
    if (!Array.isArray(flows)) flows = [flows];
    return api('/predict', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ flows }) });
  }));
  $('tabMlBtn').addEventListener('click', loadModel, { once: true });
})();
