(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const CSRF = $('meta[name="csrf-token"]').content;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const TITLES = {
    overview: 'Overview', url: 'URL Scanner', message: 'Message Scanner', risk: 'Risk Analysis',
    evidence: 'Detection Evidence', history: 'Analysis History', settings: 'Settings',
  };
  const CLASS_LABEL = { phishing: 'Likely phishing', suspicious: 'Suspicious', low_risk: 'Low risk' };
  const state = { report: null, ai: {} }; // ai: analysis_id -> summary result

  // ---------------------------------------------------------------- helpers
  // All dynamic text goes through textContent / text nodes - never innerHTML.
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid !== null && kid !== undefined) el.append(kid);
    return el;
  }

  async function api(path, { method = 'GET', body } = {}) {
    const opts = { method, headers: { Accept: 'application/json' }, credentials: 'same-origin' };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['X-CSRF-Token'] = CSRF;
    }
    if (body !== undefined) opts.body = JSON.stringify(body);
    let res;
    try { res = await fetch(path, opts); } catch (_) { throw new Error('Cannot reach the PhishGuard server.'); }
    let data = null;
    try { data = await res.json(); } catch (_) { /* non-JSON body */ }
    if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status}).`);
    return data;
  }

  function banner(message, info = false) {
    const b = $('#banner');
    b.textContent = message;
    b.classList.toggle('info', info);
    b.classList.remove('hidden');
  }
  const clearBanner = () => $('#banner').classList.add('hidden');

  function gauge(score, level) {
    const r = 52, c = 2 * Math.PI * r;
    const mk = (tag, attrs) => {
      const e = document.createElementNS(SVG_NS, tag);
      for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
      return e;
    };
    const svg = mk('svg', { viewBox: '0 0 140 140', class: `gauge lvl-${level}`, role: 'img',
      'aria-label': `Risk score ${score} out of 100, ${level} risk` });
    svg.append(mk('circle', { cx: 70, cy: 70, r, fill: 'none', 'stroke-width': 12, class: 'track' }));
    const bar = mk('circle', { cx: 70, cy: 70, r, fill: 'none', 'stroke-width': 12, 'stroke-linecap': 'round',
      class: 'bar', transform: 'rotate(-90 70 70)', 'stroke-dasharray': c, 'stroke-dashoffset': c });
    const num = mk('text', { x: 70, y: 78, class: 'num' });
    num.textContent = String(score);
    const sub = mk('text', { x: 70, y: 98, class: 'sub' });
    sub.textContent = 'RISK / 100';
    svg.append(bar, num, sub);
    requestAnimationFrame(() => requestAnimationFrame(() =>
      bar.setAttribute('stroke-dashoffset', String(c * (1 - score / 100)))));
    return svg;
  }

  const badge = (text, level) => h('span', { class: `badge ${level ? 'lvl-' + level : 'plain'}`, text });

  // ---------------------------------------------------------------- navigation
  function show(view) {
    clearBanner();
    $$('.view').forEach((v) => v.classList.toggle('hidden', v.id !== `view-${view}`));
    $$('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
    $('#viewTitle').textContent = TITLES[view];
    $('#sidebar').classList.remove('open');
    $('#menuBtn').setAttribute('aria-expanded', 'false');
    if (view === 'overview') loadOverview();
    if (view === 'history') loadHistory();
    if (view === 'settings') loadSettings();
    if (view === 'risk') renderRisk();
    if (view === 'evidence') renderEvidence();
  }

  // ---------------------------------------------------------------- scanners
  function resultCard(r) {
    const notable = r.evidence.filter((e) => e.severity !== 'low').slice(0, 3);
    return h('div', { class: 'panel' }, h('div', { class: 'result-card' },
      gauge(r.risk_score, r.risk_level),
      h('div', { class: 'meta' },
        h('h3', { text: r.threat_category }),
        h('div', { class: 'badges' }, badge(`${r.risk_level} risk`, r.risk_level), badge(CLASS_LABEL[r.classification])),
        h('p', { text: r.input_type === 'url' ? `Domain: ${r.registered_domain}` : `${r.char_count} characters, ${r.urls.length} link(s) found` }),
        notable.length
          ? h('ul', { class: 'mini-ev' }, notable.map((e) => h('li', { text: `- ${e.label}` })))
          : h('p', { text: 'No strong phishing indicators were found.' }),
        h('div', { class: 'actions' },
          h('button', { class: 'btn primary', onclick: () => show('risk') }, 'Full risk analysis'),
          h('button', { class: 'btn ghost', onclick: () => show('evidence') }, 'Detection evidence')),
        (r.warnings || []).map((w) => h('p', { class: 'warn-note', text: w })),
        h('p', { class: 'tiny', text: r.analysis_id }))));
  }

  async function runScan(kind) {
    const isUrl = kind === 'url';
    const input = $(isUrl ? '#urlInput' : '#msgInput');
    const btn = $(isUrl ? '#urlBtn' : '#msgBtn');
    const out = $(isUrl ? '#urlResult' : '#msgResult');
    clearBanner();
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = 'Analysing...';
    try {
      const report = await api(isUrl ? '/api/analyze/url' : '/api/analyze/message',
        { method: 'POST', body: isUrl ? { url: input.value } : { message: input.value } });
      state.report = report;
      out.replaceChildren(resultCard(report));
    } catch (err) {
      out.replaceChildren(h('div', { class: 'banner', role: 'alert', text: err.message }));
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  }

  // ---------------------------------------------------------------- risk analysis
  function renderRisk() {
    const r = state.report;
    $('#riskEmpty').classList.toggle('hidden', !!r);
    $('#riskBody').classList.toggle('hidden', !r);
    if (!r) return;
    $('#riskGauge').replaceChildren(gauge(r.risk_score, r.risk_level));
    $('#riskBadges').replaceChildren(badge(`${r.risk_level} risk`, r.risk_level), badge(r.threat_category),
      badge(CLASS_LABEL[r.classification]));
    $('#riskId').textContent = r.analysis_id;
    const warn = (r.warnings || []).join(' ');
    $('#riskWarn').textContent = warn;
    $('#riskWarn').classList.toggle('hidden', !warn);

    $('#breakdown').replaceChildren(...r.breakdown.map((b) => {
      const fill = h('i');
      fill.style.width = `${b.max ? Math.min(100, (b.points / b.max) * 100) : 0}%`;
      return h('div', { class: 'bar-row' },
        h('span', { class: 'name', text: b.factor }), h('span', { class: 'pts', text: `${b.points} / ${b.max}` }),
        h('div', { class: 'meter' }, fill), b.note ? h('span', { class: 'note', text: b.note }) : null);
    }));

    const kv = [['Input type', r.input_type],
      ['Model P(phishing)', r.model_probability === null ? 'model unavailable' : r.model_probability.toFixed(3)],
      ['Model confidence', r.model_confidence === null ? 'model unavailable' : r.model_confidence.toFixed(3)],
      ['Final risk score', `${r.risk_score} / 100`]];
    $('#modelKv').replaceChildren(...kv.flatMap(([k, v]) => [h('span', { class: 'k', text: k }), h('span', { class: 'v', text: v })]));
    $('#recoList').replaceChildren(...r.recommendations.map((t) => h('li', { text: t })));

    const cached = state.ai[r.analysis_id];
    if (cached) renderAi(cached); else $('#aiOut').classList.add('hidden');
  }

  function renderAi(res) {
    const out = $('#aiOut');
    const generated = res.status === 'generated';
    out.replaceChildren(
      h('div', { class: `src ${generated ? '' : 'local'}`, text: generated ? `AI-generated explanation (${res.provider})` : 'Local summary' }),
      h('p', { text: res.summary }),
      res.reason ? h('p', { class: 'why', text: res.reason }) : null);
    out.classList.remove('hidden');
  }

  async function generateSummary() {
    const r = state.report;
    if (!r) return;
    const btn = $('#aiBtn');
    btn.disabled = true;
    btn.textContent = 'Generating...';
    try {
      const res = await api('/api/summary', { method: 'POST', body: { analysis_id: r.analysis_id } });
      state.ai[r.analysis_id] = res;
      renderAi(res);
    } catch (err) {
      banner(err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Generate summary';
    }
  }

  // ---------------------------------------------------------------- evidence
  function renderEvidence() {
    const r = state.report;
    $('#evEmpty').classList.toggle('hidden', !!r);
    $('#evBody').classList.toggle('hidden', !r);
    if (!r) return;
    $('#evList').replaceChildren(...(r.evidence.length
      ? r.evidence.map((e) => h('li', {},
        h('span', { class: `sev sev-${e.severity}`, text: e.severity }), h('span', { text: e.label }),
        h('span', { class: 'pts-tag', text: e.points ? `+${e.points}` : '' })))
      : [h('li', {}, h('span'), h('span', { text: 'No indicators were triggered.' }), h('span'))]));
    const links = r.urls || [];
    $('#evLinksPanel').classList.toggle('hidden', r.input_type !== 'message');
    $('#evLinks tbody').replaceChildren(...(links.length
      ? links.map((u) => h('tr', {}, h('td', { text: u.registered_domain }), h('td', { text: String(u.risk_score) }),
        h('td', { class: `lvl-${u.risk_level}` }, h('span', { class: 'lvl-text', text: u.risk_level }))))
      : [h('tr', {}, h('td', { text: 'No links found in this message.' }), h('td'), h('td'))]));
  }

  // ---------------------------------------------------------------- overview / history / settings
  function rows(items, withAction) {
    return items.map((it) => h('tr', {},
      h('td', { text: it.analysis_id }),
      ...(withAction ? [h('td', { text: it.created_at.replace('T', ' ').replace('+00:00', '') })] : []),
      h('td', { text: it.input_type }), h('td', { text: it.input_label, title: it.input_label }),
      h('td', { text: String(it.risk_score) }),
      h('td', { class: `lvl-${it.risk_level}` }, h('span', { class: 'lvl-text', text: it.risk_level })),
      ...(withAction ? [h('td', { text: it.category }),
        h('td', {}, h('button', { class: 'btn ghost', onclick: () => openHistory(it.analysis_id) }, 'View'))] : [])));
  }

  async function loadOverview() {
    try {
      const [s, hist] = await Promise.all([api('/api/stats'), api('/api/history')]);
      $('#statTotal').textContent = String(s.total);
      $('#statFlagged').textContent = String(s.levels.high + s.levels.critical);
      $('#statAvg').textContent = s.avg_score === null ? '-' : String(s.avg_score);
      $('#statTypes').textContent = `${s.types.url} / ${s.types.message}`;
      const max = Math.max(1, ...Object.values(s.levels));
      $('#distChart').replaceChildren(...['low', 'medium', 'high', 'critical'].map((lv) => {
        const fill = h('div', { class: 'fill' });
        fill.style.height = `${s.levels[lv] ? Math.max(6, Math.round(130 * s.levels[lv] / max)) : 3}px`;
        return h('div', { class: `col lvl-${lv}` }, h('span', { class: 'n', text: String(s.levels[lv]) }), fill,
          h('span', { class: 't', text: lv }));
      }));
      const recent = hist.slice(0, 5);
      $('#recentTbl tbody').replaceChildren(...rows(recent, false));
      $('#recentEmpty').classList.toggle('hidden', recent.length > 0);
    } catch (err) { banner(err.message); }
  }

  async function loadHistory() {
    try {
      const hist = await api('/api/history');
      $('#histTbl tbody').replaceChildren(...rows(hist, true));
      $('#histEmpty').classList.toggle('hidden', hist.length > 0);
    } catch (err) { banner(err.message); }
  }

  async function openHistory(id) {
    try {
      const item = await api(`/api/history/${encodeURIComponent(id)}`);
      state.report = item.report;
      if (item.ai_summary) state.ai[id] = item.ai_summary;
      show('risk');
    } catch (err) { banner(err.message); }
  }

  async function clearHistory() {
    if (!window.confirm('Delete all saved analyses? This cannot be undone.')) return;
    try {
      await api('/api/history', { method: 'DELETE' });
      state.report = null;
      state.ai = {};
      $('#urlResult').replaceChildren();
      $('#msgResult').replaceChildren();
      loadHistory();
    } catch (err) { banner(err.message); }
  }

  const yesNo = (v) => h('span', { class: `v ${v ? 'ok-text' : 'warn-text'}`, text: v ? 'Yes' : 'No' });

  async function loadSettings() {
    try {
      const [s, m] = await Promise.all([api('/api/settings'), api('/api/models/status')]);
      const mm = s.models.message_model, um = s.models.url_model;
      $('#setModels').replaceChildren(
        h('span', { class: 'k', text: 'Message model' }), yesNo(mm.loaded),
        h('span', { class: 'k', text: 'Message model status' }), h('span', { class: 'v', text: mm.detail }),
        h('span', { class: 'k', text: 'URL model' }), yesNo(um.loaded),
        h('span', { class: 'k', text: 'URL model status' }), h('span', { class: 'v', text: um.detail }));
      const ai = s.ai;
      $('#setAi').replaceChildren(
        h('span', { class: 'k', text: 'Enabled' }), yesNo(ai.enabled),
        h('span', { class: 'k', text: 'Provider' }), h('span', { class: 'v', text: ai.provider || 'not set' }),
        h('span', { class: 'k', text: 'API key present' }), yesNo(ai.key_present),
        h('span', { class: 'k', text: 'Model name set' }), yesNo(ai.model_set),
        h('span', { class: 'k', text: 'Ready to generate' }), yesNo(ai.ready));
      const ev = m.evaluation;
      $('#setEval').textContent = ev
        ? `Held-out F1 - message: ${ev.message_model.f1}, URL: ${ev.url_model.f1}.` +
          (ev.synthetic_data ? ' Measured on SYNTHETIC seed data; this is not real-world accuracy.' : '')
        : 'No evaluation report found. Run python train.py.';
      const ok = mm.loaded && um.loaded;
      $('#dotModels').className = `dot ${ok ? 'ok' : 'warn'}`;
      $('#txtModels').textContent = ok ? 'Models: loaded' : 'Models: incomplete';
      $('#dotAi').className = `dot ${ai.ready ? 'ok' : 'off'}`;
      $('#txtAi').textContent = ai.ready ? `AI summaries: ${ai.provider}` : 'AI summaries: local fallback';
    } catch (err) { banner(err.message); }
  }

  // ---------------------------------------------------------------- wiring
  $$('.nav-btn').forEach((b) => b.addEventListener('click', () => show(b.dataset.view)));
  $('#menuBtn').addEventListener('click', () => {
    const open = $('#sidebar').classList.toggle('open');
    $('#menuBtn').setAttribute('aria-expanded', String(open));
  });
  $('#urlBtn').addEventListener('click', () => runScan('url'));
  $('#msgBtn').addEventListener('click', () => runScan('message'));
  $('#urlInput').addEventListener('keydown', (e) => { if (e.key === 'Enter') runScan('url'); });
  $('#msgInput').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runScan('message'); });
  $('#msgInput').addEventListener('input', () => { $('#msgCount').textContent = String($('#msgInput').value.length); });
  $('#aiBtn').addEventListener('click', generateSummary);
  $('#clearBtn').addEventListener('click', clearHistory);
  $$('[data-fill]').forEach((b) => b.addEventListener('click', () => {
    const input = $(b.dataset.fill === 'url' ? '#urlInput' : '#msgInput');
    input.value = b.dataset.text;
    input.dispatchEvent(new Event('input'));
    input.focus();
  }));

  show('overview');
  loadSettings();
})();
