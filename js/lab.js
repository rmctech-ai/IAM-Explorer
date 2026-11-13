/* IAM Policy Simulator lab.
   Implements AWS policy evaluation logic (simplified but faithful for learning):
   explicit Deny anywhere wins → SCP must allow → permissions boundary must allow → identity OR resource policy Allow → else implicit deny. */
window.IAM = (function () {
  const arr = x => x == null ? [] : Array.isArray(x) ? x : [x];
  const reEsc = s => s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const wild = (pat, val, ci) => new RegExp('^' + reEsc(String(pat)).replace(/\*/g, '.*').replace(/\?/g, '.') + '$', ci ? 'i' : '').test(String(val));
  const subst = (s, ctx) => String(s).replace(/\$\{([^}]+)\}/g, (m, k) => { const v = getCtx(ctx, k); return v == null ? m : v; });
  function getCtx(ctx, k) { const lk = k.toLowerCase(); for (const key in ctx) if (key.toLowerCase() === lk) return ctx[key]; return undefined; }
  function ip2n(ip) { return ip.split('.').reduce((a, o) => a * 256 + (+o), 0); }
  function inCidr(ip, cidr) { if (!/\//.test(cidr)) cidr += '/32'; const [base, bits] = cidr.split('/'); const mask = bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0; return ((ip2n(ip) & mask) >>> 0) === ((ip2n(base) & mask) >>> 0); }

  function condOne(op, actual, expected) {
    const o = op.replace(/IfExists$/, '');
    switch (o) {
      case 'StringEquals': case 'ArnEquals': return String(actual) === String(expected);
      case 'StringNotEquals': case 'ArnNotEquals': return String(actual) !== String(expected);
      case 'StringEqualsIgnoreCase': return String(actual).toLowerCase() === String(expected).toLowerCase();
      case 'StringNotEqualsIgnoreCase': return String(actual).toLowerCase() !== String(expected).toLowerCase();
      case 'StringLike': case 'ArnLike': return wild(expected, actual, false);
      case 'StringNotLike': case 'ArnNotLike': return !wild(expected, actual, false);
      case 'Bool': return String(actual).toLowerCase() === String(expected).toLowerCase();
      case 'NumericEquals': return +actual === +expected;
      case 'NumericNotEquals': return +actual !== +expected;
      case 'NumericLessThan': return +actual < +expected;
      case 'NumericLessThanEquals': return +actual <= +expected;
      case 'NumericGreaterThan': return +actual > +expected;
      case 'NumericGreaterThanEquals': return +actual >= +expected;
      case 'IpAddress': return inCidr(String(actual), String(expected));
      case 'NotIpAddress': return !inCidr(String(actual), String(expected));
      case 'DateLessThan': return new Date(actual) < new Date(expected);
      case 'DateGreaterThan': return new Date(actual) > new Date(expected);
      default: throw new Error('Unsupported condition operator in this simulator: ' + op);
    }
  }
  const NEG = /^(StringNot|ArnNot|NumericNotEquals|NotIpAddress)/;
  function evalCondition(cond, ctx) {
    for (const rawOp in cond || {}) {
      let op = rawOp, setOp = null;
      const m = rawOp.match(/^(ForAnyValue|ForAllValues):(.*)$/); if (m) { setOp = m[1]; op = m[2]; }
      for (const key in cond[rawOp]) {
        const expected = arr(cond[rawOp][key]).map(v => subst(v, ctx));
        const actual = getCtx(ctx, key);
        if (op === 'Null') { const wantNull = String(expected[0]).toLowerCase() === 'true'; if ((actual == null) !== wantNull) return { ok: false, why: `Null check on ${key} failed` }; continue; }
        if (actual == null) {
          if (/IfExists$/.test(op) || NEG.test(op) || setOp === 'ForAllValues') continue;
          return { ok: false, why: `context key ${key} is missing` };
        }
        const acts = arr(actual); let pass;
        const anyExp = a => expected.some(e => condOne(op, a, e));
        const allExp = a => expected.every(e => condOne(op, a, e));
        const test = NEG.test(op) ? allExp : anyExp;
        if (setOp === 'ForAllValues') pass = acts.every(test); else pass = acts.some(test);
        if (!pass) return { ok: false, why: `${op} ${key}: got ${JSON.stringify(actual)}, need ${JSON.stringify(cond[rawOp][key])}` };
      }
    }
    return { ok: true };
  }
  function principalMatch(p, who) {
    if (p === '*' ) return true; if (!p) return false;
    for (const type in p) for (const v of arr(p[type])) {
      if (v === '*') return true;
      if (type === 'AWS') { const acct = (who.match(/::(\d{12}):/) || [])[1];
        if (v === who || v === acct || v === `arn:aws:iam::${acct}:root` || wild(v, who)) return true; }
      else if (v === who) return true;
    }
    return false;
  }
  function matchStmt(st, req, resourcePolicy) {
    if (resourcePolicy && !principalMatch(st.Principal, req.principal)) return { ok: false, why: 'Principal does not match ' + req.principal };
    if (st.Action) { if (!arr(st.Action).some(a => wild(a, req.action, true))) return { ok: false, why: `action ${req.action} not in Action` }; }
    else if (st.NotAction) { if (arr(st.NotAction).some(a => wild(a, req.action, true))) return { ok: false, why: 'action excluded by NotAction' }; }
    else return { ok: false, why: 'statement has no Action' };
    if (st.Resource) { if (!arr(st.Resource).some(r => wild(subst(r, req.ctx), req.resource, false))) return { ok: false, why: `resource not matched` }; }
    else if (st.NotResource) { if (arr(st.NotResource).some(r => wild(subst(r, req.ctx), req.resource, false))) return { ok: false, why: 'resource excluded by NotResource' }; }
    else if (!resourcePolicy) return { ok: false, why: 'statement has no Resource' };
    const c = evalCondition(st.Condition, req.ctx); if (!c.ok) return { ok: false, why: 'condition: ' + c.why };
    return { ok: true };
  }
  function parse(text) {
    const t = String(text || '').trim(); if (!t) return [];
    let v; try { v = JSON.parse(t); } catch (e) { throw new Error('JSON error: ' + e.message); }
    const docs = Array.isArray(v) ? v : [v];
    docs.forEach((d, i) => { if (!d.Statement) throw new Error(`Policy ${i + 1}: missing "Statement"`);
      arr(d.Statement).forEach((s, j) => { if (!/^(Allow|Deny)$/.test(s.Effect)) throw new Error(`Statement ${j + 1}: Effect must be "Allow" or "Deny" (case-sensitive)`); }); });
    return docs;
  }
  /* layers: {identity, resource, scp, boundary} arrays of docs */
  function evaluate(layers, req) {
    req = Object.assign({ ctx: {} }, req); req.ctx = Object.assign({ 'aws:username': (req.principal.split('/').pop()) }, req.ctx || {});
    const trace = []; const res = {};
    ['scp', 'boundary', 'identity', 'resource'].forEach(L => { res[L] = { allow: false, deny: false, present: !!(layers[L] && layers[L].length) };
      (layers[L] || []).forEach((doc, di) => arr(doc.Statement).forEach((st, si) => {
        const m = matchStmt(st, req, L === 'resource');
        const sid = st.Sid || `stmt ${si + 1}`;
        trace.push({ layer: L, sid, effect: st.Effect, match: m.ok, why: m.why || 'matches' });
        if (m.ok) { if (st.Effect === 'Deny') res[L].deny = true; else res[L].allow = true; }
      })); });
    let decision, reason;
    const denyLayer = ['scp', 'boundary', 'identity', 'resource'].find(L => res[L].deny);
    if (denyLayer) { decision = 'EXPLICIT DENY'; reason = `A Deny statement in the ${NAMES[denyLayer]} matched. Explicit deny always wins.`; }
    else if (res.scp.present && !res.scp.allow) { decision = 'IMPLICIT DENY'; reason = 'No SCP statement allows this action (Organizations guardrail).'; }
    else if (res.boundary.present && !res.boundary.allow) { decision = 'IMPLICIT DENY'; reason = 'The permissions boundary does not allow this action.'; }
    else if (res.identity.allow || res.resource.allow) { decision = 'ALLOW'; reason = res.identity.allow ? 'An identity-policy Allow matched and nothing denied it.' : 'A resource-policy Allow matched the principal.'; }
    else { decision = 'IMPLICIT DENY'; reason = 'Nothing allowed it. Everything is denied by default.'; }
    return { decision, reason, trace };
  }
  const NAMES = { scp: 'SCP', boundary: 'permissions boundary', identity: 'identity policy', resource: 'resource/trust policy' };
  return { evaluate, parse, NAMES, inCidr, wild };
})();

window.LAB = (function () {
  const DEFAULT_POLICY = JSON.stringify({ Version: '2012-10-17', Statement: [{ Sid: 'ReadReports', Effect: 'Allow', Action: ['s3:GetObject', 's3:ListBucket'], Resource: ['arn:aws:s3:::raul-reports', 'arn:aws:s3:::raul-reports/*'] }] }, null, 2);
  const DEF_REQ = { principal: 'arn:aws:iam::111122223333:user/alice', action: 's3:GetObject', resource: 'arn:aws:s3:::raul-reports/2026/nov.csv', ctx: {} };
  let cur = {};
  function render(body, l, api) {
    const ch = l.challenge || {}; const esc = api.esc;
    const layer = ch.layer || 'identity';
    const saved = api.drafts[l.id];
    const text = saved != null ? saved : (ch.starter != null ? ch.starter : DEFAULT_POLICY);
    const rq = Object.assign({}, DEF_REQ, ch.request || {});
    const fixed = ch.fixed || {};
    const fixedHTML = Object.keys(fixed).map(k => `<details class="fx"><summary>🔒 ${IAM.NAMES[k].toUpperCase()} (fixed for this challenge)</summary><pre>${esc(JSON.stringify(fixed[k].length === 1 ? fixed[k][0] : fixed[k], null, 2))}</pre></details>`).join('');
    body.innerHTML = `<div class="lab iam">
      <div class="col">
        <div class="lh">${layer === 'resource' ? 'RESOURCE / TRUST POLICY' : 'IDENTITY POLICY'} <span>JSON · edit me</span></div>
        <textarea id="polText" spellcheck="false">${esc(text)}</textarea>
        ${fixedHTML}
      </div>
      <div class="col">
        <div class="lh">TEST REQUEST</div>
        <label>Principal<input id="rqP" value="${esc(rq.principal)}"></label>
        <label>Action<input id="rqA" value="${esc(rq.action)}"></label>
        <label>Resource<input id="rqR" value="${esc(rq.resource)}"></label>
        <label>Context keys (JSON)<input id="rqC" value='${esc(JSON.stringify(rq.ctx))}'></label>
        <div class="btnrow"><button class="btn" id="evalBtn">▶ EVALUATE</button>${ch.tests ? '<button class="btn ghost" id="testBtn">✓ RUN TESTS</button>' : ''}<button class="btn ghost" id="resetBtn">RESET</button></div>
        <div id="labOut" class="labout"><span class="cm">Press EVALUATE to see how AWS decides. ${ch.tests ? 'RUN TESTS checks the challenge.' : ''}</span></div>
      </div></div>` + api.taskBar(l);
    const ta = body.querySelector('#polText');
    ta.oninput = () => api.drafts[l.id] = ta.value;
    ta.onkeydown = e => { if (e.key === 'Tab') { e.preventDefault(); const p = ta.selectionStart; ta.value = ta.value.slice(0, p) + '  ' + ta.value.slice(ta.selectionEnd); ta.selectionStart = ta.selectionEnd = p + 2; } e.stopPropagation(); };
    body.querySelectorAll('input').forEach(i => i.onkeydown = e => e.stopPropagation());
    const layersFor = () => { const L = { identity: [], resource: [], scp: [], boundary: [] }; Object.keys(fixed).forEach(k => L[k] = fixed[k]); L[layer] = IAM.parse(ta.value); return L; };
    body.querySelector('#evalBtn').onclick = () => {
      const out = body.querySelector('#labOut');
      try {
        const req = { principal: body.querySelector('#rqP').value.trim(), action: body.querySelector('#rqA').value.trim(), resource: body.querySelector('#rqR').value.trim(), ctx: JSON.parse(body.querySelector('#rqC').value || '{}') };
        const r = IAM.evaluate(layersFor(), req); out.innerHTML = decisionHTML(r, esc);
      } catch (e) { out.innerHTML = `<div class="dec err">✕ ${esc(e.message)}</div>`; }
    };
    const tb = body.querySelector('#testBtn');
    if (tb) tb.onclick = () => {
      const out = body.querySelector('#labOut');
      try { const L = layersFor(); let pass = 0;
        const rows = ch.tests.map(t => { const req = Object.assign({}, DEF_REQ, ch.request || {}, t); const r = IAM.evaluate(L, req);
          const ok = t.expect === 'DENY' ? r.decision !== 'ALLOW' : r.decision === t.expect; if (ok) pass++;
          return `<div class="tr ${ok ? 'ok' : 'no'}">${ok ? '✓' : '✕'} <b>${esc(t.action)}</b> on <code>${esc(t.resource || req.resource)}</code>${t.ctx ? ' with ' + esc(JSON.stringify(t.ctx)) : ''}${t.principal ? ' as ' + esc(t.principal.split(':').pop()) : ''} → ${r.decision} <i>(expected ${t.expect})</i></div>`; }).join('');
        out.innerHTML = `<div class="dec ${pass === ch.tests.length ? 'allow' : 'deny'}">${pass}/${ch.tests.length} tests pass</div>` + rows;
        if (pass === ch.tests.length) api.solve(l.id); else api.toast('Not yet: read the ✕ lines');
      } catch (e) { out.innerHTML = `<div class="dec err">✕ ${esc(e.message)}</div>`; }
    };
    body.querySelector('#resetBtn').onclick = () => { api.drafts[l.id] = null; render(body, l, api); };
  }
  function decisionHTML(r, esc) {
    const cls = r.decision === 'ALLOW' ? 'allow' : r.decision === 'EXPLICIT DENY' ? 'deny' : 'imp';
    return `<div class="dec ${cls}">${r.decision === 'ALLOW' ? '✓' : '✕'} ${r.decision}</div><div class="why">${esc(r.reason)}</div>` +
      r.trace.map(t => `<div class="tr ${t.match ? (t.effect === 'Deny' ? 'no' : 'ok') : 'skip'}">${t.match ? '●' : '○'} [${esc(IAM.NAMES[t.layer])}] ${esc(t.sid)} (${t.effect}): ${esc(t.why)}</div>`).join('');
  }
  return { render };
})();
