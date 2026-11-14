// Static SafeBox Owner Console page. It contains NO incident data, NO token and NO authority: everything shown comes
// from the console API after the owner signs in with an enrolled device, and nothing changes until the owner types
// the confirm phrase and approves the exact command on the device (WebAuthn user verification; fingerprint-only
// credentials additionally need the local fingerprint gate helper, which only answers on a real sensor MATCH).
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const CONSOLE_PAGE = ({ locator, notice, gateOrigin }) => `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>SafeBox Owner Console</title>
<style>
body{font:15px/1.45 system-ui,sans-serif;max-width:760px;margin:24px auto;padding:0 16px;color:#1d232b;background:#f6f7f9}
h1{font-size:20px;margin:0 0 4px}.sub{color:#5a6573;margin:0 0 16px}
.card{background:#fff;border:1px solid #d9dee5;border-radius:10px;padding:14px 16px;margin:12px 0}
.warn{border-color:#d9a400;background:#fffaf0}.bad{border-color:#c62828;background:#fff5f5}.ok{border-color:#2e7d32;background:#f3fbf3}
pre{white-space:pre-wrap;background:#f1f3f6;padding:10px;border-radius:6px;font-size:13px}
button{font:inherit;padding:8px 14px;border-radius:7px;border:1px solid #8893a1;background:#fff;cursor:pointer}
button.primary{background:#b3261e;color:#fff;border-color:#b3261e}input{font:inherit;padding:7px;border:1px solid #8893a1;border-radius:6px;width:16em}
.label{display:inline-block;font-size:12px;font-weight:600;padding:2px 7px;border-radius:5px;background:#e8ecf1;margin-right:4px}
</style></head><body>
<h1>SafeBox Owner Console</h1>
<p class="sub">Opening this page changes nothing. Nothing is frozen, released or approved until you sign in, review the command below and approve it on your enrolled device.</p>
${notice ? `<div class="card bad">${esc(notice)}</div>` : ''}
<div class="card" id="login"><b>1. Sign in with your enrolled device</b><br>
Credential: <input id="cred" value="k2-laptop" autocomplete="off"> <button id="signin">Sign in</button><div id="loginOut"></div></div>
<div class="card" id="incident" hidden><b>2. Incident (from SafeBox's own records)</b><div id="incOut"></div></div>
<div class="card warn" id="freeze" hidden><b>3. Emergency Freeze (scope: GLOBAL)</b>
<div id="cmdOut"></div><p>Type <b id="phrase"></b> to confirm, then approve on your device:</p>
<input id="confirm" autocomplete="off"> <button class="primary" id="go" disabled>Approve on device and freeze</button><div id="freezeOut"></div></div>
<script>
"use strict";
const LOCATOR = ${JSON.stringify(locator)};
const GATE_URL = ${JSON.stringify(gateOrigin)};
let CSRF = null, PROPOSAL = null;
const $ = (id) => document.getElementById(id);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const fromB64u = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/') + '==='.slice((s.length + 3) % 4)), c => c.charCodeAt(0));
const hex2buf = (h) => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
const show = (el, html, cls) => { el.innerHTML = html; if (cls) el.parentElement.className = 'card ' + cls; };
const txt = (s) => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function api(path, body) {
  const r = await fetch(path, body === undefined ? { credentials: 'same-origin' } : { method: 'POST', credentials: 'same-origin',
    headers: { 'content-type': 'application/json', ...(CSRF ? { 'x-safebox-csrf': CSRF } : {}) }, body: JSON.stringify(body) });
  const j = await r.json(); if (!j.ok) throw new Error(j.error.code + (j.error.detail ? ' (' + j.error.detail + ')' : '')); return j;
}
async function loginChallenge(hex) {
  // device-side derivation: the login assertion signs SHA-256('safebox.v6.console-login:' || digest), never a raw
  // server-chosen value, so it cannot double as a command approval
  const p = new TextEncoder().encode('safebox.v6.console-login:'); const d = new Uint8Array(hex2buf(hex));
  const m = new Uint8Array(p.length + d.length); m.set(p); m.set(d, p.length);
  return crypto.subtle.digest('SHA-256', m);
}
async function assertWith(challengeHex, credentialId, rpId, { login = false } = {}) {
  const c = await navigator.credentials.get({ publicKey: { challenge: login ? await loginChallenge(challengeHex) : hex2buf(challengeHex), rpId, userVerification: 'required', timeout: 120000,
    allowCredentials: [{ type: 'public-key', id: fromB64u(credentialId) }] } });
  return { credentialId: b64u(c.rawId), authenticatorData: b64u(c.response.authenticatorData), clientDataJSON: b64u(c.response.clientDataJSON), signature: b64u(c.response.signature) };
}
$('signin').onclick = async () => {
  try {
    const st = await api('/api/login/start', { credId: $('cred').value.trim() });
    if (st.kind !== 'passkey') throw new Error('this credential signs on its own hardware device, not in a browser');
    const webauthn = await assertWith(st.challengeHex, st.credentialId, st.rpId, { login: true });
    const fin = await api('/api/login/finish', { loginId: st.loginId, webauthn });
    CSRF = fin.csrf; show($('loginOut'), 'Signed in as <b>' + txt(fin.credId) + '</b> (' + txt(fin.role) + ').', 'ok');
    const inc = await api('/api/incident' + (LOCATOR ? '?locator=' + encodeURIComponent(LOCATOR) : ''));
    $('incident').hidden = false;
    const i = inc.incident;
    show($('incOut'), i ? '<pre>' + txt(['Incident: ' + i.incidentId, 'State: ' + i.state + ' / risk ' + i.riskClass, 'Opened: ' + i.openedAt, 'Affected credential: ' + i.affectedCredential,
      'Delayed payments: ' + i.delayedPayments, 'Reasons: ' + i.reasons.join(', '), 'Already frozen: ' + (inc.freeze.rootFrozen ? 'YES' : 'no')].join('\\n')) + '</pre>'
      : '<p>No incident named. Open incidents: ' + txt((inc.incidents || []).map(x => x.incidentId).join(', ') || 'none') + '</p>');
    if (i) {
      PROPOSAL = await api('/api/freeze/prepare', { incidentId: i.incidentId, ...(LOCATOR ? { locator: LOCATOR } : {}) });
      $('freeze').hidden = false; $('phrase').textContent = PROPOSAL.confirmPhrase;
      show($('cmdOut'), '<pre>' + txt(PROPOSAL.text) + '</pre><span class="label">' + (PROPOSAL.gateRequired ? 'FINGERPRINT GATE REQUIRED' : 'UV (Windows Hello may accept a PIN)') + '</span> expires ' + txt(PROPOSAL.expiresAt));
      $('confirm').oninput = () => { $('go').disabled = $('confirm').value !== PROPOSAL.confirmPhrase; };
    }
  } catch (e) { show($('loginOut'), 'Not signed in: ' + txt(e.message), 'bad'); }
};
$('go').onclick = async () => {
  $('go').disabled = true;
  try {
    const P = PROPOSAL;
    const approval = { credId: P.command.credId, command: P.command, grant: P.grant, webauthn: await assertWith(P.digestHex, P.credentialId, P.rpId) };
    if (P.gateRequired) {
      const g = await fetch(GATE_URL + '/attest', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ subject: 'COMMAND', credId: P.command.credId,
        // P0.2: the owner side rebuilds this from its own Root replica and shows ITS text in the gate window
        action: P.action, grant: P.grant, command: P.command, boundDigestHex: P.digestHex, challengeNonce: P.grant.statement.challengeNonce }) }).then(r => r.json());
      if (!g.ok) throw new Error('fingerprint gate: ' + g.code + ' (nothing was submitted)');
      approval.gate = g.gate;
    }
    const r = await api('/api/freeze/confirm', { proposalId: P.proposalId, confirm: $('confirm').value, approval });
    show($('freezeOut'), '<b>' + (r.rootFrozen && r.vaultFrozen ? 'FROZEN' : 'NOT CONFIRMED FROZEN') + '</b>: hold ' + txt(r.holdId) + ' (' + txt(r.holdClass) + '), Root seq ' + r.seq
      + '. Root frozen: ' + r.rootFrozen + ', Vault frozen: ' + r.vaultFrozen + '.', r.rootFrozen && r.vaultFrozen ? 'ok' : 'bad');
  } catch (e) { show($('freezeOut'), 'Not frozen: ' + txt(e.message), 'bad'); }
};
</script></body></html>`;
