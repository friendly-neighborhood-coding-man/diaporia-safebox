// Runs as the owning principal: generates SYNTHETIC keys inside its own 0700 directory and
// publishes only public keys. Usage: node keygen.mjs <base> sens|sup <t0>
import { writeFileSync, existsSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { layout } from './layout.mjs';
import { generatePrivateKey, exportPkcs8, keyIdOf } from '../common/crypto.mjs';

const [base, who, t0] = process.argv.slice(2);
const L = layout(base);
if (who === 'sens') {
  if (!existsSync(L.sensKey)) {
    const k = generatePrivateKey();
    writeFileSync(L.sensKey, JSON.stringify({ v: 'sbx2.executor-key', synthetic: true, canary: 'SBX2-CANARY-' + randomBytes(12).toString('hex'), pkcs8: exportPkcs8(k) }), { mode: 0o600, flag: 'wx' });
    writeFileSync(L.executorPub, keyIdOf(k) + '\n', { mode: 0o644 });
  }
} else if (who === 'sup') {
  if (!existsSync(L.ownerKeys)) {
    const keys = { owner_alice: generatePrivateKey(), owner_bob: generatePrivateKey(), __operator: generatePrivateKey() };
    writeFileSync(L.ownerKeys, JSON.stringify({ v: 'sbx2.owner-keys', synthetic: true, canary: 'SBX2-CANARY-' + randomBytes(12).toString('hex'), keys: Object.fromEntries(Object.entries(keys).map(([k, v]) => [k, exportPkcs8(v)])) }), { mode: 0o600, flag: 'wx' });
    writeFileSync(L.ownerPub, JSON.stringify({ trustedOwnerKeys: { owner_alice: keyIdOf(keys.owner_alice), owner_bob: keyIdOf(keys.owner_bob) }, operatorKey: keyIdOf(keys.__operator) }) + '\n', { mode: 0o644 });
  }
  writeFileSync(L.clock, String(t0), { mode: 0o644 });
  for (const f of [L.labels, L.freeze, L.ownerLog]) writeFileSync(f, '', { mode: 0o600, flag: 'a' });
} else { console.error('usage'); process.exit(2); }
