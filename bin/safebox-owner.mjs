#!/usr/bin/env node
// SafeBox OWNER AUTHORIZER — run by the human owner, in a separate process/terminal (ideally a separate
// device). It is the only component that ever loads the owner signing key. It recomputes the intent
// digest from the canonical intent itself and shows the exact execution parameters before signing.
// No AI runtime should have access to this program's key file.
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { DOMAINS } from '../src/v1/canonical.mjs';
import { parseSealedIntent, displayIntent } from '../src/v1/intent.mjs';
import { writeOwnerKeyFile, loadOwnerSigner, authorizationStatement, revocationStatement, MANDATE_VERSION } from '../src/v1/authz.mjs';
import { parseArgs, need } from '../src/v1/cli-args.mjs';

const USAGE = `usage:
  safebox-owner keygen        --principal <id> --out <key.json>
  safebox-owner sign-mandate  --key <key.json> --mandate-id <id> --action <NEAR_NATIVE_TRANSFER|SAFEBOX_CONTRACT_PAYMENT>
                              --max-per-yocto <n> --max-total-yocto <n> --recipients <a.testnet,b.testnet> --hours <h> --out <mandate.json>
  safebox-owner authorize     --key <key.json> --request <request.json> --out <authorization.json> [--ttl-seconds 300] [--confirm-digest <first 16 hex>]
  safebox-owner revoke        --key <key.json> --request <request.json> --out <revocation.json>`;

async function confirm(sealed, given) {
  const expect = sealed.digest.slice(0, 16);
  if (given !== undefined) { if (given !== expect) throw new Error('digest confirmation does not match; nothing signed'); return; }
  if (!process.stdin.isTTY) throw new Error('interactive owner confirmation requires a TTY (or --confirm-digest typed by the owner)');
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const ans = (await rl.question(`\nType the first 16 characters of the intent digest to AUTHORIZE (anything else cancels): `)).trim();
  rl.close();
  if (ans !== expect) throw new Error('not confirmed; nothing signed');
}

async function main() {
  const a = parseArgs(process.argv.slice(2));
  const now = Date.now();
  switch (a._cmd) {
    case 'keygen': {
      need(a, 'principal', 'out');
      const pub = writeOwnerKeyFile(a.out, a.principal);
      console.log(JSON.stringify({ principalId: a.principal, ownerPublicKey: pub, keyFile: a.out, note: 'Pin ownerPublicKey in the SafeBox config. Keep the key file away from any AI runtime.' }, null, 2));
      return;
    }
    case 'sign-mandate': {
      need(a, 'key', 'mandate-id', 'action', 'max-per-yocto', 'max-total-yocto', 'recipients', 'hours', 'out');
      const owner = loadOwnerSigner(a.key);
      const hours = Number(a.hours);
      if (!Number.isInteger(hours) || hours < 1 || hours > 24 * 30) throw new Error('--hours must be an integer 1..720');
      const s = owner.signStatement(DOMAINS.MANDATE, { v: MANDATE_VERSION, mandateId: a['mandate-id'], principalId: owner.principalId, ownerKey: owner.publicKey,
        action: a.action, maxPerIntentYocto: a['max-per-yocto'], maxTotalYocto: a['max-total-yocto'], allowedRecipients: a.recipients.split(',').sort(),
        validFrom: new Date(now).toISOString(), expiresAt: new Date(now + hours * 3_600_000).toISOString() });
      writeFileSync(a.out, JSON.stringify({ mandate: s.statement, signature: s.signature }, null, 2) + '\n');
      console.log(`mandate signed -> ${a.out}`);
      return;
    }
    case 'authorize': case 'revoke': {
      need(a, 'key', 'request', 'out');
      const owner = loadOwnerSigner(a.key);
      const req = JSON.parse(readFileSync(a.request, 'utf8'));
      const sealed = parseSealedIntent(req.canonical); // recomputes digest locally; never trusts a server-supplied digest
      if (sealed.intent.principalId !== owner.principalId) throw new Error('intent belongs to another principal');
      console.error('\n' + displayIntent(sealed) + '\n');
      if (a._cmd === 'revoke') {
        const s = owner.signStatement(DOMAINS.REVOKE, revocationStatement({ sealed, ownerKey: owner.publicKey, now }));
        writeFileSync(a.out, JSON.stringify({ intentId: sealed.intent.intentId, revocation: s.statement, signature: s.signature }, null, 2) + '\n');
        console.error(`revocation signed -> ${a.out}`); return;
      }
      if (!/^[0-9a-f]{64}$/.test(req.challenge ?? '')) throw new Error('request has no valid challenge');
      await confirm(sealed, a['confirm-digest']);
      const ttl = Number(a['ttl-seconds'] ?? 300);
      if (!Number.isInteger(ttl) || ttl < 10 || ttl > 900) throw new Error('--ttl-seconds must be 10..900');
      const s = owner.signStatement(DOMAINS.AUTHZ, authorizationStatement({ sealed, challenge: req.challenge, ownerKey: owner.publicKey, now, ttlMs: ttl * 1000 }));
      writeFileSync(a.out, JSON.stringify({ intentId: sealed.intent.intentId, authorization: s.statement, signature: s.signature }, null, 2) + '\n');
      console.error(`authorization signed for digest ${sealed.digest} -> ${a.out}`);
      return;
    }
    default: console.error(USAGE); process.exitCode = 64;
  }
}
main().catch(e => { console.error('ERROR:', e.code ?? '', e.message); process.exitCode = 1; });
