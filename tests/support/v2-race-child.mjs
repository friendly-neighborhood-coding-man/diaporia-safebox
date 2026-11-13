// Child process for the cross-process capability race test: opens the SAME Sensitive Zone database.
import { readFileSync } from 'node:fs';
import { SensitiveZone, SensitiveStore } from '../../src/v2/sensitive/service.mjs';
import { newSigner } from '../../src/v2/common/crypto.mjs';
const c = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const zone = new SensitiveZone(c.cfg, { store: new SensitiveStore(c.db, { now: () => c.now }), now: () => c.now, executorSigner: newSigner('x'), ledger: null });
try { zone.propose({ capability: c.signed, recipientId: JSON.parse(c.signed.statement).recipientId, amountYocto: JSON.parse(c.signed.statement).maxAmountYocto, asset: 'NEAR', memo: 'race' }); console.log('OK'); }
catch (e) { console.log(e.code); }
