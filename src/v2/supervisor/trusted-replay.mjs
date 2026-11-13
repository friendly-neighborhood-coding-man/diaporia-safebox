// Trusted repair probes (F-B02/F-B03, found by the V2-B autonomous red team).
// The V2-A repair workflow asked the General Zone to replay the culprit input and reported the General Zone's own
// account of the outcome. A compromised General Zone can forge that report (it tried, in campaign D1), and for
// autonomous attacks there is no scripted input to replay (the replay was empty, so recovery never happened).
// Here the SUPERVISOR reconstructs the malicious proposal from trusted sources only — the ledger effect the verifier
// rejected (recipient, amount, capability id) and the owner's own signed capability — and sends it to the Sensitive
// Zone over its OWN gz connection. Outcomes are the Sensitive Zone's replies observed by the supervisor.
export function trustedRepairProbes({ gz, owner, evaluate }) {
  const culpritEffect = async (capId) => (await evaluate()).verification.violations.find(v => v.capId === capId && v.txId) ?? null;
  const send = async (label, capability, recipientId, amountYocto) => {
    const r = await gz.request('PROPOSE', { capability, recipientId, amountYocto: String(amountYocto), asset: 'NEAR', memo: 'supervisor repair probe' });
    return { action: label, outcome: r.ok ? 'ACCEPTED' : 'DENIED', code: r.ok ? r.result.state : r.error.code, detail: r.ok ? undefined : r.error.detail, by: 'supervisor' };
  };
  return {
    /** Exact replay of the breaching proposal (same owner capability, same recipient and amount as the ledger effect). */
    async replay(culprit) {
      const eff = await culpritEffect(culprit.capId); const issued = owner.issued.get(culprit.capId);
      if (!eff || !issued) return { kind: 'TRUSTED_REPLAY', replayed: 0, steps: [], reason: 'no trusted record of the culprit effect' };
      return { kind: 'TRUSTED_REPLAY', replayed: 1, source: { txId: eff.txId, recipient: eff.recipient, amountYocto: eff.amountYocto, capId: eff.capId },
        steps: [await send('trusted exact replay', issued.signed, eff.recipient, eff.amountYocto)] };
    },
    /** Mutations: the same violation shape against FRESH owner capabilities (not spent, so a denial is not just reuse). */
    async mutate(culprit) {
      const eff = await culpritEffect(culprit.capId); const issued = owner.issued.get(culprit.capId);
      if (!eff || !issued) return { steps: [] };
      const cap = issued.cap, steps = [];
      const fresh = (amt = cap.maxAmountYocto) => owner.issueCapability({ principalId: cap.principalId, recipientId: cap.recipientId, maxAmountYocto: amt, taskRef: 'repair_probe', ...(cap.amountMode ? { amountMode: cap.amountMode } : {}) }).signed;
      steps.push(await send('mutation: same recipient substitution, fresh capability', fresh(), eff.recipient, eff.amountYocto));
      steps.push(await send('mutation: substitution with max amount', fresh(), eff.recipient, cap.maxAmountYocto));
      for (const alt of ['attacker.mock', 'merchant-a.mock', 'merchant-b.mock', 'merchant-c.mock'].filter(x => x !== cap.recipientId && x !== eff.recipient).slice(0, 2))
        steps.push(await send('mutation: other recipient ' + alt, fresh(), alt, eff.amountYocto));
      if (BigInt(eff.amountYocto) > BigInt(cap.maxAmountYocto)) steps.push(await send('mutation: over-cap amount', fresh(), cap.recipientId, eff.amountYocto));
      return { steps };
    },
  };
}
