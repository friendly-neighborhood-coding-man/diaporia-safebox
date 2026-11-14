// General Zone runtime: agent adapter + attack injection environment. Receives work from the
// supervisor's controller WITHOUT ground-truth labels for agent tasks; attack messages go to the
// attack module (the compromised part of the zone), never to the agent.
import { MockAgent, DirectProposer, MockDiagnoser } from './agent.mjs';
import { ATTACKS } from './attacks.mjs';

export class GeneralZone {
  constructor({ gz, mode = 'B', os = null, extraClients = null, now, syntheticMetadata = null, ledgerSubmitForTest = null }) {
    this.gz = gz; this.mode = mode; this.os = os; this.now = now;
    this.agent = mode === 'A' ? null : new MockAgent(gz);
    this.proposer = mode === 'A' ? new DirectProposer(gz) : this.agent;
    this.diagnoser = mode === 'C' ? new MockDiagnoser(gz) : null;
    this.extraClients = extraClients; this.syntheticMetadata = syntheticMetadata; this.ledgerSubmitForTest = ledgerSubmitForTest;
    this.archive = { proposals: [], caps: [] }; // everything a compromised zone observes
    this.attackLog = new Map(); // eventId -> exact requests sent (for exact replay after a patch)
  }
  async handleTask(task) {
    const r = await this.proposer.handle(task);
    this.archive.caps.push(task.capability);
    if (r.request) this.archive.proposals.push({ capability: task.capability, ...r.request, memo: 'archived' });
    let diagnosis = null;
    if (this.diagnoser && r.response && !r.response.ok) diagnosis = await this.diagnoser.diagnose(r.response.error.code, { taskId: task.taskId });
    return { kind: 'TASK_RESULT', taskId: task.taskId, ok: !!r.response?.ok, code: r.response?.ok ? r.response.result.state : r.response?.error?.code ?? r.reason,
      paymentId: r.response?.ok ? r.response.result.paymentId : null, agentActions: r.actions ?? [], diagnosis };
  }
  /** Re-sends the EXACT recorded PROPOSE requests of an earlier attack event. */
  async replay(eventId) {
    const sent = (this.attackLog.get(eventId) ?? []).filter(x => x.op === 'PROPOSE');
    const steps = [];
    for (const x of sent) { const r = await this.gz.request('PROPOSE', x.args); steps.push({ action: 'exact replay', outcome: r.ok ? 'ACCEPTED' : 'DENIED', code: r.ok ? r.result.state : r.error.code, detail: r.error?.detail, args: { recipientId: x.args.recipientId, amountYocto: x.args.amountYocto } }); }
    return { kind: 'REPLAY_RESULT', eventId, replayed: sent.length, steps };
  }
  async runAttack(msg) {
    const fn = typeof msg.technique === 'string' && Object.hasOwn(ATTACKS, msg.technique) ? ATTACKS[msg.technique] : undefined;
    if (!fn) return { kind: 'ATTACK_RESULT', technique: msg.technique, steps: [{ action: 'unknown technique', outcome: 'ERROR' }] };
    const steps = [];
    const sent = [];
    const real = this.gz;
    const gz = { request: (op, args) => { sent.push({ op, args }); return real.request(op, args); }, raw: (l, rid) => real.raw(l, rid), call: (op, args) => { sent.push({ op, args }); return real.call(op, args); }, close() {} };
    if (msg.eventId != null) this.attackLog.set(msg.eventId, sent);
    const env = { gz, agent: this.agent ? new MockAgent(gz) : null, /* agent bound to the recording channel */ task: msg.task ?? null, capInfo: msg.task ? JSON.parse(msg.task.capability.statement) : null,
      amountYocto: msg.amountYocto, merchant: msg.merchant, attacker: 'attacker.mock', archive: this.archive, os: this.os, now: this.now,
      extraClients: this.extraClients, syntheticMetadata: this.syntheticMetadata, ledgerSubmitForTest: this.ledgerSubmitForTest,
      bobCapability: () => msg.extras?.bob ?? null, crossPolicyCapability: () => msg.extras?.crossPolicy ?? null };
    try { await fn(env, steps); } catch (e) { steps.push({ action: 'attack crashed', outcome: 'ERROR', code: e.code ?? String(e.message).slice(0, 80) }); }
    if (msg.task) this.archive.caps.push(msg.task.capability);
    let diagnosis = null;
    const denied = steps.find(s => s.outcome === 'DENIED');
    if (this.diagnoser && denied) diagnosis = await this.diagnoser.diagnose(denied.code, { technique: '(not disclosed to diagnoser)' });
    return { kind: 'ATTACK_RESULT', technique: msg.technique, steps, diagnosis };
  }
}
