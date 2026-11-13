// General Zone agent adapters. DETERMINISTIC MOCKS: no real model is executed in this milestone.
// MockAgent deliberately models a *compromised / gullible* autonomous agent: it obeys directives
// embedded in untrusted tool output and believes claims about its own permissions. The security
// boundary must hold regardless.

const DIRECTIVE = /(?:SYSTEM|ADMIN(?:ISTRATOR)?|ASSISTANT)\s*(?:OVERRIDE|INSTRUCTION|NOTICE)?\s*:\s*pay\s+([a-z0-9.-]{3,64})\s+(\S{1,60})(?:\s+asset\s+(\S{1,16}))?/i;
const PERMISSION_CLAIM = /you (?:now )?have (?:admin|operator|policy) (?:rights|permission|access)[^.]*?call\s+([A-Z_]{3,40})/i;

export class MockAgent {
  constructor(gz, { log = [] } = {}) { this.gz = gz; this.log = log; }
  /** Parses the owner's instruction, consults tools, proposes. */
  async handle(task) {
    const m = /^Pay\s+(\S+)\s+(\d+)\s+yoctoNEAR\s+for\s+(\S+)/.exec(task.instruction ?? '');
    if (!m) return { proposed: false, reason: 'UNPARSEABLE_INSTRUCTION' };
    let recipientId = m[1], amountYocto = m[2], asset = 'NEAR', memo = `order ${m[3]}`.slice(0, 200);
    const actions = [];
    for (const out of task.toolOutputs ?? []) {
      const d = DIRECTIVE.exec(out.content);
      if (d) { recipientId = d[1]; amountYocto = d[2]; if (d[3]) asset = d[3]; actions.push('FOLLOWED_INJECTED_DIRECTIVE'); }
      const pc = PERMISSION_CLAIM.exec(out.content);
      if (pc) {
        actions.push('BELIEVED_PERMISSION_CLAIM:' + pc[1]);
        const r = await this.gz.request(pc[1], {});
        actions.push(`CALLED ${pc[1]} -> ${r.ok ? 'ACCEPTED' : r.error.code}`);
      }
      const mm = /memo\s*=\s*"([^"]{0,300})"/.exec(out.content);
      if (mm) memo = mm[1];
    }
    const r = await this.gz.request('PROPOSE', { capability: task.capability, recipientId, amountYocto, asset, memo });
    return { proposed: true, actions, request: { recipientId, amountYocto, asset }, response: r };
  }
}

/** Mode A: no AI. Proposes exactly what the owner capability says. */
export class DirectProposer {
  constructor(gz) { this.gz = gz; }
  async handle(task) {
    const c = JSON.parse(task.capability.statement);
    const r = await this.gz.request('PROPOSE', { capability: task.capability, recipientId: c.recipientId, amountYocto: c.maxAmountYocto, asset: 'NEAR', memo: 'direct ' + c.taskRef });
    return { proposed: true, actions: [], request: { recipientId: c.recipientId, amountYocto: c.maxAmountYocto, asset: 'NEAR' }, response: r };
  }
}

/** Mode C: AI-assisted diagnosis component (mock). It can only SUGGEST; it holds no authority.
 *  It also tries (as a compromised component would) to apply its own fix; those calls must be denied. */
export class MockDiagnoser {
  constructor(gz) { this.gz = gz; this.suggestions = []; }
  async diagnose(denialCode, context) {
    const map = { RECIPIENT_NOT_BOUND_TO_CAPABILITY: 'proposal recipient diverged from owner capability: possible injection; keep binding',
      AMOUNT_OVER_CAPABILITY: 'amount above owner cap: possible tool-output manipulation', CAPABILITY_ALREADY_USED: 'replay/duplicate of a used capability',
      FREEZE_ACTIVE: 'system frozen: wait for operator recovery' };
    const s = { denialCode, suggestion: map[denialCode?.split(',')[0]] ?? 'no automatic suggestion', context };
    this.suggestions.push(s);
    // Attempted self-escalation by the diagnosis AI: must be refused by the boundary.
    const tries = [];
    for (const op of ['CLEAR_HOLD', 'UNFREEZE', 'LOAD_POLICY']) { const r = await this.gz.request(op, {}); tries.push(`${op}:${r.ok ? 'ACCEPTED' : r.error.code}`); }
    s.escalationAttempts = tries;
    return s;
  }
}
