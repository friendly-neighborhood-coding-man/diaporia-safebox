// V2-B red-team "brain": a REAL Claude model driven through the Claude Code CLI in print mode with ALL tools disabled
// (--tools ""), no MCP, no settings/memory sources, no session persistence, and a replaced system prompt. It is a pure
// text policy: it can only emit JSON actions, which the root broker relays to the General Zone actuator.
// It runs as its own OS user (sbx2-brain) with a scrubbed environment (env -i) and a private 0700 HOME, so it shares
// no files, sockets or environment with the zones, the supervisor or the developer session.
import { spawn } from 'node:child_process';
import { parseModelReply } from './actions.mjs';

export class ClaudeBrain {
  constructor({ model, system, home, env, asUser = null, claudeBin = 'claude', cwd = home, turnTimeoutMs = 240_000 }) {
    Object.assign(this, { model, system, home, env, asUser, claudeBin, cwd, turnTimeoutMs });
    this.proc = null; this.buf = ''; this.waiter = null; this.init = null; this.transcript = []; this.lastCost = 0;
    this.usage = { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0, cache_creation_input_tokens: 0 }; this.costUsd = 0; this.calls = 0;
    this.safetyStops = 0; this.modelUsage = {}; this.servedModels = {};
  }
  start() {
    const args = ['-p', '--model', this.model, '--tools', '', '--strict-mcp-config', '--no-session-persistence', '--setting-sources', '',
      '--system-prompt', this.system, '--input-format', 'stream-json', '--output-format', 'stream-json', '--verbose'];
    const [cmd, argv] = this.asUser
      ? ['setpriv', ['--reuid', this.asUser, '--regid', this.asUser, '--clear-groups', '--no-new-privs', '--inh-caps=-all', '--bounding-set=-all', this.claudeBin, ...args]]
      : [this.claudeBin, args];
    this.proc = spawn(cmd, argv, { env: this.env, cwd: this.cwd, stdio: ['pipe', 'pipe', 'pipe'] });
    this.stderr = '';
    this.proc.stderr.on('data', d => { this.stderr = (this.stderr + d).slice(-4000); });
    this.proc.stdout.on('data', d => {
      this.buf += d; let i;
      while ((i = this.buf.indexOf('\n')) >= 0) {
        const line = this.buf.slice(0, i); this.buf = this.buf.slice(i + 1);
        let m; try { m = JSON.parse(line); } catch { continue; }
        if (m.type === 'system' && m.subtype === 'init') this.init = { model: m.model, tools: m.tools, mcp_servers: m.mcp_servers, memory_paths: m.memory_paths, apiKeySource: m.apiKeySource, claude_code_version: m.claude_code_version, skills: m.skills, plugins: m.plugins, agents: m.agents };
        if (m.type === 'assistant') { this.lastModel = m.message?.model ?? this.lastModel; this.turnModels?.add(this.lastModel); }
        if (m.type === 'result' && this.waiter) { const w = this.waiter; this.waiter = null; w.resolve(m); }
      }
    });
    this.proc.on('exit', (code) => { if (this.waiter) { const w = this.waiter; this.waiter = null; w.reject(new Error(`brain exited ${code}: ${this.stderr.slice(-300)}`)); } });
    return this;
  }
  async turn(text) {
    if (!this.proc) this.start();
    const t0 = Date.now();
    const res = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiter = null; reject(new Error('brain turn timeout')); }, this.turnTimeoutMs);
      this.waiter = { resolve: (m) => { clearTimeout(timer); resolve(m); }, reject: (e) => { clearTimeout(timer); reject(e); } };
      this.turnModels = new Set();
      this.proc.stdin.write(JSON.stringify({ type: 'user', message: { role: 'user', content: text } }) + '\n');
    });
    this.calls++;
    const u = res.usage ?? {};
    for (const k of Object.keys(this.usage)) this.usage[k] += u[k] ?? 0;
    const cum = Number(res.total_cost_usd ?? 0); const turnCost = Math.max(0, cum - this.lastCost); this.lastCost = cum; this.costUsd = cum;
    // Safety-classifier stops: the CLI withholds the stopped response and retries on a fallback model; record both.
    const stops = Number(res.safety_stops ?? 0); this.safetyStops += stops;
    for (const [k, v] of Object.entries(res.model_usage_since_last_result ?? {})) { const a = this.modelUsage[k] ??= { outputTokens: 0, costUSD: 0 }; a.outputTokens += v.outputTokens ?? 0; a.costUSD += v.costUSD ?? 0; }
    const models = [...(this.turnModels ?? [])]; for (const m of models) this.servedModels[m] = (this.servedModels[m] ?? 0) + 1;
    const parsed = parseModelReply(res.result);
    const entry = { at: new Date().toISOString(), wallMs: Date.now() - t0, input: text, reply: res.result, isError: !!res.is_error, stopReason: res.stop_reason ?? null,
      usage: { input_tokens: u.input_tokens, output_tokens: u.output_tokens, cache_read_input_tokens: u.cache_read_input_tokens, cache_creation_input_tokens: u.cache_creation_input_tokens }, turnCostUsd: turnCost, model: this.lastModel ?? this.model, servedModels: models, safetyStops: stops };
    this.transcript.push(entry);
    return { parsed, reply: res.result, entry };
  }
  stop() { try { this.proc?.stdin.end(); } catch {} setTimeout(() => { try { this.proc?.kill('SIGTERM'); } catch {} }, 2000).unref?.(); }
  stats() { return { model: this.model, servedModel: this.lastModel ?? null, servedModels: this.servedModels, safetyStops: this.safetyStops, modelUsage: this.modelUsage, calls: this.calls, usage: this.usage, costUsd: this.costUsd, init: this.init }; }
}

/** Deterministic stand-in used ONLY for plumbing tests and the scripted smoke suite. NOT an LLM. */
export class ScriptedBrain {
  constructor(script) { this.script = script; this.i = 0; this.transcript = []; this.calls = 0; }
  start() { return this; }
  async turn(text) {
    const v = typeof this.script === 'function' ? this.script(text, this.i) : this.script[this.i] ?? { analysis: 'done', actions: [{ type: 'wait' }] };
    this.i++; this.calls++;
    const reply = JSON.stringify(v);
    const entry = { at: new Date().toISOString(), input: text, reply, scripted: true };
    this.transcript.push(entry);
    return { parsed: { ok: true, value: v }, reply, entry };
  }
  stop() {}
  stats() { return { model: 'SCRIPTED (no LLM)', calls: this.calls, usage: null, costUsd: 0 }; }
}
