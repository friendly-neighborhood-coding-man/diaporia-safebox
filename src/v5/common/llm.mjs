// One-shot model call through the Claude Code CLI in print mode: NO tools, no MCP, no settings / memory sources, no
// session persistence, a scrubbed environment and a scratch HOME. The model is a pure text function. Every call
// records the REQUESTED and the SERVED model (modelUsage); any substitution, safety-classifier fallback or usage-limit
// error is surfaced to the caller as a guard stop (Eric 2026-11-13: Opus 4.8 only, never a silent substitute).
import { spawn } from 'node:child_process';
import { mkdirSync, copyFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

export const DEFAULT_MODEL = 'claude-opus-4-8';
export function scratchEnv(tag) {
  const home = `/tmp/sbx5-llm/${tag}`; mkdirSync(join(home, '.claude'), { recursive: true });
  if (existsSync('/root/.ccr/ca-bundle.crt')) copyFileSync('/root/.ccr/ca-bundle.crt', join(home, 'ca.crt'));
  const P = process.env;
  return { home, env: { PATH: '/opt/node22/bin:/usr/bin:/bin', HOME: home, ANTHROPIC_BASE_URL: 'https://api.anthropic.com', HTTPS_PROXY: P.HTTPS_PROXY, HTTP_PROXY: P.HTTPS_PROXY, https_proxy: P.HTTPS_PROXY,
    NO_PROXY: P.NO_PROXY, no_proxy: P.NO_PROXY, NODE_EXTRA_CA_CERTS: join(home, 'ca.crt'), SSL_CERT_FILE: join(home, 'ca.crt') } };
}
export function callModel({ model = DEFAULT_MODEL, system, user, tag = 'call', timeoutMs = 300_000, claudeBin = '/opt/node22/bin/claude' }) {
  const { home, env } = scratchEnv(tag);
  const args = ['-p', '--model', model, '--tools', '', '--strict-mcp-config', '--no-session-persistence', '--setting-sources', '', '--system-prompt', system, '--output-format', 'json'];
  return new Promise((resolve) => {
    const t0 = Date.now();
    const p = spawn(claudeBin, args, { env, cwd: home, stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '', err = '';
    const timer = setTimeout(() => { try { p.kill('SIGTERM'); } catch {} }, timeoutMs);
    p.stdout.on('data', d => { out += d; }); p.stderr.on('data', d => { err = (err + d).slice(-2000); });
    p.on('close', (code) => {
      clearTimeout(timer);
      let r = null; try { r = JSON.parse(out); } catch {}
      const served = r?.modelUsage ? Object.keys(r.modelUsage) : [];
      const text = String(r?.result ?? '');
      let guard = null;
      if (!r) guard = 'NO_RESULT:' + (err || out).slice(-200);
      else if (r.is_error && /limit|usage|quota|exceeded|rate/i.test(text)) guard = 'USAGE_LIMIT';
      else if (served.some(m => m !== model)) guard = 'MODEL_SUBSTITUTION:' + served.join(',');
      else if (Number(r.safety_stops ?? 0) > 0) guard = 'SAFETY_STOP_FALLBACK';
      else if (r.is_error) guard = 'MODEL_ERROR:' + text.slice(0, 200);
      resolve({ text, requestedModel: model, servedModels: served, costUsd: Number(r?.total_cost_usd ?? 0), usage: r?.usage ?? null, wallMs: Date.now() - t0, guard, exitCode: code });
    });
    p.stdin.end(user);
  });
}
/** Extracts the first JSON object from a model reply (fenced or bare). */
export function extractJson(text) {
  const m = String(text).match(/```(?:json)?\s*([\s\S]*?)```/); const s = m ? m[1] : String(text);
  const i = s.indexOf('{'), j = s.lastIndexOf('}'); if (i < 0 || j < i) return null;
  try { return JSON.parse(s.slice(i, j + 1)); } catch { return null; }
}
