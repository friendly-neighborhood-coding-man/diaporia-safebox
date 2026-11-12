// Tiny strict argv parser shared by the CLIs: --key value pairs and bare --flags only.
export function parseArgs(argv, { flags = [] } = {}) {
  const [cmd, ...rest] = argv;
  const out = { _cmd: cmd };
  for (let k = 0; k < rest.length; k++) {
    const a = rest[k];
    if (!a.startsWith('--')) throw new Error(`unexpected argument: ${a}`);
    const name = a.slice(2);
    if (flags.includes(name)) { out[name] = true; continue; }
    if (k + 1 >= rest.length) throw new Error(`missing value for --${name}`);
    out[name] = rest[++k];
  }
  return out;
}
export const need = (o, ...keys) => { for (const k of keys) if (o[k] === undefined) throw new Error(`--${k} is required`); };
