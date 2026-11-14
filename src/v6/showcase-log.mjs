/** One physical log line. Newlines in any field cannot forge a second record. */
export function showcaseLogLine(clip, kind, text) {
  const flat = (s) => String(s ?? '').replace(/[\r\n]/g, ' ');
  return `[${flat(clip)}] ${flat(kind).padEnd(7)} ${flat(text)}`;
}
