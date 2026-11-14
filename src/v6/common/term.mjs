// One terminal line per event (CodeQL js/log-injection): CR/LF, ANSI escapes, other C0/C1 controls and bidi
// overrides, invisible format characters (LRM/RLM/ALM, zero-width, word joiner, BOM, interlinear
// annotation, Hangul fillers) and Unicode tag characters in request-derived text (memo, subject, hold reason) are shown as \u{X} / \n, never interpreted, so
// nothing a request carries can forge or recolour a line in the live demo terminal. Tabs and printable Unicode pass.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u115f\u1160\u200b-\u200f\u2028-\u202e\u2060-\u2069\u3164\ufeff\ufff9-\ufffb\u{e0000}-\u{e007f}]/gu;
export const termSafe = (t) => String(t).replace(UNSAFE, (ch) => '\\u{' + ch.codePointAt(0).toString(16) + '}').replace(/\n/g, '\\n');
