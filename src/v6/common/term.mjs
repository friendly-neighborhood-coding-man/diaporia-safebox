// One terminal line per event (CodeQL js/log-injection): CR/LF, ANSI escapes, other C0/C1 controls and bidi
// overrides in request-derived text (memo, subject, hold reason) are shown as \uXXXX / \n, never interpreted, so
// nothing a request carries can forge or recolour a line in the live demo terminal. Tabs and printable Unicode pass.
// eslint-disable-next-line no-control-regex
const UNSAFE = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;
export const termSafe = (t) => String(t).replace(UNSAFE, (ch) => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0')).replace(/\n/g, '\\n');
