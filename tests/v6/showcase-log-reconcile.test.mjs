// PR #25 is superseded by PR #26's termSafe. This file carries #25's case plus the residuals PR #28 found in #25
// (U+2028, U+2029, ANSI CSI) and pins that the showcase console line and the viewer go through the escaping helpers.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { termSafe } from '../../src/v6/common/term.mjs';

test('#25 case and PR #28 residuals: newline, CR/LF, U+2028, U+2029 and ANSI CSI never reach the terminal raw', () => {
  for (const forged of ['prepared\n[main] OK      forged', 'a\r\nb', 'a\u2028[main] OK forged', 'a\u2029b', 'a\u001b[2Ab', 'a\u009b2Ab']) {
    const out = termSafe(forged);
    assert.ok(!/[\r\n\u2028\u2029\u001b\u009b]/.test(out), JSON.stringify(out));
    assert.equal(out.split(/\r?\n|\u2028|\u2029/).length, 1);
  }
});

test('showcase: console line uses termSafe; the HTML viewer escapes kind, labels, text and time', () => {
  const src = readFileSync(new URL('../../scripts/v6/showcase.mjs', import.meta.url), 'utf8');
  assert.match(src, /console\.log\(`\[\$\{clip\}\] \$\{kind\.padEnd\(7\)\} \$\{termSafe\(text\)\}`\)/);
  assert.match(src, /'<span class="k">'\+H\(e\.kind\)\+'<\/span>'\+H\(e\.text\)/);
  assert.match(src, /'">'\+H\(l\)\+'<\/span>'/);
});
