import test from 'node:test';
import assert from 'node:assert/strict';
import { showcaseLogLine } from '../../src/v6/showcase-log.mjs';

test('showcase log lines cannot be split by a newline in the text', () => {
  const line = showcaseLogLine('main', 'AI', 'prepared\n[main] OK      forged record');
  assert.equal(line.includes('\n'), false);
  assert.equal(line.split('\n').length, 1);
  assert.match(line, /^\[main\] AI +prepared \[main\] OK +forged record$/);
});
