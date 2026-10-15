// Strict JSON, for every document the client reads from the relay or a peer (section 1):
// control messages, rosters, resignations and sealed pairing messages.
//
// - One JSON value (RFC 8259) and nothing after it but whitespace.
// - I-JSON (RFC 7493), as JCS requires of what it canonicalises: an object's member names
//   do not repeat (JSON.parse would keep the last), and no string or name holds a lone
//   surrogate, escaped or not.
// - At most MAX_JSON_DEPTH arrays and objects open at once.
// - Numbers are what JSON.parse makes of them, and must be finite. A member whose number
//   was written with a fraction or an exponent is remembered, so that a field the protocol
//   gives as an integer can require a non-negative integer literal, digits only: `12`, never
//   `12.0` or `1.2e1` (nor `-0`, which JSON.parse keeps as -0).
//
// The parser keeps its own stack rather than recursing.

import { hasLoneSurrogate } from './jcs.js';

/** The most arrays and objects open at once in a protocol JSON document (section 1). */
export const MAX_JSON_DEPTH = 32;

/** Members, per parsed object, whose number was written with a fraction or an exponent. */
const notIntegerLiterals = new WeakMap<object, Set<string>>();

const NUMBER = /-?(?:0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/y;
const HEX4 = /^[0-9a-fA-F]{4}$/;
const ESCAPES: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

type Open = { arr: unknown[] } | { obj: Record<string, unknown>; names: Set<string>; name: string };

/** Parses one strict JSON value; throws on anything JSON.parse would refuse, and on the above. */
export function parseJson(text: string): unknown {
  let i = 0;
  const stack: Open[] = [];

  const fail = (what: string): never => {
    throw new SyntaxError(`json: ${what} at offset ${i}`);
  };
  const ws = (): void => {
    for (;;) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x0a || c === 0x0d || c === 0x09) i++;
      else return;
    }
  };
  const str = (): string => {
    if (text.charCodeAt(i) !== 0x22) fail('expected a string');
    i++;
    let out = '';
    let start = i;
    for (;;) {
      const c = text.charCodeAt(i);
      if (Number.isNaN(c)) fail('unterminated string');
      if (c === 0x22) break;
      if (c < 0x20) fail('control character in a string');
      if (c !== 0x5c) {
        i++;
        continue;
      }
      out += text.slice(start, i);
      const e = text[i + 1] ?? '';
      if (e === 'u') {
        const hex = text.slice(i + 2, i + 6);
        if (!HEX4.test(hex)) fail('bad \\u escape');
        out += String.fromCharCode(parseInt(hex, 16));
        i += 6;
      } else {
        const ch = ESCAPES[e];
        if (ch === undefined) fail('bad escape');
        out += ch;
        i += 2;
      }
      start = i;
    }
    out += text.slice(start, i);
    i++;
    if (hasLoneSurrogate(out)) fail('lone surrogate in a string');
    return out;
  };
  const name = (o: { names: Set<string> }): string => {
    ws();
    const n = str();
    if (o.names.has(n)) fail(`duplicate member name ${JSON.stringify(n)}`);
    o.names.add(n);
    ws();
    if (text.charCodeAt(i) !== 0x3a) fail('expected ":"');
    i++;
    return n;
  };

  for (;;) {
    // One value starts at i.
    ws();
    let value: unknown;
    let notInteger = false;
    const c = text[i];
    if ((c === '{' || c === '[') && stack.length >= MAX_JSON_DEPTH) fail('nested too deeply');
    if (c === '{') {
      i++;
      ws();
      if (text[i] === '}') {
        i++;
        value = {};
      } else {
        const o = { obj: {} as Record<string, unknown>, names: new Set<string>(), name: '' };
        o.name = name(o);
        stack.push(o);
        continue;
      }
    } else if (c === '[') {
      i++;
      ws();
      if (text[i] === ']') {
        i++;
        value = [];
      } else {
        stack.push({ arr: [] });
        continue;
      }
    } else if (c === '"') {
      value = str();
    } else if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) {
      NUMBER.lastIndex = i;
      const m = NUMBER.exec(text);
      if (!m) fail('bad number');
      const n = Number(m![0]);
      if (!Number.isFinite(n)) fail('number out of range');
      value = n;
      notInteger = m![1] !== undefined || m![2] !== undefined;
      i += m![0].length;
    } else if (text.startsWith('true', i)) {
      value = true;
      i += 4;
    } else if (text.startsWith('false', i)) {
      value = false;
      i += 5;
    } else if (text.startsWith('null', i)) {
      value = null;
      i += 4;
    } else {
      fail(c === undefined ? 'unexpected end' : 'unexpected character');
    }

    // The value is complete: add it to what is open, closing every container it completes.
    for (;;) {
      const top = stack[stack.length - 1];
      ws();
      if (!top) {
        if (i !== text.length) fail('trailing data');
        return value;
      }
      if ('arr' in top) {
        top.arr.push(value);
        if (text[i] === ',') {
          i++;
          break;
        }
        if (text[i] !== ']') fail('expected "," or "]"');
        i++;
        value = top.arr;
      } else {
        Object.defineProperty(top.obj, top.name, { value, writable: true, enumerable: true, configurable: true });
        if (notInteger) {
          let set = notIntegerLiterals.get(top.obj);
          if (!set) notIntegerLiterals.set(top.obj, (set = new Set()));
          set.add(top.name);
        }
        if (text[i] === ',') {
          i++;
          top.name = name(top);
          break;
        }
        if (text[i] !== '}') fail('expected "," or "}"');
        i++;
        value = top.obj;
      }
      notInteger = false;
      stack.pop();
    }
  }
}

/**
 * `obj[key]` when it is an integer of at most 2^53 − 1 written as a non-negative integer
 * literal (digits only: no sign, fraction or exponent); otherwise undefined. Objects built in
 * code, not parsed, have only their values to go by.
 */
export function integerMember(obj: object, key: string): number | undefined {
  if (!Object.hasOwn(obj, key)) return undefined;
  const v = (obj as Record<string, unknown>)[key];
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0 || Object.is(v, -0)) return undefined;
  if (notIntegerLiterals.get(obj)?.has(key)) return undefined;
  return v;
}
