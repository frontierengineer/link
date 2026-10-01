// JSON Canonicalization Scheme, RFC 8785, for every JSON value type.
//
// - Numbers serialize as ECMAScript's Number::toString, which JSON.stringify
//   applies to finite numbers (RFC 8785 section 3.2.2.3). NaN and Infinity are
//   not JSON and are refused.
// - Strings serialize as ECMAScript's JSON.stringify does (section 3.2.2.2).
//   Lone surrogates are refused: JCS input must be I-JSON (RFC 7493).
// - Object members are sorted by the UTF-16 code units of their names
//   (section 3.2.3), recursively; arrays keep their order.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function compareUtf16(a: string, b: string): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = a.charCodeAt(i) - b.charCodeAt(i);
    if (d !== 0) return d;
  }
  return a.length - b.length;
}

function str(s: string): string {
  if (LONE_SURROGATE.test(s)) throw new Error('jcs: string contains a lone surrogate');
  return JSON.stringify(s);
}

export function canonicalize(value: unknown): string {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('jcs: non-finite number');
      return JSON.stringify(value);
    case 'string':
      return str(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new Error('jcs: not a plain object');
      const keys = Object.keys(value).sort(compareUtf16);
      const parts: string[] = [];
      for (const k of keys) {
        const v = (value as Record<string, unknown>)[k];
        if (v === undefined) throw new Error(`jcs: member ${k} is undefined`);
        parts.push(`${str(k)}:${canonicalize(v)}`);
      }
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`jcs: unsupported type ${typeof value}`);
  }
}
