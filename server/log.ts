type Level = 'info' | 'warn' | 'error';

// One JSON object per line — greppable, and ready for any log shipper without a
// parser. Errors go to stderr so k8s separates them from the normal stream.
//
// Privacy: nothing that flows through a link is ever loggable. Callers must
// only pass lifecycle facts (ports, counts, signals) — never addresses or frame
// contents.
export function log(level: Level, msg: string, fields: Record<string, unknown> = {}): void {
  const line = JSON.stringify({ level, msg, ...fields, t: new Date().toISOString() });
  if (level === 'error') process.stderr.write(line + '\n');
  else process.stdout.write(line + '\n');
}
