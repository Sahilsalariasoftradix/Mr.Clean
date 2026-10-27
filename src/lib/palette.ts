/** Matching for the command palette (⌘K). */

export interface Command {
  id: string;
  group: "Go to" | "Actions" | "Results";
  title: string;
  /** Extra words that should find this command ("delete", "trash"…). */
  keywords?: string;
  /** Shown on the right: a shortcut or a size. */
  hint?: string;
}

/**
 * How well `query` matches a command; 0 = no match. Every word typed must
 * appear somewhere in the title or keywords. Matches at the start of the title
 * or of a word rank higher, so "sec" finds "Security" before "Run security scan".
 */
export function score(query: string, c: Pick<Command, "title" | "keywords">): number {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return 1;
  const title = c.title.toLowerCase();
  const hay = `${title} ${(c.keywords ?? "").toLowerCase()}`;
  let total = 0;
  for (const w of words) {
    const at = hay.indexOf(w);
    if (at < 0) return 0;
    if (title.startsWith(w)) total += 4;
    else if (new RegExp(`(^|[\\s/(.-])${escape(w)}`).test(title)) total += 3;
    else if (title.includes(w)) total += 2;
    else total += 1;
  }
  return total;
}

function escape(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Commands that match, best first; ties keep their original order. */
export function filter<T extends Command>(commands: T[], query: string, limit = 50): T[] {
  return commands
    .map((c, i) => ({ c, i, s: score(query, c) }))
    .filter((x) => x.s > 0)
    .sort((a, b) => b.s - a.s || a.i - b.i)
    .slice(0, limit)
    .map((x) => x.c);
}
