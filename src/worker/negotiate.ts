// Accept-header negotiation between a page's HTML and its Markdown version for agents.
// Browsers never ask for text/markdown, so Markdown is served only when the client names it
// explicitly and doesn't prefer HTML.

interface Range {
  type: string;
  subtype: string;
  q: number;
}

function parseAccept(header: string): Range[] {
  const ranges: Range[] = [];
  for (const part of header.slice(0, 1024).split(",")) {
    const [media = "", ...params] = part.split(";").map((s) => s.trim().toLowerCase());
    const [type, subtype] = media.split("/");
    if (!type || !subtype) continue;
    let q = 1;
    for (const param of params) {
      const m = /^q=([01](?:\.\d{0,3})?)$/.exec(param);
      if (m) q = Math.min(1, Number(m[1]));
    }
    ranges.push({ type, subtype, q });
  }
  return ranges;
}

/** The quality the client gives a media type: from its most specific matching range, or 0. */
function quality(ranges: Range[], type: string, subtype: string): { q: number; explicit: boolean } {
  let best = { q: 0, explicit: false, rank: -1 };
  for (const r of ranges) {
    const rank =
      r.type === type && r.subtype === subtype ? 2 : r.type === type && r.subtype === "*" ? 1 : r.type === "*" && r.subtype === "*" ? 0 : -1;
    if (rank > best.rank) best = { q: r.q, explicit: rank === 2, rank };
  }
  return { q: best.q, explicit: best.explicit };
}

export function prefersMarkdown(accept: string | null): boolean {
  if (!accept) return false;
  const ranges = parseAccept(accept);
  const markdown = quality(ranges, "text", "markdown");
  return markdown.explicit && markdown.q > 0 && markdown.q >= quality(ranges, "text", "html").q;
}
