// Repair the invalid Mermaid local models routinely emit, so a diagram renders
// instead of "Syntax error in text". Ported verbatim from the working vanilla UI
// (_fixMermaid). Every rule is conservative and idempotent.
export function fixMermaid(src: string): string {
  return src
    .split("\n")
    .map((line) => {
      line = line.replace(/\\+\s*$/, ""); // stray trailing backslash
      // Balance an unclosed node bracket / brace (model drops the closing ] or }).
      const need = (o: string, c: string) =>
        Math.max(0, line.split(o).length - 1 - (line.split(c).length - 1));
      line = line + "]".repeat(need("[", "]")) + "}".repeat(need("{", "}"));
      // Drop stray whitespace between a quoted label and its closing bracket.
      line = line.replace(/"\s+\]/g, '"]').replace(/"\s+\}/g, '"}');
      // Quote UNQUOTED node / subgraph bracket labels (spaces, parens, slashes,
      // unicode). Already-quoted labels contain " and are skipped — idempotent.
      line = line.replace(/([A-Za-z0-9_]+)\[([^\]"]+)\]/g, (_m, id, lbl) => `${id}["${lbl}"]`);
      line = line.replace(/([A-Za-z0-9_]+)\{([^}"]+)\}/g, (_m, id, lbl) => `${id}{"${lbl}"}`);
      // Quote UNQUOTED edge labels — |...| on an arrow (parens/slashes break it).
      line = line.replace(/\|([^|"\n]+)\|/g, (_m, lbl) => `|"${lbl.trim()}"|`);
      return line;
    })
    .join("\n")
    .trim();
}
