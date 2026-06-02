import type { Break, Paragraph, Root, RootContent, Text } from "mdast";
import type { VFile } from "vfile";

// Bugcrowd renders submissions with a classic-Markdown / Redcarpet engine that
// is stricter than CommonMark about block separation: a block-level element
// MUST be preceded by a blank line, otherwise the engine does not recognise it
// and swallows the raw markup into the preceding paragraph as literal text.
//
// CommonMark (what `@uiw/react-md-editor` uses) is lenient — it lets a heading,
// list, table, etc. interrupt a paragraph with no blank line. That mismatch is
// why authors see "the ### heading disappeared" / "my list shifted" after
// pasting into Bugcrowd: it looked fine in the lenient preview but Bugcrowd's
// strict parser absorbed it.
//
// This remark plugin reproduces Bugcrowd's strict behaviour in the preview, so
// what you see while authoring matches what Bugcrowd renders. The fix the author
// learns is the correct one everywhere: leave a blank line before every block.
const ABSORBABLE = new Set<RootContent["type"]>([
  "heading",
  "list",
  "blockquote",
  "code",
  "table",
  "thematicBreak",
]);

export function remarkBugcrowdStrictBlocks() {
  return (tree: Root, file: VFile) => {
    const src =
      typeof file?.value === "string" ? file.value : String(file?.value ?? "");
    const lines = src.split("\n");
    const merged: RootContent[] = [];

    for (const node of tree.children) {
      const prev = merged[merged.length - 1] as Paragraph | undefined;
      const adjacent =
        prev?.type === "paragraph" &&
        !!prev.position &&
        !!node.position &&
        ABSORBABLE.has(node.type) &&
        node.position.start.line === prev.position.end.line + 1;

      if (adjacent && prev && node.position && prev.position) {
        // Slice the raw source lines of the absorbed block (positions are
        // 1-based; the array slice end is exclusive, i.e. inclusive of end.line).
        const raw = lines.slice(
          node.position.start.line - 1,
          node.position.end.line,
        );
        // Re-emit each line as literal text joined by hard breaks, matching the
        // hard_wrap rendering used for the rest of the paragraph. The markup
        // (e.g. "## ") shows verbatim — exactly how Bugcrowd renders it.
        for (const line of raw) {
          prev.children.push({ type: "break" } as Break);
          prev.children.push({ type: "text", value: line } as Text);
        }
        // Extend the paragraph so a following adjacent block chains into it too.
        prev.position.end = node.position.end;
        continue;
      }
      merged.push(node);
    }

    tree.children = merged;
  };
}
