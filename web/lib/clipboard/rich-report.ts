// Copy an image's decoded bytes onto the clipboard as `image/png`, the way
// pasting a screenshot works. Cloud editors (Bugcrowd, Notion, …) receive real
// image data and upload it to their own storage — there's no URL, so the
// unreachable-localhost problem disappears.
//
// Non-PNG sources (JPEG/WebP/GIF) are re-encoded to PNG via canvas because
// Safari's clipboard only accepts `image/png`. The blob is supplied as a
// Promise so the synchronous `clipboard.write` call stays inside the user
// gesture — required by Safari, tolerated by Chrome.
export async function copyImageAsPng(url: string): Promise<void> {
  const toPng = (async () => {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`fetch failed (${res.status})`);
    const blob = await res.blob();
    if (blob.type === "image/png") return blob;
    const bitmap = await createImageBitmap(blob);
    const canvas = document.createElement("canvas");
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext("2d");
    if (!ctx) throw new Error("canvas 2d context unavailable");
    ctx.drawImage(bitmap, 0, 0);
    const png = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, "image/png"),
    );
    if (!png) throw new Error("PNG encode failed");
    return png;
  })();
  await navigator.clipboard.write([new ClipboardItem({ "image/png": toPng })]);
}
