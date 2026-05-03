// Hostname helpers — used to pivot scan output (which records URLs/hosts
// in mixed shapes) into a normalised hostname key.
//
// The canonical hostname form across the panel: lowercase, no port, no
// scheme, no trailing slash. This matches the F4 host-annotations key
// rule on the backend, so once we send annotations the keys line up.

export function normalizeHostname(input: string): string {
  if (!input) return "";
  let s = input.trim().toLowerCase();
  // strip scheme
  const schemeMatch = s.match(/^[a-z][a-z0-9+.\-]*:\/\//);
  if (schemeMatch) s = s.slice(schemeMatch[0].length);
  // drop path/query/fragment
  s = s.split(/[/?#]/, 1)[0];
  // strip port
  s = s.replace(/:\d+$/, "");
  return s;
}

export function hostnameFromURL(url: string | undefined | null): string {
  if (!url) return "";
  return normalizeHostname(url);
}
