#!/usr/bin/env bash
# T095 (SC-014) real-store fingerprint: path + size + mtime(ns) + sha256 of every
# file under the operator's durable stores. Read-only. Written to $1.
set -u
OUT="$1"
: > "$OUT"
for root in "$HOME/.vhlocal" "$HOME/vulnhunter-reports"; do
  [ -d "$root" ] || continue
  # -printf keeps mtime to the nanosecond so a rewrite with identical bytes is still visible.
  find "$root" -type f -printf '%p\t%s\t%T@\n' 2>/dev/null | LC_ALL=C sort >> "$OUT"
done
# Content hashes in a second pass (stable order), so the fingerprint proves bytes, not just metadata.
CUT="${OUT}.hashes"
: > "$CUT"
cut -f1 "$OUT" | while IFS= read -r f; do
  h=$(sha256sum -- "$f" 2>/dev/null | cut -d' ' -f1)
  printf '%s\t%s\n' "${h:-UNREADABLE}" "$f" >> "$CUT"
done
wc -l < "$OUT" > "${OUT}.count"
sha256sum "$OUT" "$CUT" | sed 's#/.*/##' > "${OUT}.summary"
cat "${OUT}.summary"
