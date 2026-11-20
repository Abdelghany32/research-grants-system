#!/usr/bin/env python3
"""Fetch a handful of Tabler Icons (MIT) at a pinned release and build one local
SVG sprite, so the interface works offline. Re-run only to change the icon set."""
import re, sys, urllib.request, pathlib

RELEASE = "v3.51.0"
BASE = f"https://raw.githubusercontent.com/tabler/tabler-icons/{RELEASE}"
# sprite id -> Tabler outline icon name
ICONS = {
    "proposals": "file-text", "reviews": "clipboard-check", "decisions": "gavel",
    "calls": "speakerphone", "audit": "history", "logout": "logout",
    "alert": "alert-triangle", "check": "circle-check", "denied": "ban",
    "plus": "plus", "search": "search", "send": "send", "save": "device-floppy",
    "lock": "lock", "trash": "trash", "arrow": "arrow-right",
    "download": "download", "shield": "shield-lock", "mail": "mail",
}
out = pathlib.Path(__file__).resolve().parent.parent / "public/assets/icons"
out.mkdir(parents=True, exist_ok=True)

def get(path):
    with urllib.request.urlopen(f"{BASE}/{path}", timeout=20) as r:
        return r.read().decode()

symbols = []
for sid, name in ICONS.items():
    svg = get(f"icons/outline/{name}.svg")
    inner = re.search(r"<svg[^>]*>(.*)</svg>", svg, re.S).group(1).strip()
    symbols.append(f'<symbol id="{sid}" viewBox="0 0 24 24"><!-- tabler:{name} -->{inner}</symbol>')
(out / "sprite.svg").write_text(
    f'<!-- Tabler Icons {RELEASE} (MIT). See LICENSE-tabler-icons.txt -->\n'
    '<svg xmlns="http://www.w3.org/2000/svg">\n' + "\n".join(symbols) + "\n</svg>\n")
(out / "LICENSE-tabler-icons.txt").write_text(get("LICENSE"))
print(f"{len(symbols)} icons from tabler-icons {RELEASE} -> {out}/sprite.svg")
