#!/usr/bin/env python3
"""Copy annotate.js into every session deck, so each deck stays one self-contained HTML file.

Run from the repo root after changing annotate.js:  python3 tools/inline-annotate.py
A new deck gets the block just before its last </body>; later runs replace the block in place."""
import glob, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
START, END = '<!-- annotate:start -->', '<!-- annotate:end -->'

js = open(os.path.join(ROOT, 'annotate.js'), encoding='utf-8').read().strip()
assert '</script' not in js.lower()
block = START + '\n<script>\n' + js + '\n</script>\n' + END

for path in sorted(glob.glob(os.path.join(ROOT, 'Cyber_*.html'))):
    html = open(path, encoding='utf-8').read()
    if START in html:
        new = re.sub(re.escape(START) + '.*?' + re.escape(END), lambda m: block, html, count=1, flags=re.S)
    else:
        i = html.rfind('</body>')
        if i < 0:
            print('skip (no </body>):', os.path.basename(path)); continue
        new = html[:i] + block + '\n' + html[i:]
    if new != html:
        open(path, 'w', encoding='utf-8').write(new)
        print('updated', os.path.basename(path))
    else:
        print('unchanged', os.path.basename(path))
