"""Keep the "Status at a glance" table in docs/ROADMAP.md in step with the
checkboxes below it.

    python scripts/roadmap_status.py           # rewrite the "Done" column and the total
    python scripts/roadmap_status.py --check   # exit 1 if the table is out of date (CI)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROADMAP = Path(__file__).resolve().parent.parent / "docs" / "ROADMAP.md"


def _anchor(title: str) -> str:
    a = re.sub(r"[^\w\- ]", "", title.lower()).strip().replace(" ", "-")
    return a


def counts(text: str) -> dict[str, tuple[int, int]]:
    out = {}
    for sec in re.split(r"\n## ", text)[1:]:
        title = sec.splitlines()[0].strip()
        done, open_ = sec.count("\n- [x]"), sec.count("\n- [ ]")
        if done + open_:
            out[_anchor(title)] = (done, done + open_)
    return out


def updated(text: str) -> str:
    c = counts(text)
    total_done = sum(d for d, _ in c.values())
    total = sum(n for _, n in c.values())

    def row(m):
        anchor = m.group(2)
        if anchor not in c:
            return m.group(0)
        d, n = c[anchor]
        return f"{m.group(1)}{d} of {n} |"

    text = re.sub(r"(\| \[[^\]]+\]\(#([\w\-]+)\) \| [^|]+ \| )\d+ of \d+ \|", row, text)
    return re.sub(r"\| Total \| \| \d+ of \d+ \|", f"| Total | | {total_done} of {total} |", text)


def main() -> int:
    text = ROADMAP.read_text()
    new = updated(text)
    if "--check" in sys.argv:
        if new != text:
            print("docs/ROADMAP.md: the status table does not match the checkboxes; "
                  "run python scripts/roadmap_status.py", file=sys.stderr)
            return 1
        return 0
    ROADMAP.write_text(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
