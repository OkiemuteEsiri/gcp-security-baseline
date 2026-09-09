from __future__ import annotations

import argparse
import json
from pathlib import Path

from .assessor import assess_inventory
from .reporting import render_markdown


def main() -> int:
    parser = argparse.ArgumentParser(description="Assess a synthetic GCP inventory against security baseline controls.")
    parser.add_argument("inventory", type=Path, help="Path to JSON inventory")
    parser.add_argument("--output", type=Path, help="Optional Markdown report path")
    args = parser.parse_args()

    records = json.loads(args.inventory.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("Inventory root must be a JSON list")

    result = assess_inventory(records)
    report = render_markdown(result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
