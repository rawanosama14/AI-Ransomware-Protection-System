"""Safe demo simulator.

This script creates harmless demo files and renames them to .locked so the GUI
can show alerts. It does not encrypt or damage existing files.
"""
from __future__ import annotations

import os
import random
import string
import time
from pathlib import Path


def create_demo_activity(folder: str, count: int = 15, delay: float = 0.08) -> None:
    target = Path(folder).expanduser().resolve()
    target.mkdir(parents=True, exist_ok=True)
    for i in range(count):
        p = target / f"demo_file_{i:02d}.txt"
        random_text = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(2048))
        p.write_text(random_text, encoding="utf-8")
        time.sleep(delay)
        locked = target / f"demo_file_{i:02d}.txt.locked"
        p.rename(locked)
        time.sleep(delay)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate safe demo ransomware-like file events.")
    parser.add_argument("folder", help="Folder to generate demo activity inside")
    parser.add_argument("--count", type=int, default=15)
    args = parser.parse_args()
    create_demo_activity(args.folder, args.count)
    print("Demo activity completed safely.")
