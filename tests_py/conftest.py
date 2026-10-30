import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXAMPLES = os.path.join(ROOT, "examples")
sys.path.insert(0, os.path.join(ROOT, "web"))


def binary_path():
    for name in ("netguard.exe", "netguard"):
        path = os.path.join(ROOT, "bin", name)
        if os.path.isfile(path):
            return path
    raise RuntimeError("bin/netguard is not built; run 'make' first")
