#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10,<3.14"
# dependencies = ["torch>=2.10,<3", "torchvision>=0.25,<1"]
# ///
"""Generate TorchScript fixture files for tests.

These fixtures are checked into the repository so that tests don't need
to call torch.jit.script/torch.jit.save at runtime (which emits
deprecation warnings on Python 3.14+ and may be removed in future
PyTorch versions).

Usage:
    uv run test/fixtures/generate_fixtures.py
"""

import warnings
from pathlib import Path

import torch
import torchvision.models as models

FIXTURES_DIR = Path(__file__).parent


def main():
    model = models.squeezenet1_0()
    scripted = torch.jit.script(model)

    out = FIXTURES_DIR / "squeezenet1_0_torchscript_v1_4.pt"
    torch.jit.save(scripted, out)
    print(f"Generated {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
