"""Audit #21: an abuser may notice scanning or removal, and evidence should be
kept before anything is removed. The README and the site must say so and point
to real help."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("doc", ["README.md", "docs/index.html"])
def test_safety_guidance_is_published(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    low = text.lower()
    assert "stopstalkerware.org" in low
    assert "document first" in low
    assert "if you think someone is watching you" in low
