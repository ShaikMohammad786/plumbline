"""Benchmark tests for repository ingest and UCM extraction performance."""

import time
from pathlib import Path

from plumbline.config import PlumblineConfig
from plumbline.ingest.walker import walk_repository
from plumbline.ucm.builder import extract_file_facts


def test_synthetic_5000_files_performance(tmp_path: Path) -> None:
    """A synthetic directory of 5,000 small files scans in under 5 seconds."""
    bench_dir = tmp_path / "synthetic_repo"
    bench_dir.mkdir()

    # Generate 5,000 files distributed in 50 directories
    for pkg in range(50):
        pkg_dir = bench_dir / f"pkg_{pkg}"
        pkg_dir.mkdir()
        for i in range(100):
            file_path = pkg_dir / f"mod_{i}.py"
            file_path.write_text(
                f"# Module {i}\ndef calculate_{i}(x, y):\n    return x + y\n", encoding="utf-8"
            )

    start = time.perf_counter()
    cfg = PlumblineConfig()
    result = walk_repository(bench_dir, cfg)
    assert len(result.files) == 5000

    for fe in result.files:
        if fe.text:
            extract_file_facts(fe.path, fe.language, fe.text)

    duration = time.perf_counter() - start
    # Must meet the 5-second performance budget
    assert duration < 5.0, f"5,000 files scan took {duration:.3f}s (budget: 5.0s)"
