from pathlib import Path

from typer.testing import CliRunner

from bench.run_bench import run_benchmark
from plumbline.cli import app

runner = CliRunner()


def test_benchmark_execution() -> None:
    bench_dir = Path("bench")
    res = run_benchmark(bench_dir=bench_dir)
    assert res.target_met is True
    assert res.overall_recall >= 0.85
    assert res.overall_precision >= 0.85
    assert res.decoys_clean == 20
    assert res.claims_correct == res.claims_total
    assert (bench_dir / "RESULTS.md").exists()


def test_cli_bench_command() -> None:
    res = runner.invoke(app, ["bench"])
    assert res.exit_code == 0
    assert "Benchmark Status: PASSED" in res.output
    assert "OVERALL" in res.output
