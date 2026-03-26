from pathlib import Path

from surfacescope.modules.pipeline import run_pipeline


def test_demo_pipeline_creates_reports(tmp_path: Path):
    records = run_pipeline(target="demo", output_dir=tmp_path.as_posix(), demo=True)
    assert len(records) == 1
    assert (tmp_path / "final_results.json").exists()
    assert (tmp_path / "report.html").exists()
    assert records[0]["severity"] in {"low", "medium", "high"}
