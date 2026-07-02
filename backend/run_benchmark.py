from __future__ import annotations

import csv
import json
from pathlib import Path

from app.evaluation.benchmark import run_benchmark

if __name__ == "__main__":
    response = run_benchmark(use_llm=False)
    out_dir = Path(__file__).resolve().parents[1] / "experiments"
    out_dir.mkdir(exist_ok=True)
    json_path = out_dir / "benchmark_results.json"
    csv_path = out_dir / "benchmark_results.csv"
    json_path.write_text(response.model_dump_json(indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["case_id", "title", "expected_categories", "detected_categories", "category_recall", "expected_min_severity", "predicted_severity", "severity_pass", "risk_score"],
        )
        writer.writeheader()
        for row in response.results:
            payload = row.model_dump()
            payload["expected_categories"] = "; ".join(payload["expected_categories"])
            payload["detected_categories"] = "; ".join(payload["detected_categories"])
            writer.writerow(payload)
    print(f"Benchmark complete: {response.average_category_recall=}, {response.severity_pass_rate=}")
    print(f"Wrote {json_path}")
    print(f"Wrote {csv_path}")
