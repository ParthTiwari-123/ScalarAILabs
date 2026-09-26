"""
evaluate.py
-----------
Runs the detectors against test datasets, compares detected spans
to ground truth items, and reports metrics.
"""

import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from detectors import detect_all


def load_lines(path):
    with open(path, encoding="utf-8") as f:
        return f.readlines()


def main():
    here = os.path.dirname(__file__)
    log_name = sys.argv[1] if len(sys.argv) > 1 else "test_ticket_log.txt"
    gt_name = sys.argv[2] if len(sys.argv) > 2 else "ground_truth.json"
    
    lines = load_lines(os.path.join(here, log_name))
    with open(os.path.join(here, gt_name), encoding="utf-8") as f:
        ground_truth = json.load(f)

    detected_by_line = {}
    for i, line in enumerate(lines, start=1):
        spans = detect_all(line)
        detected_by_line[i] = [(s.pii_type, s.text) for s in spans]

    gt_remaining = {i: list(items) for i, items in
                    __import__("itertools").groupby(sorted(ground_truth, key=lambda x: x["line"]), key=lambda x: x["line"])}

    results = {}
    tp_details, fp_details, fn_details = [], [], []

    for i, line in enumerate(lines, start=1):
        gt_items = gt_remaining.get(i, [])
        gt_used = [False] * len(gt_items)
        for (dtype, dtext) in detected_by_line.get(i, []):
            results.setdefault(dtype, {"tp": 0, "fp": 0, "fn": 0})
            match_idx = None
            for j, gt in enumerate(gt_items):
                if gt_used[j] or gt["type"] != dtype:
                    continue
                if dtext.strip() == gt["text"].strip() or gt["text"].strip() in dtext.strip() or dtext.strip() in gt["text"].strip():
                    match_idx = j
                    break
            if match_idx is not None:
                gt_used[match_idx] = True
                results[dtype]["tp"] += 1
                tp_details.append((i, dtype, dtext))
            else:
                results[dtype]["fp"] += 1
                fp_details.append((i, dtype, dtext))
        for j, gt in enumerate(gt_items):
            if not gt_used[j]:
                results.setdefault(gt["type"], {"tp": 0, "fp": 0, "fn": 0})
                results[gt["type"]]["fn"] += 1
                fn_details.append((i, gt["type"], gt["text"]))

    total_tp = sum(r["tp"] for r in results.values())
    total_fp = sum(r["fp"] for r in results.values())
    total_fn = sum(r["fn"] for r in results.values())

    print(f"{'TYPE':<15}{'TP':<5}{'FP':<5}{'FN':<5}{'Precision':<12}{'Recall':<10}{'F1':<8}")
    for t in sorted(results):
        r = results[t]
        p = r["tp"] / (r["tp"] + r["fp"]) if (r["tp"] + r["fp"]) else float("nan")
        rec = r["tp"] / (r["tp"] + r["fn"]) if (r["tp"] + r["fn"]) else float("nan")
        f1 = 2 * p * rec / (p + rec) if (p + rec) and p == p and rec == rec and (p + rec) > 0 else float("nan")
        print(f"{t:<15}{r['tp']:<5}{r['fp']:<5}{r['fn']:<5}{p:<12.2f}{rec:<10.2f}{f1:<8.2f}")

    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else float("nan")
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else float("nan")
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) else float("nan")
    accuracy = total_tp / (total_tp + total_fp + total_fn) if (total_tp + total_fp + total_fn) else float("nan")

    print("\n=== OVERALL ===")
    print(f"TP={total_tp}  FP={total_fp}  FN={total_fn}")
    print(f"Precision={overall_p:.3f}  Recall={overall_r:.3f}  F1={overall_f1:.3f}  Accuracy={accuracy:.3f}")


if __name__ == "__main__":
    main()