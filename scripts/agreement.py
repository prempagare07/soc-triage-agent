#!/usr/bin/env python3
"""Agreement between the two evidence-check judges, for the report.

  python scripts/agreement.py outputs/m2_openai/evidence_check
"""
import csv, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from soc.eval_metrics import cohen_kappa

folder = Path(sys.argv[1] if len(sys.argv) > 1 else "outputs/m2_openai/evidence_check")
col = "relevant (yes/partly/no)"
sheets = {p.stem.split("_")[-1]: list(csv.DictReader(p.open())) for p in sorted(folder.glob("evidence_check_*.csv"))}
(n1, s1), (n2, s2) = sheets.items()
a = [r[col].strip().lower() for r in s1]
b = [r[col].strip().lower() for r in s2]
if "" in a + b:
    sys.exit("both sheets need an answer on every row first")
agree = sum(x == y for x, y in zip(a, b))
print(f"{len(a)} claims, judges {n1} and {n2}")
print(f"agreement: {agree}/{len(a)} ({agree / len(a):.0%}), Cohen's kappa {cohen_kappa(a, b):.2f}")
for name, labels in ((n1, a), (n2, b)):
    print(f"{name}: yes {labels.count('yes')}, partly {labels.count('partly')}, no {labels.count('no')}")
both_yes = sum(x == y == "yes" for x, y in zip(a, b))
print(f"claims both judges marked relevant: {both_yes}/{len(a)}")
