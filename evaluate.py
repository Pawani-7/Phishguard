"""PhishGuard evaluation script.

Runs the tool on two text files of links and counts correct and wrong results:
    data/safe_links.txt      - links you know are safe
    data/phishing_links.txt  - reported phishing links (TEXT ONLY, never open them)

Run it with:  python evaluate.py
"""

import csv
import sys
from pathlib import Path

from scoring import analyse

DATA = Path("data")
SAFE_FILE = DATA / "safe_links.txt"
PHISHING_FILE = DATA / "phishing_links.txt"
RESULTS_FILE = DATA / "results.csv"

LEVEL_ORDER = {"Low": 0, "Medium": 1, "High": 2}


def read_links(path):
    """Read one link per line. Blank lines and lines starting with # are skipped."""
    if not path.exists():
        print(f"Missing file: {path}")
        sys.exit(1)
    links = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            links.append(line)
    return links


def percent(part, whole):
    """Return a percentage string, safe when whole is zero."""
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def summarise(rows, threshold):
    """Count results when 'flagged' means level >= threshold."""
    tp = fp = tn = fn = 0
    for row in rows:
        flagged = LEVEL_ORDER[row["level"]] >= LEVEL_ORDER[threshold]
        if row["label"] == "phishing":
            if flagged:
                tp += 1
            else:
                fn += 1
        else:
            if flagged:
                fp += 1
            else:
                tn += 1
    return tp, fp, tn, fn


def print_summary(rows, threshold):
    tp, fp, tn, fn = summarise(rows, threshold)
    print(f"\n=== Flagging links rated {threshold} or higher ===")
    print(f"Phishing caught (true positives):      {tp}")
    print(f"Phishing missed (false negatives):     {fn}")
    print(f"Safe links wrongly flagged (false +):  {fp}")
    print(f"Safe links passed (true negatives):    {tn}")
    print(f"Accuracy:   {percent(tp + tn, tp + tn + fp + fn)}")
    print(f"Precision:  {percent(tp, tp + fp)}   (of flagged links, how many were phishing)")
    print(f"Recall:     {percent(tp, tp + fn)}   (of phishing links, how many were caught)")
    print(f"False alarm rate: {percent(fp, fp + tn)}   (of safe links, how many were flagged)")


def main():
    safe_links = read_links(SAFE_FILE)
    phishing_links = read_links(PHISHING_FILE)
    print(f"Loaded {len(safe_links)} safe links and {len(phishing_links)} phishing links.")
    print("Links are analysed as text only and are never opened.")

    rows = []
    for label, links in (("safe", safe_links), ("phishing", phishing_links)):
        for url in links:
            result = analyse(url)
            rows.append({
                "label": label,
                "url": url,
                "score": result["score"],
                "level": result["level"],
                "reasons": " | ".join(result["reasons"]),
            })

    print_summary(rows, "Medium")
    print_summary(rows, "High")

    false_alarms = [r for r in rows if r["label"] == "safe" and r["level"] != "Low"]
    missed = [r for r in rows if r["label"] == "phishing" and r["level"] == "Low"]

    print("\n--- Safe links rated Medium or High (false alarms) ---")
    for r in false_alarms:
        print(f"[{r['level']}, score {r['score']}] {r['url']}")
        print(f"    {r['reasons']}")
    if not false_alarms:
        print("None")

    print("\n--- Phishing links rated Low (missed) ---")
    for r in missed:
        print(f"[score {r['score']}] {r['url']}")
    if not missed:
        print("None")

    with RESULTS_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f, fieldnames=["label", "url", "score", "level", "reasons"]
        )
        writer.writeheader()
        writer.writerows(rows)
    print(f"\nFull results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()
