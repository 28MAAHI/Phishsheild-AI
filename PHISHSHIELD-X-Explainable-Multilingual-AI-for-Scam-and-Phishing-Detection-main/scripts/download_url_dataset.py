"""
Download the public URL dataset used to train the URL phishing model.

Dataset: "Web page phishing detection" (dataset_B_05_2020.csv), version 3
  Hannousse, A. & Yahiouche, S. (2021). Towards benchmark datasets for machine
  learning based website phishing detection: An experimental study.
  Engineering Applications of Artificial Intelligence, 104, 104347.
  Data: https://doi.org/10.17632/c2gw7fy2j4.3  (Mendeley Data, CC BY 4.0)

The original CSV has 11,430 URLs (50% phishing / 50% legitimate) plus 87
pre-computed features. Only the `url` and `status` columns are used; they are
written to data/url_dataset.csv as `url,label` with label 1 = phishing and
0 = legitimate. The raw file is kept unchanged in data/raw/.

Usage:
    python scripts/download_url_dataset.py
"""

import csv
import hashlib
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(ROOT, "data", "raw")
RAW_PATH = os.path.join(RAW_DIR, "dataset_B_05_2020.csv")
OUT_PATH = os.path.join(ROOT, "data", "url_dataset.csv")

SOURCE_URL = ("https://data.mendeley.com/public-files/datasets/c2gw7fy2j4/files/"
              "575316f4-ee1d-453e-a04f-7b950915b61b/file_downloaded")
EXPECTED_SHA256 = "21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c"
LABELS = {"phishing": 1, "legitimate": 0}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download():
    os.makedirs(RAW_DIR, exist_ok=True)
    if os.path.exists(RAW_PATH) and sha256(RAW_PATH) == EXPECTED_SHA256:
        print(f"[OK] Raw dataset already present: {RAW_PATH}")
        return
    print(f"Downloading {SOURCE_URL} ...")
    tmp = RAW_PATH + ".part"
    try:
        # Mendeley rejects urllib's default User-Agent with HTTP 403.
        req = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "phishshield-dataset-downloader/1.0"})
        with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
            while chunk := resp.read(1 << 16):
                out.write(chunk)
    except OSError as e:
        sys.exit(f"[ERROR] Download failed: {e}\n"
                 f"Download the file manually from https://doi.org/10.17632/c2gw7fy2j4.3 "
                 f"and save it as {RAW_PATH}")
    digest = sha256(tmp)
    if digest != EXPECTED_SHA256:
        os.remove(tmp)
        sys.exit(f"[ERROR] Checksum mismatch (got {digest}). The file was not saved.")
    os.replace(tmp, RAW_PATH)
    print(f"[OK] Saved and verified: {RAW_PATH}")


def convert():
    counts = {0: 0, 1: 0}
    skipped = 0
    with open(RAW_PATH, newline="", encoding="utf-8", errors="replace") as src, \
            open(OUT_PATH, "w", newline="", encoding="utf-8") as dst:
        reader = csv.DictReader(src)
        writer = csv.writer(dst)
        writer.writerow(["url", "label"])
        for row in reader:
            label = LABELS.get((row.get("status") or "").strip().lower())
            url = (row.get("url") or "").strip()
            if label is None or not url:
                skipped += 1
                continue
            writer.writerow([url, label])
            counts[label] += 1
    print(f"[OK] Wrote {OUT_PATH}: {counts[1]} phishing, {counts[0]} legitimate, {skipped} skipped")


if __name__ == "__main__":
    download()
    convert()
