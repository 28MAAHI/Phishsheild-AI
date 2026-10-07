"""Checks the URL training script's mechanics (CLI, cleaning, grouped split,
artifact format) on a tiny generated CSV. The resulting numbers are
meaningless and are not used anywhere."""

import json

from phishshield.detection import load_url_model
from phishshield.url_analysis import parse_url


def _write_csv(path):
    rows = ["url,label"]
    # Every row gets its own registered domain so the domain-grouped folds
    # contain both classes.
    for i in range(60):
        rows.append(f"https://site{i}.com/about,0")
        rows.append(f"https://www.shop{i}.org/products/item{i},0")
        rows.append(f"http://secure-login{i}.xyz/verify/account?id={i}000,1")
        rows.append(f"http://192.168.{i % 250}.{i % 200 + 1}/bank/login.php,1")
    rows.append("https://site0.com/about,0")              # duplicate
    rows.append("https://dup.example.net/x,0")
    rows.append("https://dup.example.net/x,1")            # conflicting label
    rows.append("ftp://not-http.example/,1")              # unparseable
    path.write_text("\n".join(rows), encoding="utf-8")


def test_training_script_end_to_end(tmp_path):
    import train_url_model
    data = tmp_path / "urls.csv"
    out = tmp_path / "model.joblib"
    _write_csv(data)
    train_url_model.main(["--data", str(data), "--out", str(out), "--no-reference-model",
                          "--dataset-name", "synthetic test data"])

    metrics = json.loads((tmp_path / "model_metrics.json").read_text())
    ds = metrics["metadata"]["dataset"]
    assert ds["rows_unparseable"] == 1
    assert ds["rows_conflicting_labels_dropped"] == 2
    assert ds["rows_duplicates_dropped"] == 1
    assert {"accuracy", "precision", "recall", "f1", "roc_auc", "confusion_matrix"} <= set(metrics["metrics"]["test"])

    model = load_url_model(str(out))
    p = model.predict(parse_url("https://example.com/"))
    assert 0 <= p.probability <= 1
