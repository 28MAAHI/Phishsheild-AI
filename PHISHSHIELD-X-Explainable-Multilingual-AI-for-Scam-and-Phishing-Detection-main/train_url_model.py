"""
Train the URL phishing model.

    python scripts/download_url_dataset.py      # once, fetches the public dataset
    python train_url_model.py                   # trains and evaluates

Any CSV with a URL column and a binary label column can be used:

    python train_url_model.py --data my_urls.csv --url-col URL --label-col label \
        --positive-label 0 --dataset-name "My dataset"

Evaluation protocol (all numbers written to models/url_model_metrics.json):
  * duplicate URLs are removed and URLs with conflicting labels are dropped
  * the train/test split is grouped by registered domain, so no domain
    appears in both sets (a random split lets the model memorise domains
    and overstates accuracy)
  * the regularisation strength is chosen by grouped 5-fold cross-validation
    on the training set only; the test set is used exactly once
"""

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score,
)
from sklearn.model_selection import GridSearchCV, GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from phishshield.url_analysis import FEATURE_NAMES, FEATURE_VERSION, InvalidURLError, extract_features, parse_url

ROOT = os.path.dirname(os.path.abspath(__file__))

DEFAULT_CITATION = (
    "Hannousse, A. & Yahiouche, S. (2021). Web page phishing detection dataset, "
    "Mendeley Data v3, https://doi.org/10.17632/c2gw7fy2j4.3 (CC BY 4.0)"
)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default=os.path.join(ROOT, "data", "url_dataset.csv"))
    p.add_argument("--url-col", default="url")
    p.add_argument("--label-col", default="label")
    p.add_argument("--positive-label", default="1", help="label value meaning 'phishing'")
    p.add_argument("--dataset-name", default="Web page phishing detection (Hannousse & Yahiouche, 2021)")
    p.add_argument("--dataset-citation", default=DEFAULT_CITATION)
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out", default=os.path.join(ROOT, "models", "url_model.joblib"))
    p.add_argument("--no-reference-model", action="store_true",
                   help="skip the gradient-boosting comparison model")
    return p.parse_args(argv)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset(args):
    if not os.path.exists(args.data):
        sys.exit(f"[ERROR] Dataset not found: {args.data}\n"
                 "Run `python scripts/download_url_dataset.py` first, or pass --data.")
    df = pd.read_csv(args.data, dtype=str, keep_default_na=False)
    for col in (args.url_col, args.label_col):
        if col not in df.columns:
            sys.exit(f"[ERROR] Column '{col}' not in dataset (columns: {list(df.columns)})")
    df = df[[args.url_col, args.label_col]].rename(columns={args.url_col: "url", args.label_col: "raw_label"})
    df["label"] = (df["raw_label"].str.strip() == str(args.positive_label)).astype(int)
    stats = {"rows_in_file": int(len(df))}

    X, y, groups, norm_urls, skipped = [], [], [], [], 0
    for url, label in zip(df["url"], df["label"]):
        try:
            parsed = parse_url(url)
        except InvalidURLError:
            skipped += 1
            continue
        X.append(extract_features(parsed))
        y.append(label)
        groups.append(parsed.registered_domain or parsed.host)
        norm_urls.append(parsed.normalized)
    stats["rows_unparseable"] = skipped

    data = pd.DataFrame({"norm": norm_urls, "label": y, "group": groups})
    data["X"] = X
    conflicting = data.groupby("norm")["label"].nunique()
    conflicting = set(conflicting[conflicting > 1].index)
    before = len(data)
    data = data[~data["norm"].isin(conflicting)].drop_duplicates("norm")
    stats["rows_conflicting_labels_dropped"] = int(sum(1 for n in norm_urls if n in conflicting))
    stats["rows_duplicates_dropped"] = int(before - len(data) - stats["rows_conflicting_labels_dropped"])
    stats["rows_used"] = int(len(data))
    stats["class_counts"] = {"phishing": int(data["label"].sum()),
                             "legitimate": int((data["label"] == 0).sum())}
    stats["distinct_registered_domains"] = int(data["group"].nunique())
    return np.array(data["X"].tolist()), data["label"].to_numpy(), data["group"].to_numpy(), stats


def evaluate(y_true, proba, threshold=0.5):
    pred = (proba >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y_true)),
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "precision": round(precision_score(y_true, pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, proba), 4),
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "threshold": threshold,
    }


def main(argv=None):
    args = parse_args(argv)
    X, y, groups, stats = load_dataset(args)
    print(f"Dataset: {stats}")
    if len(set(y)) < 2:
        sys.exit("[ERROR] Dataset must contain both phishing and legitimate URLs.")

    splitter = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=args.seed)
    train_idx, test_idx = next(splitter.split(X, y, groups))
    X_tr, X_te, y_tr, y_te = X[train_idx], X[test_idx], y[train_idx], y[test_idx]
    assert not set(groups[train_idx]) & set(groups[test_idx]), "domain leakage between splits"
    print(f"Train: {len(y_tr)}  Test: {len(y_te)}  (grouped by registered domain)")

    pipe = Pipeline([("scaler", StandardScaler()),
                     ("clf", LogisticRegression(max_iter=5000, class_weight="balanced"))])
    search = GridSearchCV(pipe, {"clf__C": [0.01, 0.1, 1.0, 10.0]}, scoring="roc_auc",
                          cv=GroupKFold(n_splits=5), n_jobs=1)
    search.fit(X_tr, y_tr, groups=groups[train_idx])
    model = search.best_estimator_
    cv_scores = search.cv_results_
    best = search.best_index_
    print(f"Best C={search.best_params_['clf__C']}  CV ROC-AUC={cv_scores['mean_test_score'][best]:.4f} "
          f"± {cv_scores['std_test_score'][best]:.4f}")

    test_metrics = evaluate(y_te, model.predict_proba(X_te)[:, 1])
    train_metrics = evaluate(y_tr, model.predict_proba(X_tr)[:, 1])
    print("Held-out test metrics:", json.dumps(test_metrics, indent=2))

    metrics = {
        "test": test_metrics,
        "train": train_metrics,
        "cross_validation": {
            "folds": 5, "grouped_by": "registered_domain", "scoring": "roc_auc",
            "mean": round(float(cv_scores["mean_test_score"][best]), 4),
            "std": round(float(cv_scores["std_test_score"][best]), 4),
            "best_params": {"C": search.best_params_["clf__C"]},
        },
    }

    if not args.no_reference_model:
        ref = HistGradientBoostingClassifier(random_state=args.seed).fit(X_tr, y_tr)
        metrics["reference_gradient_boosting_test"] = {
            **evaluate(y_te, ref.predict_proba(X_te)[:, 1]),
            "note": "Same features and split; shown only to quantify the accuracy cost of using an "
                    "exactly-explainable linear model. This model is not saved or served.",
        }
        print("Reference gradient boosting (not served):",
              {k: metrics["reference_gradient_boosting_test"][k] for k in ("accuracy", "f1", "roc_auc")})

    clf = model.named_steps["clf"]
    metrics["coefficients"] = {
        name: round(float(c), 4)
        for name, c in sorted(zip(FEATURE_NAMES, clf.coef_[0]), key=lambda t: -abs(t[1]))
    }

    metadata = {
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sklearn_version": sklearn.__version__,
        "seed": args.seed,
        "test_size": args.test_size,
        "dataset": {
            "name": args.dataset_name,
            "citation": args.dataset_citation,
            "file": os.path.relpath(args.data, ROOT),
            "sha256": file_sha256(args.data),
            **stats,
        },
    }
    artifact = {
        "pipeline": model,
        "feature_names": list(FEATURE_NAMES),
        "feature_version": FEATURE_VERSION,
        "metadata": metadata,
        "metrics": metrics,
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump(artifact, args.out)
    metrics_path = os.path.splitext(args.out)[0] + "_metrics.json"
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump({"metadata": metadata, "feature_version": FEATURE_VERSION,
                   "feature_names": list(FEATURE_NAMES), "metrics": metrics}, f, indent=2)
    print(f"[OK] Model saved to {args.out}\n[OK] Metrics saved to {metrics_path}")
    return metrics


if __name__ == "__main__":
    main()
