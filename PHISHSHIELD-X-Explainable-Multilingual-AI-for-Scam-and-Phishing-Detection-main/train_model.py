"""
Train the message (SMS) spam classifier used by the message analyser.

Dataset: emails.csv — despite the file name this is the SMS Spam Collection
(Almeida & Gómez Hidalgo, 2011; UCI ML Repository): short English SMS
messages labelled ham/spam. It contains no URL-level labels, so this model
is NOT a URL phishing detector (see train_url_model.py for that).

Changes from the original script, so the reported numbers are honest:
  * rows with labels other than ham/spam are dropped (the CSV ends with a
    stray '{"mode":"full",...}' line)
  * exact duplicate messages are removed before splitting, so the same
    text cannot appear in both train and test
  * the split happens BEFORE upsampling; previously spam was upsampled first,
    which copied test messages into the training set and inflated accuracy
  * precision / recall / F1 are reported alongside accuracy, because with
    ~13% spam, accuracy alone is misleading

Outputs: spam_pipeline.joblib and spam_model_metrics.json
"""

import json
from datetime import datetime, timezone

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.utils import resample

SEED = 42

# 1. Load and clean
df = pd.read_csv("emails.csv").rename(columns={"Category": "label", "Message": "text"})
df["label"] = df["label"].astype(str).str.strip().str.lower()
rows_in_file = len(df)
df = df[df["label"].isin(["ham", "spam"]) & df["text"].notna()]
rows_invalid = rows_in_file - len(df)
before = len(df)
df = df.drop_duplicates("text")
rows_duplicate = before - len(df)

# 2. Split first (stratified), then balance the TRAINING set only
train_df, test_df = train_test_split(df, test_size=0.2, random_state=SEED, stratify=df["label"])
spam_tr = train_df[train_df["label"] == "spam"]
ham_tr = train_df[train_df["label"] == "ham"]
train_bal = pd.concat([ham_tr, resample(spam_tr, replace=True, n_samples=len(ham_tr), random_state=SEED)])

# 3. Same model as before: TF-IDF (uni+bigrams) + Multinomial Naive Bayes
pipeline = Pipeline([
    ("vectorizer", TfidfVectorizer(lowercase=True, stop_words="english", ngram_range=(1, 2), max_features=10000)),
    ("classifier", MultinomialNB()),
])
pipeline.fit(train_bal["text"], train_bal["label"])

# 4. Evaluate on the untouched test set
pred = pipeline.predict(test_df["text"])
y = test_df["label"]
tn, fp, fn, tp = confusion_matrix(y, pred, labels=["ham", "spam"]).ravel()
metrics = {
    "n_test": int(len(test_df)),
    "accuracy": round(accuracy_score(y, pred), 4),
    "precision_spam": round(precision_score(y, pred, pos_label="spam"), 4),
    "recall_spam": round(recall_score(y, pred, pos_label="spam"), 4),
    "f1_spam": round(f1_score(y, pred, pos_label="spam"), 4),
    "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
}
print(f"Rows: {rows_in_file} in file, {rows_invalid} invalid, {rows_duplicate} duplicates removed, "
      f"{len(df)} used ({(df['label'] == 'spam').sum()} spam)")
print("Held-out test metrics:", json.dumps(metrics, indent=2))

# 5. Save
joblib.dump(pipeline, "spam_pipeline.joblib")
with open("spam_model_metrics.json", "w", encoding="utf-8") as f:
    json.dump({
        "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": "SMS Spam Collection (emails.csv)",
        "rows": {"in_file": rows_in_file, "invalid_dropped": rows_invalid,
                 "duplicates_dropped": rows_duplicate, "used": int(len(df))},
        "split": "80/20 stratified, split before upsampling; duplicates removed first",
        "test": metrics,
    }, f, indent=2)
print("Model saved as spam_pipeline.joblib; metrics in spam_model_metrics.json")
