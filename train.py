"""Train and evaluate the PhishGuard AI models.

    python train.py                                   # uses datasets/messages.csv and datasets/urls.csv
    python train.py --messages my_msgs.csv --urls my_urls.csv

If the default CSVs do not exist, the SYNTHETIC seed dataset is generated first
(see datasets/generate_seed.py). Results on synthetic data only show that the
pipeline works; they are not evidence of real-world performance.

Splits are GROUPED (messages by template id, URLs by registered domain) so the
test set contains templates/domains never seen during training. Everything is
seeded, so results are reproducible.
"""
import argparse
import json
import platform
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score, recall_score,
                             roc_auc_score)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline

import detector as det
import risk_engine

SEED = 42
BASE = Path(__file__).resolve().parent
DATA = BASE / "datasets"


def metrics(y_true, y_pred, y_prob):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "n_test": int(len(y_true)), "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
        "false_positive_rate": round(fp / max(fp + tn, 1), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def load_csv(path, required):
    df = pd.read_csv(path).dropna(subset=required[:2])
    missing = [c for c in required if c not in df.columns]
    if missing:
        sys.exit(f"{path}: missing columns {missing}")
    df["label"] = df["label"].astype(int)
    if not set(df["label"].unique()) <= {0, 1}:
        sys.exit(f"{path}: labels must be 0 (legitimate) or 1 (phishing)")
    before = len(df)
    df = df.drop_duplicates(subset=[required[0]])
    print(f"  {path.name}: {before} rows, {before - len(df)} duplicates removed, "
          f"class balance {df['label'].value_counts().to_dict()}")
    return df.reset_index(drop=True)


def group_split(df, group_col):
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=SEED)
    tr, te = next(gss.split(df, df["label"], df[group_col]))
    assert not set(df.iloc[tr][group_col]) & set(df.iloc[te][group_col]), "group leakage"
    return df.iloc[tr], df.iloc[te]


def message_pipeline():
    return Pipeline([
        ("tfidf", TfidfVectorizer(preprocessor=det.preprocess_message, ngram_range=(1, 2), min_df=2,
                                  sublinear_tf=True)),
        ("clf", LogisticRegression(C=4.0, class_weight="balanced", max_iter=1000, random_state=SEED)),
    ])


def url_model():
    return RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight="balanced",
                                  random_state=SEED, n_jobs=1)


def url_matrix(urls):
    return np.array([det.url_vector(det.url_features(det.parse_url(u))) for u in urls])


def cross_val_f1(make_model, X, y, groups, is_text):
    scores = []
    for tr, te in GroupKFold(n_splits=5).split(X, y, groups):
        m = make_model()
        Xtr = [X[i] for i in tr] if is_text else X[tr]
        Xte = [X[i] for i in te] if is_text else X[te]
        m.fit(Xtr, y[tr])
        scores.append(f1_score(y[te], m.predict(Xte)))
    return {"mean_f1": round(float(np.mean(scores)), 4), "std_f1": round(float(np.std(scores)), 4)}


def perturb(url):
    """Simple URL variations used for a robustness check."""
    host_start = url.find("://") + 3
    return {
        "query_added": url + ("&" if "?" in url else "?") + "utm_source=mail&ref=1",
        "uppercase_scheme_host": url[:host_start].upper() + url[host_start:].split("/", 1)[0].upper() +
                                 ("/" + url[host_start:].split("/", 1)[1] if "/" in url[host_start:] else ""),
        "trailing_slash": url if url.endswith("/") else url + "/",
        "scheme_swapped": ("https://" + url[7:]) if url.startswith("http://") else ("http://" + url[8:]),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--messages", default=str(DATA / "messages.csv"))
    ap.add_argument("--urls", default=str(DATA / "urls.csv"))
    ap.add_argument("--out", default=str(det.MODEL_DIR))
    args = ap.parse_args()
    msg_path, url_path, out = Path(args.messages), Path(args.urls), Path(args.out)

    synthetic = False
    if not msg_path.exists() or not url_path.exists():
        print("Datasets not found - generating SYNTHETIC seed data (see datasets/generate_seed.py)")
        sys.path.insert(0, str(DATA))
        import generate_seed
        generate_seed.main()
        synthetic = True
    else:
        uses_default = any(p.resolve() in {(DATA / "messages.csv").resolve(), (DATA / "urls.csv").resolve()}
                           for p in (msg_path, url_path))
        synthetic = uses_default and (DATA / "SYNTHETIC_DATA.txt").exists()
    print("Loading datasets")
    msgs = load_csv(msg_path, ["text", "label", "group"])
    urls = load_csv(url_path, ["url", "label", "group"])

    report = {"seed": SEED, "synthetic_data": synthetic, "versions": {
        "python": platform.python_version(), "scikit-learn": sklearn.__version__,
        "numpy": np.__version__, "pandas": pd.__version__}}

    # ---- message model
    mtr, mte = group_split(msgs, "group")
    print(f"Message split: train {len(mtr)} ({mtr['group'].nunique()} templates) / "
          f"test {len(mte)} ({mte['group'].nunique()} unseen templates)")
    mm = message_pipeline().fit(mtr["text"], mtr["label"])
    mprob = mm.predict_proba(mte["text"])[:, 1]
    report["message_model"] = metrics(mte["label"].values, (mprob >= 0.5).astype(int), mprob)
    report["message_model"]["grouped_5fold_cv"] = cross_val_f1(
        message_pipeline, list(msgs["text"]), msgs["label"].values, msgs["group"].values, True)

    # ---- URL model
    utr, ute = group_split(urls, "group")
    print(f"URL split: train {len(utr)} / test {len(ute)} ({ute['group'].nunique()} unseen domains)")
    Xtr, Xte = url_matrix(utr["url"]), url_matrix(ute["url"])
    um = url_model().fit(Xtr, utr["label"])
    uprob = um.predict_proba(Xte)[:, 1]
    report["url_model"] = metrics(ute["label"].values, (uprob >= 0.5).astype(int), uprob)
    report["url_model"]["grouped_5fold_cv"] = cross_val_f1(
        url_model, url_matrix(urls["url"]), urls["label"].values, urls["group"].values, False)
    imp = sorted(zip(det.URL_FEATURE_NAMES, um.feature_importances_), key=lambda t: -t[1])[:8]
    report["url_model"]["top_features"] = [{"feature": n, "importance": round(float(v), 4)} for n, v in imp]

    # robustness: recall on held-out phishing URLs after benign-looking variations
    phish_test = list(ute[ute["label"] == 1]["url"])
    rob = {"original": round(float(np.mean(um.predict(url_matrix(phish_test)))), 4)}
    variants = {}
    for u in phish_test:
        for k, v in perturb(u).items():
            variants.setdefault(k, []).append(v)
    for k, vs in variants.items():
        rob[k] = round(float(np.mean(um.predict(url_matrix(vs)))), 4)
    report["url_model"]["robustness_recall"] = rob

    # ---- end-to-end (model + indicators + risk engine) on the held-out sets
    d = det.Detector(mm, um)
    for name, df, kind in (("message_end_to_end", mte, "message"), ("url_end_to_end", ute, "url")):
        col = "text" if kind == "message" else "url"
        scores = []
        for x in df[col]:
            if kind == "message":
                scores.append(risk_engine.score_message(d.analyze_message(x))["risk_score"])
            else:
                scores.append(risk_engine.score_url(d.analyze_url(x))["risk_score"])
        s = np.array(scores)
        report[name] = metrics(df["label"].values, (s >= 50).astype(int), s / 100.0)
        report[name]["decision_rule"] = "risk_score >= 50 flagged as phishing"

    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(mm, out / det.MESSAGE_MODEL)
    joblib.dump(um, out / det.URL_MODEL)
    det.write_manifest(out, {"trained_with": report["versions"]})
    (out / "evaluation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    if synthetic:
        print("\nNOTE: trained on SYNTHETIC seed data - these figures do not describe real-world accuracy.")


if __name__ == "__main__":
    main()
