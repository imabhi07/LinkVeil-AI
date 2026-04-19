"""
train_xgboost.py
-----------------
XGBoost-based phishing URL classifier.

Pipeline:
  1. Load train.csv / val.csv (same files used by DistilBERT trainer)
  2. Extract hand-crafted URL features via xgb_features.py
  3. Train an XGBoostClassifier with early stopping on val set
  4. Evaluate on val set (accuracy, precision, recall, F1)
  5. Save model as ml/models/xgb-phish/xgb_model.json  (+ scaler)
  6. Log everything to MLflow

Run from project root:
    python ml/train_xgboost.py
"""

import os
import sys
import logging
import pickle

import numpy as np
import pandas as pd
import xgboost as xgb
import mlflow
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    classification_report,
)

# Ensure project root is on path so xgb_features is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from ml.xgb_features import extract_features, FEATURE_NAMES

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TRAIN_CSV     = "data/train.csv"
VAL_CSV       = "data/val.csv"
MODEL_SAVE_DIR = "ml/models/xgb-phish"
MODEL_FILE    = os.path.join(MODEL_SAVE_DIR, "xgb_model.json")
SCALER_FILE   = os.path.join(MODEL_SAVE_DIR, "scaler.pkl")

XGB_PARAMS = {
    "n_estimators":     500,
    "max_depth":        6,
    "learning_rate":    0.05,
    "subsample":        0.8,
    "colsample_bytree": 0.8,
    "eval_metric":      "logloss",
    "use_label_encoder": False,
    "tree_method":      "hist",   # fast CPU training
    "random_state":     42,
}
EARLY_STOPPING_ROUNDS = 30

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def load_and_featurize(csv_path: str):
    """Load a CSV and return (X_array, y_array)."""
    logger.info(f"Loading {csv_path} …")
    df = pd.read_csv(csv_path)

    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError(f"{csv_path} must have columns [url, label]")

    logger.info(f"  Rows: {len(df)}  |  Positive rate: {df['label'].mean():.3f}")

    X = np.array([extract_features(u) for u in df["url"].astype(str)])
    y = df["label"].astype(int).values
    return X, y


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    # -- Guard: data must exist --
    for csv in [TRAIN_CSV, VAL_CSV]:
        if not os.path.exists(csv):
            logger.error(f"Missing file: {csv}  —  run prepare_data.py first.")
            sys.exit(1)

    # -- Featurize --
    X_train, y_train = load_and_featurize(TRAIN_CSV)
    X_val,   y_val   = load_and_featurize(VAL_CSV)

    # -- Scale features (helps in edge cases; XGB itself is scale-invariant,
    #    but we keep the scaler so the inference service can reuse it) --
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_val   = scaler.transform(X_val)

    logger.info(f"Feature matrix: train={X_train.shape}  val={X_val.shape}")
    logger.info(f"Features ({len(FEATURE_NAMES)}): {', '.join(FEATURE_NAMES)}")

    # -- XGBoost DMatrix (faster internal format) --
    dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=FEATURE_NAMES)
    dval   = xgb.DMatrix(X_val,   label=y_val,   feature_names=FEATURE_NAMES)

    # -- MLflow tracking --
    os.makedirs("mlruns", exist_ok=True)
    mlflow.set_tracking_uri(r"sqlite:///mlruns/mlflow.db")
    mlflow.set_experiment("LinkVeil-XGBoost")

    with mlflow.start_run():
        mlflow.log_params({**XGB_PARAMS, "early_stopping_rounds": EARLY_STOPPING_ROUNDS})

        # -- Train --
        logger.info("Training XGBoost …")
        evals_result = {}
        booster = xgb.train(
            params={
                **XGB_PARAMS,
                "objective":  "binary:logistic",
                "eval_metric": "logloss",
                "seed": 42,
            },
            dtrain=dtrain,
            num_boost_round=XGB_PARAMS["n_estimators"],
            evals=[(dtrain, "train"), (dval, "val")],
            early_stopping_rounds=EARLY_STOPPING_ROUNDS,
            evals_result=evals_result,
            verbose_eval=50,
        )

        best_round = booster.best_iteration
        logger.info(f"Best boosting round: {best_round}")

        # -- Evaluate --
        val_probs = booster.predict(dval)
        val_preds = (val_probs > 0.5).astype(int)

        acc  = accuracy_score(y_val, val_preds)
        prec, rec, f1, _ = precision_recall_fscore_support(
            y_val, val_preds, average="binary", zero_division=0
        )
        auc = roc_auc_score(y_val, val_probs)

        logger.info(f"\n{classification_report(y_val, val_preds, target_names=['safe','phish'])}")
        logger.info(f"Accuracy={acc:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  F1={f1:.4f}  AUC={auc:.4f}")

        mlflow.log_metrics({
            "val_accuracy":  acc,
            "val_precision": prec,
            "val_recall":    rec,
            "val_f1":        f1,
            "val_auc":       auc,
            "best_round":    float(best_round),
        })

        # log per-round train/val logloss curves
        for i, (tr_ll, va_ll) in enumerate(
            zip(evals_result["train"]["logloss"], evals_result["val"]["logloss"])
        ):
            mlflow.log_metrics({"train_logloss": tr_ll, "val_logloss": va_ll}, step=i)

        # -- Save model artifacts --
        os.makedirs(MODEL_SAVE_DIR, exist_ok=True)
        booster.save_model(MODEL_FILE)
        with open(SCALER_FILE, "wb") as f:
            pickle.dump(scaler, f)

        mlflow.log_artifact(MODEL_FILE)
        mlflow.log_artifact(SCALER_FILE)

        logger.info(f"Model saved  → {MODEL_FILE}")
        logger.info(f"Scaler saved → {SCALER_FILE}")
        logger.info(f"Training complete. Best val F1 = {f1:.4f}")


if __name__ == "__main__":
    main()
