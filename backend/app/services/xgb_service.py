"""
xgb_service.py
---------------
XGBoost phishing classifier — inference service.

Mirrors the interface of DLService.predict() so the engine can call
either model transparently.
"""

import os
import pickle
import logging

import numpy as np
import xgboost as xgb

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
from ml.xgb_features import extract_features, FEATURE_NAMES

logger = logging.getLogger(__name__)


class XGBService:
    def __init__(self):
        self.model_dir  = "ml/models/xgb-phish"
        model_file  = os.path.join(self.model_dir, "xgb_model.json")
        scaler_file = os.path.join(self.model_dir, "scaler.pkl")

        self.booster = None
        self.scaler  = None
        self._load_model(model_file, scaler_file)

    def _load_model(self, model_file: str, scaler_file: str):
        try:
            if not os.path.exists(model_file):
                logger.warning(f"XGBoost model not found at {model_file}. "
                               "Run python ml/train_xgboost.py first.")
                return

            self.booster = xgb.Booster()
            self.booster.load_model(model_file)
            logger.info(f"Loaded XGBoost model from {model_file}")

            if os.path.exists(scaler_file):
                with open(scaler_file, "rb") as f:
                    self.scaler = pickle.load(f)
                logger.info(f"Loaded scaler from {scaler_file}")

        except Exception as e:
            logger.error(f"Failed to load XGBoost model: {e}")

    def predict(self, url: str) -> float:
        """
        Returns phishing probability in [0.0, 1.0].
        0.0 = definitely safe, 1.0 = definitely phishing.
        """
        if self.booster is None:
            logger.warning("XGBService.predict called but model not loaded — returning 0.5")
            return 0.5

        try:
            features = np.array([extract_features(url)], dtype=np.float32)

            if self.scaler is not None:
                features = self.scaler.transform(features)

            dmat = xgb.DMatrix(features, feature_names=FEATURE_NAMES)
            prob = float(self.booster.predict(dmat)[0])

            logger.info(f"XGB prob for '{url}': {prob:.4f}")
            return prob

        except Exception as e:
            logger.error(f"XGBService.predict error for '{url}': {e}")
            return 0.5


# Singleton
xgb_service = XGBService()
