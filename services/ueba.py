# -*- coding: utf-8 -*-
from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Dict, Optional

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from joblib import load
    _HAS_SK = True
except Exception:
    _HAS_SK = False
    np = None  # type: ignore

@dataclass
class FeatureVector:
    data: Dict[str, float]

class UEBAModel:
    def __init__(self, model_path: Optional[str]):
        self.model_path = model_path or os.getenv("MODEL_PATH", "models/default_iforest.pkl")
        self.model = None
        self.baseline: list[list[float]] = []  # used for heuristic fallback/stats
        self._maybe_load()

    def _maybe_load(self):
        if not _HAS_SK:
            return
        try:
            if os.path.exists(self.model_path):
                self.model = load(self.model_path)
        except Exception:
            self.model = None

    def score(self, fv: FeatureVector) -> float:
        """
        Return a risk score [0..100]. IsolationForest if available; else lightweight z-score.
        """
        vec = [float(v) for v in fv.data.values()]
        self.baseline.append(vec)
        if _HAS_SK and self.model is not None:
            X = np.array([vec])
            try:
                raw = self.model.decision_function(X)[0]  # higher = less anomalous
                risk = max(0.0, min(100.0, 50.0 - raw * 80.0))
                return float(risk)
            except Exception:
                pass
        # Fallback heuristic
        if not self.baseline:
            return 50.0
        means = [sum(col) / len(self.baseline) for col in zip(*self.baseline)]
        stds = []
        for j, m in enumerate(means):
            vals = [v[j] for v in self.baseline]
            var = sum((x - m) ** 2 for x in vals) / max(1, len(vals) - 1)
            stds.append(var ** 0.5 or 1.0)
        z = sum(abs((vec[j] - means[j]) / stds[j]) for j in range(len(vec))) / max(1, len(vec))
        risk = max(0.0, min(100.0, 20.0 + 15.0 * z))
        return float(risk)
