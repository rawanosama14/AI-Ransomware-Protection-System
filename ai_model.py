"""Lightweight AI risk model for the educational ransomware detector.

The model is intentionally defensive and local-only. It does not contain malware
logic; it only classifies behavior statistics produced by the monitor.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List


@dataclass
class AIPrediction:
    label: str
    probability: int
    explanation: str


class LightweightAIRiskModel:
    """Small logistic-style classifier trained from synthetic safe/risky patterns.

    This avoids heavy dependencies and makes the AI role easy to explain in a
    college demo: rules find signals, AI combines the signals into one risk
    probability.
    """

    def __init__(self) -> None:
        # Hand-tuned weights from synthetic training examples. Positive weights
        # increase ransomware probability; negative bias keeps normal folders safe.
        self.bias = -3.4
        self.weights = {
            "events_norm": 2.25,
            "entropy_norm": 1.85,
            "suspicious_ext_norm": 2.70,
            "rename_norm": 2.10,
            "rule_score_norm": 2.40,
        }

    def predict(self, event_count: int, high_entropy: int, suspicious_ext: int, rename_count: int, rule_score: int) -> AIPrediction:
        features: Dict[str, float] = {
            "events_norm": min(event_count / 30.0, 1.0),
            "entropy_norm": min(high_entropy / 8.0, 1.0),
            "suspicious_ext_norm": min(suspicious_ext / 10.0, 1.0),
            "rename_norm": min(rename_count / 12.0, 1.0),
            "rule_score_norm": min(rule_score / 100.0, 1.0),
        }
        z = self.bias + sum(self.weights[name] * value for name, value in features.items())
        probability = int(round(100 / (1 + pow(2.718281828, -z))))

        if probability >= 75:
            label = "AI HIGH"
        elif probability >= 45:
            label = "AI MEDIUM"
        elif probability >= 20:
            label = "AI LOW"
        else:
            label = "AI SAFE"

        top = self._top_reasons(features)
        explanation = ", ".join(top) if top else "normal file behavior"
        return AIPrediction(label=label, probability=probability, explanation=explanation)

    def _top_reasons(self, features: Dict[str, float]) -> List[str]:
        labels = {
            "events_norm": "many events",
            "entropy_norm": "high entropy files",
            "suspicious_ext_norm": "suspicious extensions",
            "rename_norm": "mass renaming",
            "rule_score_norm": "rule score is high",
        }
        scored = sorted(
            ((self.weights[k] * v, labels[k]) for k, v in features.items() if v > 0.05),
            reverse=True,
        )
        return [label for _, label in scored[:3]]
