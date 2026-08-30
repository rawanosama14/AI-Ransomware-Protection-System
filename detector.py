"""Safe ransomware-like behavior detector for educational use.

This module does NOT perform encryption, process killing, privilege escalation,
or malware-like activity. It only observes file-system events in a selected
folder and scores suspicious behavior using defensive rules.
"""
from __future__ import annotations

import math
import os
import time
from collections import deque, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional, Tuple

SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".crypto", ".enc", ".locky", ".pay", ".ransom"
}
SAFE_EXTENSIONS = {
    ".txt", ".doc", ".docx", ".pdf", ".jpg", ".jpeg", ".png", ".csv", ".xlsx", ".pptx"
}

@dataclass
class FileEvent:
    timestamp: float
    event_type: str
    path: str
    dest_path: Optional[str] = None
    entropy: Optional[float] = None
    extension: str = ""

@dataclass
class DetectionResult:
    risk_level: str
    score: int
    reasons: List[str] = field(default_factory=list)
    event_count_window: int = 0
    high_entropy_count: int = 0
    suspicious_extension_count: int = 0
    rename_count: int = 0
    ai_label: str = "AI SAFE"
    ai_probability: int = 0
    ai_explanation: str = "normal file behavior"

class RansomwareDetector:
    """Rule-based defensive detector for ransomware-like activity."""

    def __init__(
        self,
        window_seconds: int = 30,
        event_threshold: int = 25,
        entropy_threshold: float = 7.2,
        entropy_sample_bytes: int = 4096,
    ) -> None:
        self.window_seconds = window_seconds
        self.event_threshold = event_threshold
        self.entropy_threshold = entropy_threshold
        self.entropy_sample_bytes = entropy_sample_bytes
        self.events: Deque[FileEvent] = deque()
        self.extension_changes: Counter[str] = Counter()
        from ai_model import LightweightAIRiskModel
        self.ai_model = LightweightAIRiskModel()

    def add_event(self, event_type: str, path: str, dest_path: Optional[str] = None) -> DetectionResult:
        now = time.time()
        extension = Path(dest_path or path).suffix.lower()
        entropy = None
        target = dest_path or path
        if event_type in {"created", "modified", "moved"} and os.path.isfile(target):
            entropy = calculate_entropy(target, max_bytes=self.entropy_sample_bytes)

        event = FileEvent(now, event_type, path, dest_path, entropy, extension)
        self.events.append(event)
        self._trim_old_events(now)
        return self.evaluate()

    def _trim_old_events(self, now: float) -> None:
        while self.events and now - self.events[0].timestamp > self.window_seconds:
            self.events.popleft()

    def evaluate(self) -> DetectionResult:
        recent = list(self.events)
        event_count = len(recent)
        high_entropy = [e for e in recent if e.entropy is not None and e.entropy >= self.entropy_threshold]
        suspicious_ext = [e for e in recent if e.extension in SUSPICIOUS_EXTENSIONS]
        renames = [e for e in recent if e.event_type == "moved"]

        score = 0
        reasons: List[str] = []

        if event_count >= self.event_threshold:
            score += 35
            reasons.append(f"High file activity: {event_count} events in {self.window_seconds}s")
        elif event_count >= max(8, self.event_threshold // 2):
            score += 15
            reasons.append(f"Elevated file activity: {event_count} recent events")

        if len(high_entropy) >= 5:
            score += 35
            reasons.append(f"Many high-entropy files detected: {len(high_entropy)}")
        elif len(high_entropy) >= 2:
            score += 15
            reasons.append(f"Some high-entropy files detected: {len(high_entropy)}")

        if len(suspicious_ext) >= 3:
            score += 25
            reasons.append(f"Suspicious extensions observed: {len(suspicious_ext)}")
        elif len(suspicious_ext) >= 1:
            score += 10
            reasons.append("Suspicious encrypted-looking extension observed")

        if len(renames) >= 8:
            score += 20
            reasons.append(f"Mass rename behavior: {len(renames)} renames")
        elif len(renames) >= 3:
            score += 8
            reasons.append(f"Multiple rename events: {len(renames)}")

        score = min(score, 100)
        if score >= 70:
            level = "HIGH"
        elif score >= 35:
            level = "MEDIUM"
        elif score >= 10:
            level = "LOW"
        else:
            level = "SAFE"
            reasons.append("No ransomware-like behavior detected")

        ai_prediction = self.ai_model.predict(
            event_count=event_count,
            high_entropy=len(high_entropy),
            suspicious_ext=len(suspicious_ext),
            rename_count=len(renames),
            rule_score=score,
        )

        # Let the AI model raise medium/high confidence when multiple signals combine.
        if ai_prediction.probability >= 75 and score < 70:
            level = "HIGH"
            score = max(score, ai_prediction.probability)
            reasons.append("AI model combined multiple suspicious signals")
        elif ai_prediction.probability >= 45 and score < 35:
            level = "MEDIUM"
            score = max(score, ai_prediction.probability)
            reasons.append("AI model detected an unusual behavior pattern")

        return DetectionResult(
            risk_level=level,
            score=score,
            reasons=reasons,
            event_count_window=event_count,
            high_entropy_count=len(high_entropy),
            suspicious_extension_count=len(suspicious_ext),
            rename_count=len(renames),
            ai_label=ai_prediction.label,
            ai_probability=ai_prediction.probability,
            ai_explanation=ai_prediction.explanation,
        )


def calculate_entropy(file_path: str, max_bytes: int = 4096) -> Optional[float]:
    """Calculate Shannon entropy for a file sample. High values can indicate encryption/compression."""
    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        counts = Counter(data)
        total = len(data)
        return -sum((count / total) * math.log2(count / total) for count in counts.values())
    except (OSError, PermissionError):
        return None


def format_reasons(reasons: Iterable[str]) -> str:
    return " | ".join(reasons)
