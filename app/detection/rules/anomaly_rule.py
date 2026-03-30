"""
Machine Learning Anomaly Detection Rule.

ATTACKER BEHAVIOR:
  Attackers often use stolen credentials or internal machines to access
  systems in ways that don't trigger static thresholds (e.g., "low and slow"
  attacks, data exfiltration at 3 AM).
  
DETECTION LOGIC:
  Uses a pre-trained Isolation Forest model to score incoming events.
  Instead of hardcoded rules, the model looks at the contextual features
  (time of day, velocity, unique ports) against its learned "normal" baseline.
  If predict() returns -1, it's a statistical anomaly.

REAL-WORLD EQUIVALENT:
  - Splunk UBA (User Behavior Analytics)
  - Elastic Machine Learning Anomaly Jobs
  - Exabeam Advanced Analytics
"""

import os
import logging
from collections import defaultdict, deque
from datetime import datetime, timezone

import joblib

from app.detection.rules.base_rule import BaseRule
from app.models.alert import create_alert
from app.detection.ml.feature_extractor import FeatureExtractor

logger = logging.getLogger("mini_soc.detection.anomaly_rule")


class MLAnomalyRule(BaseRule):
    """
    Real-time ML scoring rule using an Isolation Forest.
    
    Maintains in-memory rolling windows to compute the same features
    (velocity, variance) that the model was trained on via pandas.
    """

    def __init__(self, model_path: str = None):
        if model_path is None:
            # Look in the top-level 'models' directory created by train_model.py
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
            model_path = os.path.join(base_dir, 'models', 'iso_forest.joblib')

        self.model_path = model_path
        self.model = None
        self.extractor = FeatureExtractor()
        
        # Real-time state trackers (to calculate features on the fly)
        # {source_ip: deque([(timestamp, destination_port), ...])}
        self._ip_history = defaultdict(deque)
        
        self._load_model()

    def _load_model(self):
        """Load the pre-trained scikit-learn model."""
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded ML Anomaly Model from {self.model_path}")
            else:
                logger.warning(
                    f"ML Model not found at {self.model_path}. "
                    "Anomaly detection is currently disabled. "
                    "Run 'scripts/train_model.py' to generate baseline."
                )
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")

    @property
    def name(self) -> str:
        return "ml_behavioral_anomaly"

    @property
    def description(self) -> str:
        return (
            "Detects statistically anomalous activity using unsupervised "
            "machine learning (Isolation Forest), evaluating time-of-day, "
            "velocity, and behavior patterns against historical baselines."
        )

    @property
    def severity(self) -> str:
        # Anomalies usually warrant investigation but aren't always definitive attacks
        return "high"

    def evaluate(self, event: dict) -> dict | None:
        """
        Extract real-time features and score against the ML model.
        """
        if self.model is None:
            return None  # Model not loaded, silently skip

        source_ip = event.get("source_ip")
        if not source_ip:
            return None

        event_time = self._parse_timestamp(event.get("timestamp"))
        dest_port = event.get("destination_port", -1)

        # 1. Update running history for this IP
        window = self._ip_history[source_ip]
        window.append((event_time, dest_port))
        
        # 2. Prune history outside 60s window
        cutoff = event_time.timestamp() - 60
        while window and window[0][0].timestamp() < cutoff:
            window.popleft()

        # 3. Calculate real-time dynamic features
        velocity_60s = len(window)
        
        # Unique ports (ignoring -1 which means no port)
        valid_ports = [p for _, p in window if p != -1 and p is not None]
        unique_ports_60s = len(set(valid_ports))

        # 4. Extract static features
        feature_dict = self.extractor.extract_dict(event)
        
        # 5. Assemble final feature array in exactly the order train_model.py used
        # Order: [hour, is_weekend, is_failed, is_sudo, velocity_60s, unique_ports_60s]
        feature_array = [
            feature_dict["hour_of_day"],
            feature_dict["is_weekend"],
            feature_dict["is_failed_login"],
            feature_dict["is_sudo"],
            velocity_60s,
            unique_ports_60s
        ]

        # 6. Inference (predict expects a 2D array)
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning) # ignore scikit feature name warning
                prediction = self.model.predict([feature_array])[0]
        except Exception as e:
            logger.error(f"ML inference failed: {e}")
            return None

        # -1 indicates an anomaly in Isolation Forest
        if prediction == -1:
            logger.warning(
                f"ML ANOMALY DETECTED: {source_ip} behavior deviates from baseline. "
                f"(Features: {feature_array})"
            )
            
            # Since ML triggers on single anomalous events based on context,
            # we just provide this event as evidence, but add the feature vector to metadata
            # so analysts know *why* the model flagged it.
            return create_alert(
                rule_name=self.name,
                severity=self.severity,
                source_ip=source_ip,
                description=(
                    f"Machine Learning Anomaly: Activity from {source_ip} "
                    f"is highly unusual compared to the historical baseline. "
                    f"Action: {event.get('action')}, Time: Hour {feature_dict['hour_of_day']}."
                ),
                evidence=[event],
                metadata={
                    "model": "IsolationForest",
                    "features": {
                        "hour_of_day": feature_dict["hour_of_day"],
                        "is_weekend": feature_dict["is_weekend"],
                        "is_failed_login": feature_dict["is_failed_login"],
                        "velocity_60s": velocity_60s,
                        "unique_ports_60s": unique_ports_60s
                    }
                },
            )

        return None

    def reset(self):
        """Clear state."""
        self._ip_history.clear()

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
