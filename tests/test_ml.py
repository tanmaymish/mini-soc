"""
Tests for the ML Anomaly Detection module.

Since Isolation Forest relies on pre-trained state, we mock the model
for the rule test, but we fully test the FeatureExtractor logic.
"""

import pytest
import pandas as pd
from datetime import datetime, timezone, timedelta

from app.detection.ml.feature_extractor import FeatureExtractor
from app.detection.rules.anomaly_rule import MLAnomalyRule


def _make_event(action, source_ip, hour=None, port=None):
    now = datetime.now(timezone.utc)
    if hour is not None:
        now = now.replace(hour=hour)
        
    return {
        "timestamp": now.isoformat(),
        "source_ip": source_ip,
        "action": action,
        "destination_port": port,
    }


class TestFeatureExtractor:
    
    def setup_method(self):
        self.extractor = FeatureExtractor()

    def test_extract_dict_temporal(self):
        """Test extraction of hour and weekend flags."""
        # A Wednesday at 14:00 (assuming current year is not perfectly aligned, let's force a known date)
        dt = datetime(2023, 11, 15, 14, 30, tzinfo=timezone.utc) # Wed
        event = {"timestamp": dt.isoformat(), "action": "CONNECTION"}
        
        feats = self.extractor.extract_dict(event)
        assert feats["hour_of_day"] == 14
        assert feats["is_weekend"] == 0

        # A Saturday at 3 AM
        dt = datetime(2023, 11, 18, 3, 15, tzinfo=timezone.utc) # Sat
        event = {"timestamp": dt.isoformat(), "action": "CONNECTION"}
        
        feats = self.extractor.extract_dict(event)
        assert feats["hour_of_day"] == 3
        assert feats["is_weekend"] == 1

    def test_extract_dict_actions(self):
        """Test extraction of action flags."""
        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": "FAILED_LOGIN"}
        feats = self.extractor.extract_dict(event)
        assert feats["is_failed_login"] == 1
        assert feats["is_sudo"] == 0

        event = {"timestamp": datetime.now(timezone.utc).isoformat(), "action": "SUDO_COMMAND"}
        feats = self.extractor.extract_dict(event)
        assert feats["is_failed_login"] == 0
        assert feats["is_sudo"] == 1

    def test_extract_dataframe_rolling(self):
        """Test extraction of rolling velocity and variance (for training)."""
        now = datetime.now(timezone.utc)
        
        # 3 events from same IP within the last 30 seconds
        events = [
            {"timestamp": (now - timedelta(seconds=20)).isoformat(), "source_ip": "10.0.0.1", "action": "CONN", "destination_port": 80},
            {"timestamp": (now - timedelta(seconds=10)).isoformat(), "source_ip": "10.0.0.1", "action": "CONN", "destination_port": 443},
            {"timestamp": now.isoformat(), "source_ip": "10.0.0.1", "action": "CONN", "destination_port": 8080},
            # 1 event from different IP
            {"timestamp": now.isoformat(), "source_ip": "192.168.1.5", "action": "CONN", "destination_port": 22},
        ]
        
        df = self.extractor.extract_dataframe(events)
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 4
        assert "velocity_60s" in df.columns
        assert "unique_ports_60s" in df.columns
        
        # Third event for 10.0.0.1 should have velocity 3 and 3 unique ports
        assert df.iloc[2]["velocity_60s"] == 3
        assert df.iloc[2]["unique_ports_60s"] == 3
        
        # Event for 192.168.1.5 should have velocity 1
        assert df.iloc[3]["velocity_60s"] == 1


class MockModel:
    """Mocks the scikit-learn IsolationForest."""
    def predict(self, X):
        # We'll hardcode logic: if velocity > 10, predict anomaly (-1)
        # X is [[hour, weekend, failed, sudo, velocity, ports]]
        velocity = X[0][4]
        if velocity > 10:
            return [-1]
        return [1]


class TestAnomalyRule:
    """Test the real-time anomaly detection rule."""

    def setup_method(self):
        self.rule = MLAnomalyRule(model_path="dummy")
        self.rule.model = MockModel()

    def test_benign_event(self):
        """Normal event should return None (score 1)."""
        event = _make_event("CONNECTION", "10.0.0.1", hour=14, port=80)
        assert self.rule.evaluate(event) is None

    def test_anomalous_event(self):
        """Event triggering anomaly condition based on mock (velocity > 10)."""
        alerts = []
        for i in range(12):
            event = _make_event("CONNECTION", "10.0.0.2", hour=3, port=22)
            alert = self.rule.evaluate(event)
            if alert:
                alerts.append(alert)
                
        # Last two events should exceed mock threshold of 10 and trigger alert
        assert len(alerts) == 2
        assert alerts[0]["rule_name"] == "ml_behavioral_anomaly"
        assert alerts[0]["severity"] == "high"
        
        # Verify metadata contains features
        assert "features" in alerts[0]["metadata"]
        assert alerts[0]["metadata"]["features"]["velocity_60s"] > 10
