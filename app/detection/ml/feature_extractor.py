"""
Feature Extractor for Log Events.

In ML-based threat detection, raw text logs are useless to models
like Isolation Forest. We must extract numerical features that
represent *behavior*.

Key UEBA (User and Entity Behavior Analytics) features:
  - Temporal: Is it a weird time? (hour_of_day, is_weekend)
  - Velocity: Is it unusually fast? (events in last N seconds)
  - Variance: Is it touching unusual things? (distinct ports)
"""

from datetime import datetime, timezone
import pandas as pd


class FeatureExtractor:
    """
    Extracts numerical features from a normalized log event.
    Designed for both batch training (using pandas) and
    real-time streaming inference.
    """

    def __init__(self):
        # We define the order of features explicitly so training
        # and inference arrays always align perfectly.
        self.feature_names = [
            "hour_of_day",
            "is_weekend",
            "is_failed_login",
            "is_sudo",
        ]

    def extract_dict(self, event: dict) -> dict:
        """
        Extract features as a dictionary (useful for debugging).
        """
        # Temporal features
        dt = self._parse_timestamp(event.get("timestamp"))
        hour = dt.hour
        is_weekend = 1 if dt.weekday() >= 5 else 0

        # Categorical/Action indicators
        action = event.get("action", "")
        is_failed = 1 if action == "FAILED_LOGIN" else 0
        is_sudo = 1 if action == "SUDO_COMMAND" else 0

        return {
            "hour_of_day": hour,
            "is_weekend": is_weekend,
            "is_failed_login": is_failed,
            "is_sudo": is_sudo,
        }

    def extract_array(self, event: dict) -> list:
        """
        Extract features as a flat array for scikit-learn.
        """
        features = self.extract_dict(event)
        return [features[name] for name in self.feature_names]

    def extract_dataframe(self, events: list[dict]) -> pd.DataFrame:
        """
        Extract features for a batch of events (for training).
        Also calculates historical window features
        (e.g., event velocity per IP).
        """
        if not events:
            return pd.DataFrame(columns=self.feature_names)

        # First, basic static feature extraction
        rows = [self.extract_dict(e) for e in events]
        df = pd.DataFrame(rows)

        # For historical/velocity features, we need the original time and IP
        df["timestamp"] = [self._parse_timestamp(e.get("timestamp")) for e in events]
        df["source_ip"] = [e.get("source_ip", "unknown") for e in events]
        df["destination_port"] = [e.get("destination_port", -1) for e in events]

        # Sort by time to calculate rolling windows properly
        df = df.sort_values("timestamp").reset_index(drop=True)

        # Calculate Velocity: events per IP in last 60 seconds
        # (This simulates what our real-time streaming rules track)
        velocity_series = []
        for i, row in df.iterrows():
            # Look back 60 seconds for the same IP
            cutoff = row["timestamp"] - pd.Timedelta(seconds=60)
            past_window = df[
                (df["source_ip"] == row["source_ip"]) &
                (df["timestamp"] <= row["timestamp"]) &
                (df["timestamp"] > cutoff)
            ]
            velocity_series.append(len(past_window))

        df["velocity_60s"] = velocity_series

        # Calculate Variance: unique ports per IP in last 60 seconds
        variance_series = []
        for i, row in df.iterrows():
            cutoff = row["timestamp"] - pd.Timedelta(seconds=60)
            past_window = df[
                (df["source_ip"] == row["source_ip"]) &
                (df["timestamp"] <= row["timestamp"]) &
                (df["timestamp"] > cutoff)
            ]
            unique_ports = past_window["destination_port"].nunique()
            # Don't count "no port" (-1) as a scanned port
            if -1 in past_window["destination_port"].values:
                unique_ports = max(0, unique_ports - 1)
            variance_series.append(unique_ports)

        df["unique_ports_60s"] = variance_series

        # Update feature names with the dynamic ones
        full_feature_names = self.feature_names + ["velocity_60s", "unique_ports_60s"]

        # Fill NaNs
        df = df.fillna(0)

        # Return only the numerical feature columns used for training
        return df[full_feature_names]

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        if not ts_str:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts_str)
        except (ValueError, TypeError):
            return datetime.now(timezone.utc)
