#!/usr/bin/env python3
"""
Baseline ML Training Script.

In a real SOC, UEBA models (like Exabeam or Splunk UBA) are trained on
historical benign data to learn "normal" behavior (baselining).
This script builds an Isolation Forest model from stored MongoDB events.

Isolation Forest is an unsupervised algorithm that detects anomalies by
isolating outliers in the feature space.
"""

import os
import sys
import logging
from datetime import datetime, timezone
import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib

# Add the project root to sys.path so we can import 'app'
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.storage.mongo import get_db, init_db
from app.detection.ml.feature_extractor import FeatureExtractor
from flask import Flask

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_model")

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "models")


def fetch_training_data() -> list[dict]:
    """Fetch recent benign logs from MongoDB to use as a baseline."""
    # Dummy Flask app just to init DB config
    app = Flask(__name__)
    app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    app.config["MONGO_DB_NAME"] = os.getenv("MONGO_DB_NAME", "mini_soc")
    
    init_db(app)
    db = get_db()
    
    if db is None:
        logger.error("Could not connect to MongoDB. Is it running?")
        sys.exit(1)

    # In production, we'd filter out known attacks/alerts to ensure
    # the baseline is truly benign behavior. 
    # For this mini-SOC, we grab the last 10,000 events.
    logger.info("Fetching training data from MongoDB...")
    cursor = db.log_events.find({}, {"_id": 0}).sort("timestamp", -1).limit(10000)
    events = list(cursor)
    
    if len(events) < 10:
        logger.warning(
            "Very little data found. The baseline will be poor. "
            "Consider running 'simulate_attack.py --mode mixed' first "
            "to generate some traffic."
        )
    
    logger.info(f"Fetched {len(events)} events for baseline training.")
    return events


def generate_synthetic_baseline() -> list[dict]:
    """
    If the DB is completely empty (cold start), generate some fake
    benign traffic just so the model can compile.
    """
    logger.info("Generating synthetic baseline data (9-to-5, low velocity).")
    events = []
    now = datetime.now(timezone.utc)
    
    # Simulate a normal day: standard hours, standard ports, low velocity
    for i in range(100):
        # Force hour to be between 9 and 17 (business hours)
        dt = now.replace(hour=9 + (i % 8))
        events.append({
            "timestamp": dt.isoformat(),
            "source_ip": "10.0.0.50",
            "action": "ACCEPTED_LOGIN" if i % 10 == 0 else "CONNECTION",
            "destination_port": 22 if i % 10 == 0 else 443,
        })
    return events


def main():
    events = fetch_training_data()
    
    if not events:
        events = generate_synthetic_baseline()
        
    logger.info("Extracting features (this may take a moment for rolling windows)...")
    extractor = FeatureExtractor()
    df = extractor.extract_dataframe(events)
    
    logger.info(f"Feature matrix shape: {df.shape}")
    logger.info(f"Features used: {list(df.columns)}")
    
    # Train the Isolation Forest
    # contamination = "auto" means it determines the anomaly threshold automatically
    # For a stricter SOC, you might set it to 0.01 (top 1% are anomalies)
    logger.info("Training Isolation Forest model...")
    model = IsolationForest(
        n_estimators=100, 
        contamination=0.05,  # Expect 5% of traffic to be slightly anomalous
        random_state=42
    )
    
    model.fit(df)
    
    # Save the model
    os.makedirs(MODEL_DIR, exist_ok=True)
    model_path = os.path.join(MODEL_DIR, "iso_forest.joblib")
    joblib.dump(model, model_path)
    logger.info(f"✅ Model saved to: {model_path}")
    
    # Test inference on the training set
    predictions = model.predict(df)
    anomalies = (predictions == -1).sum()
    logger.info(f"Sanity Check: Model flagged {anomalies}/{len(predictions)} events as anomalies.")


if __name__ == "__main__":
    main()
