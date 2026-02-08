# Models folder

This folder holds **trained models** produced by HybridGuard when you run the app.

- **`isolation_forest_model.pkl`** — Trained Isolation Forest (anomaly detection). Trained on the data in `data/` (or in-memory sample data if `data/` is empty).
- **`isolation_forest_model_scaler.pkl`** — Fitted scaler used to normalize flow features the same way as at training time.

They are **not** downloaded from elsewhere: the app trains them on first run (or when the files are missing) and then **loads** them on later runs. So the models you are using are **trained by this project** (on sample or CIC-IDS2017 data), not pre-trained weights from the internet.

**To retrain from scratch** (e.g. after adding CIC-IDS2017 data):
```bash
rm -f models/isolation_forest_model.pkl models/isolation_forest_model_scaler.pkl
python main.py
```
The app will train a new model and save it here again.
