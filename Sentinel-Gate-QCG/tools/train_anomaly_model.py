"""Train the optional IsolationForest anomaly model.

The in-path detector works without any model (transparent statistical scorer).
This script trains an optional ``IsolationForest`` on the SAME four features
the detector computes online -- [rate, iat_mean, iat_cv, err_ratio] -- so it
can be dropped in via SENTINEL_ANOMALY_MODEL_PATH for sharper separation.

IsolationForest is unsupervised: it learns the shape of *normal* traffic and
flags outliers. We fit on mostly-benign traffic with a small contamination
fraction. The model's ``score_samples`` is pure-Python/NumPy and runs in
microseconds -- there is never a network call in the request path.

    python tools/train_anomaly_model.py --samples 20000 --out model.joblib
"""

from __future__ import annotations

import argparse

import numpy as np


def synth_benign(n: int, rng: np.random.Generator) -> np.ndarray:
    """Humans: modest rates, irregular timing (high CV), low error ratio."""
    rate = rng.lognormal(mean=0.0, sigma=0.6, size=n)          # ~1 req/s, spread
    iat_mean = 1.0 / np.clip(rate, 1e-3, None)
    iat_cv = rng.uniform(0.4, 1.5, size=n)                     # bursty/irregular
    err = rng.beta(1.2, 30.0, size=n)                          # mostly near 0
    return np.column_stack([rate, iat_mean, iat_cv, err])


def synth_attack(n: int, rng: np.random.Generator) -> np.ndarray:
    """Bots: high or metronomic rates, very low CV, or high error ratios."""
    rate = rng.lognormal(mean=2.5, sigma=0.8, size=n)          # much faster
    iat_mean = 1.0 / np.clip(rate, 1e-3, None)
    iat_cv = rng.uniform(0.0, 0.15, size=n)                    # robotic regularity
    err = rng.uniform(0.3, 1.0, size=n)                        # fuzzing/scanning
    return np.column_stack([rate, iat_mean, iat_cv, err])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=20000)
    ap.add_argument("--contamination", type=float, default=0.05)
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    import joblib  # imported here so the base gateway need not have ML
    from sklearn.ensemble import IsolationForest

    rng = np.random.default_rng(args.seed)
    n_attack = int(args.samples * args.contamination)
    n_benign = args.samples - n_attack
    X = np.vstack([synth_benign(n_benign, rng), synth_attack(n_attack, rng)])
    rng.shuffle(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=args.contamination,
        random_state=args.seed,
    )
    model.fit(X)
    joblib.dump(model, args.out)

    # Quick sanity check: attack-like vectors should score as more anomalous.
    benign = synth_benign(1000, rng)
    attack = synth_attack(1000, rng)
    print(f"Trained on {args.samples} samples -> {args.out}")
    print(f"  mean score_samples  benign: {model.score_samples(benign).mean():+.4f}")
    print(f"  mean score_samples  attack: {model.score_samples(attack).mean():+.4f}")
    print("  (lower = more anomalous; attack should be clearly lower)")
    print(f"\nSet SENTINEL_ANOMALY_MODEL_PATH={args.out} to enable it.")


if __name__ == "__main__":
    main()
