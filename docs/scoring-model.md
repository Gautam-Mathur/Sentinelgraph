# SentinelGraph Scoring Model (`v2.0.0`)

<!-- GENERATED FILE: edit ScoringModelConfig in backend/app/domain/scoring.py, not this file. -->

## Purpose and non-probability guarantee

The priority score is a deterministic, normalised remediation-triage ranking on
[`0, 100`]. It is **not** a breach probability,
exploit-likelihood percentage, prediction of compromise, or SLA estimate.

> Weighted, normalised priority ranking (0-100) for remediation triage. In v2.0.0, priority_score ranks by structural hazard (impact, exposure, privilege) and reports evidence_confidence and missing_data_penalty separately so uncalibrated scanner confidence does not demote critical attack paths. Not a calibrated statistical probability of breach.

## Published formula

```text
structural_raw          = 100.0 * impact_weight * exposure_factor * privilege_factor
structural_score        = round(clamp(0.0, 100.0, structural_raw), 2)
evidence_weighted_score = round(clamp(0.0, 100.0,
                                structural_raw * evidence_confidence * missing_data_penalty), 2)
priority_score          = structural_score  # default ranking_mode="structural"
```

Decoupling `structural_score` from epistemic certainty (`evidence_confidence`,
`missing_data_penalty`) ensures that uncalibrated scanner confidence scores
cannot push critical Crown Jewel attack paths below low-impact paths. Evidence
certainty remains visible alongside `priority_score`, and callers may still
request opt-in `ranking_mode="evidence_weighted"` when desired.

The implementation and this document share one typed configuration:
`SCORING_MODEL` in `backend/app/domain/scoring.py`. The rendered values below are
not a second, hand-maintained scoring specification.

## Component definitions

### 1. Impact weight

- Clamp range: [0.25, 1.00].
- Target criticality weights:

| Criticality | Weight |
|---|---:|
| `critical` | 1.00 |
| `high` | 0.80 |
| `medium` | 0.50 |
| `low` | 0.25 |
- Unknown criticality falls back to `0.50`.
- Crown-jewel designation overrides the weight to `1.00`.
- A target with `privilege_level == "domain_admin"` receives at least `0.95`.

### 2. Exposure factor

- External-entry start: `1.00`.
- Other start: `0.60`.
- If a non-external start has an `EXPOSES` or `CONNECTS_TO` step, its starting exposure is at least `0.72`.
- Hop attenuation: `max(0.45, 1.0 - 0.06 * max(0, hop_count - 1))`.
- Final clamp range: [0.35, 1.00].

### 3. Privilege factor

- Base: `0.62`; clamp range [0.40, 1.00].
- `CAN_ADMINISTER`: at least `1.00`.
- `HAS_ROLE` or `TRUSTS`: at least `0.85`.
- `MEMBER_OF`: at least `0.75`.
- A node with privilege level `privileged` or `domain_admin`: at least `0.90`.

### 4. Evidence confidence

- Each edge confidence is clamped to [0.05, 1.00].
- The combined value is `0.50 * minimum_edge_confidence + 0.50 * arithmetic_mean_edge_confidence`.
- Each inferred relationship applies attenuation `0.88 ** inferred_edge_count`, with a minimum multiplier of `0.50`.
- Final clamp range: [0.10, 1.00].

### 5. Missing-data penalty

- Start at `1.00`.
- Stale nodes multiply by `0.92 ** stale_node_count`.
- Steps missing corroboration multiply by `0.90 ** uncorroborated_step_count`.
- Each category's multiplier is floored at `0.65`; final clamp range is [0.50, 1.00].

## Reproducibility and interpretation

Each path stores the scoring version, component values, formula, and
`is_probability: false` in its explanation trace. Determinism hashes include the
scoring version. Changing any scoring constant or calculation requires an intentional
version decision and regression review.

The score is a heuristic ranking for triage. It has not been calibrated to empirical
breach frequencies and must not be interpreted as a probability.
