# SentinelGraph Scoring Model (`v1.0.0`)

## Methodology & Non-Probability Guarantee

SentinelGraph's priority score is a **deterministic, normalised remediation triage ranking on `[0, 100]`**.

> **Important:** `priority_score` is **NOT** a statistical breach probability, exploit likelihood percentage, or SLA prediction.

---

## Published Formula (`scoring_version = "v1.0.0"`)

```text
raw_score = 100.0 * impact_weight * exposure_factor * privilege_factor * evidence_confidence * missing_data_penalty
priority_score = round(clamp(0.0, 100.0, raw_score), 2)
```

### Component Definitions

1. **`impact_weight`** (`0.25 .. 1.00`):
   - Derived from target node criticality & crown-jewel designation:
     - `critical` / `is_crown_jewel=True`: `1.00`
     - `high`: `0.80`
     - `medium`: `0.55`
     - `low`: `0.35`
2. **`exposure_factor`** (`0.40 .. 1.00`):
   - Base exposure from entry node reachability (`0.95` when `is_external_entry=True`, else `0.70`), adjusted by hop decay `0.95 ** max(0, hop_count - 1)`.
3. **`privilege_factor`** (`0.60 .. 1.00`):
   - Reflects privilege escalation / administration transitions present on the path (`1.00` when path includes `CAN_ADMINISTER` or admin privileges, `0.85` for `CAN_ASSUME`/`MEMBER_OF`, `0.70` otherwise).
4. **`evidence_confidence`** (`0.05 .. 1.00`):
   - Weighted geometric mean / attenuated product across step edge confidences (`0.05 .. 1.0`), with explicit attenuation (`× 0.85` factor per `inferred_relationship` step) so unconfirmed inferences never outrank hard observed facts.
5. **`missing_data_penalty`** (`0.70 .. 1.00`):
   - Applies explicit completeness deductions (e.g., missing banner versions, missing observation timestamps, unverified host ownership metadata).

---

## Reproducibility

Every persisted `AttackPath` stores:
- `scoring_version` (`"v1.0.0"`)
- Individual component values (`impact_weight`, `exposure_factor`, `privilege_factor`, `evidence_confidence`, `missing_data_penalty`)
- `determinism_hash` (SHA-256 of canonical ordered edges & algorithm parameters)
- Explicit `assumptions` and `"is_probability": false` inside `explanation_trace.scoring`.
