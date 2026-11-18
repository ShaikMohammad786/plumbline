# Plumbline Repo Truth Score Documentation

Plumbline computes an objective, normalized **0–100 Repo Truth Score** and assigns a letter grade (A, B, C, D, or F).

## Penalty Calculation

For each finding:
```
finding_penalty = severity_weight * confidence_mult * path_mult
```

### Weights & Multipliers

#### Severity Weight
- **Critical**: 20.0
- **High**: 8.0
- **Medium**: 3.0
- **Low**: 1.0
- **Info**: 0.0

#### Confidence Multiplier
- **High**: 1.0
- **Medium**: 0.6
- **Low**: 0.3

#### Path Classification Multiplier
- **Production (`prod`)**: 1.0
- **Test (`test`)**: 0.2
- **Example / Docs (`example`, `docs`)**: 0.3
- **Generated (`generated`)**: 0.1
- **Vendor (`vendor`)**: 0.0

---

## Logarithmic Rule Dampening

To prevent a single noisy rule from disproportionately destroying the repository score, multiple findings of the same rule scale logarithmically:
```
rule_penalty = base * (1 + 0.5 * ln(n))
```
where `base` is the largest single finding penalty for that rule, and `n` is the count of findings for that rule.

---

## Claim Ledger Penalties

- **CONTRADICTED**: 10.0 points
- **UNSUPPORTED**: 5.0 points
- **PARTIAL**: 2.0 points
- **VERIFIED**: 0.0 points

---

## Final Score & Grading Scale

```
score = max(0, 100 - round(total_penalty))
```

- **A**: Score >= 90 (Excellent truth fidelity)
- **B**: Score >= 80 (Good code health, minor loose ends)
- **C**: Score >= 70 (Moderate concerns or missing controls)
- **D**: Score >= 60 (Significant gaps or security issues)
- **F**: Score < 60 (Critical vulnerabilities, AI slop, or contradicted claims)
