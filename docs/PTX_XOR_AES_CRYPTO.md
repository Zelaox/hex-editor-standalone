# PTX XOR & AES — Hex Editor Decrypt Probing

## Plaintext-profile evidence

The registry signal `plaintext_profile_similarity` compares each transformed window with policy-built byte profiles for reference families. It combines histogram, configured byte-class, hashed-token, hashed byte-sequence, and UTF-8 similarities. Threshold bonuses live in `config/crypto_defaults.json`, while feature extraction, sequence lengths, discovery rules, and privacy limits live in `config/plaintext_profile_policy.json`.

Dynamic key hunt evidence sent to Gemma is deliberately reduced to profile ID, similarity components, and similarity gain over the original bytes. No reference path or token fingerprint is included. Profile similarity is advisory ranking evidence only and never replaces cross-window, graph, timeline, coverage, non-identity, or integrity validation.

How **`Hex editor/src/services/`** evaluates XOR and AES-128 candidates: bounded sweeps, two-stage scoring, mechanical promotion, artifact materialization.

**Project:** Hex Editor (`Hex editor/`)  
**Plan (next):** [plans/binary_transform_inference_engine/plan.md](plans/binary_transform_inference_engine/plan.md)  
**Calibration (loaded by `ptx_crypto_config.py`):** `../tests/fixtures/hex_parser_calibration/ac240_ptx_calibration.json`

---

## Entry points (Hex Editor)

| Layer | Path | Role |
|-------|------|------|
| Probe API | `src/services/ptx_key_discovery.py` | `probe_ptx_decrypt_keys` |
| Analysis | `src/services/ptx_crypto_analysis.py` | XOR sweep + known-key + AES |
| Primitives | `src/services/ptx_crypto_primitives.py` | `xor_apply`, AES-128-ECB |
| Promotion | `src/services/ptx_promotion_gate.py` | Mechanical gate |
| Evidence | `src/services/ptx_transform_evidence.py` | Before/after, preserve, diff |
| Materialize | `src/services/ptx_auto_decrypt.py` | Decrypted copy + source snapshot |
| Desktop confirmation | `src/services/ptx_desktop_decrypt.py` | Probe → promotion gate → atomic selected output; source overwrite refused |
| Config | `src/services/ptx_crypto_config.py` | Loads calibration fixture |

AI Lab MCP calls the same services — Hex Editor owns the implementation.

**Invariant:** Pure Python only. No HuggingFace, no external crypto libs.

---

## Shared transform model

```text
[ preserved prefix 0 .. xor_start_offset )  +  T( body from xor_start_offset .. EOF )
```

- **`xor_start_offset`** — from calibration (`crypto_defaults.xor_start_offset` or per-case `decrypt.xor_start_offset`).
- **Preserve region** — bytes before offset copied unchanged.
- **Body** — transform target from offset to EOF.

Scoring uses **body windows** from fixture (`probe_windows`, `evidence_windows`, `preserve_evidence_windows`).

---

## XOR — primary lane

### Primitive (`ptx_crypto_primitives.xor_apply`)

```text
out[i] = data[i] ^ key[i % len(key)]
```

Ready for any repeating key length; sweep today only covers L=1 and L=2.

### Sweep (config-driven)

| Algorithm | Keys | Cursor range |
|-----------|------|--------------|
| `xor_single_byte` | 256 | 0–255 |
| `xor_repeating_byte` | 2304 | 256–2559 |

Total: `sweep_key_limit` = **2560** from fixture `probe_pipeline` — not hardcoded in Python.

### Known-key lane (first when `include_known=true`)

1. Fixture `known_keys` + case `decrypt.key_hex`
2. PT12 sig XOR: `sum(first 4 bytes) mod 256` (computed, not fixed `0x94`)
3. Optional `algorithm: aes128_ecb` entries (16-byte keys)

### Materialize

```python
decrypted = raw[:xor_start] + xor_apply(raw[xor_start:], key)
```

---

## AES-128 — advisory lane

Not in the 2560 XOR sweep. Runs in known-key lane only.

- **Mode:** AES-128 ECB (pure Python)
- **Keys:** five prefix-derived candidates via `derive_aes_candidate_keys(header[:64])`
- **Stage2:** only when `cheap score >= found_score_threshold` (fixture default 8)

---

## Two-stage pipeline

| Stage | Work |
|-------|------|
| **Cheap** | Window scoring on all batch keys |
| **Stage2** | Full file + evidence + promotion for survivors |

Config: `probe_pipeline.cheap_top_k`, `stage2_top_k`, `cheap_min_score`.

**Known issue:** code uses `stage2_cap = max(cheap_top_k, stage2_top_k)` so with 8/4 config, logs show `stage2=8`. See transform inference plan **T0b**.

---

## Scoring (today)

Per window after transform:

- Marker hits (`_PT_MARKERS` — migrate to `config/markers.json`)
- Printable ratio
- Entropy drop (weak for XOR — plan adds structure signals)
- Identity flag

---

## Promotion gate

`keys_found=true` ⇔ **`promoted=true`**, not high score.

Rejects: identity transform, SHA equals source, preserve region mutated, plaintext regression.

Requires: cross-window agreement, structural improvements, transform evidence `promote_allowed=true` (or reference SHA match).

---

## Config SSOT

Today: lab fixture `ac240_ptx_calibration.json` via `ptx_crypto_config._lab_root()`.

Target: **`Hex editor/config/`** owns defaults; fixture overrides per case. See [transform inference plan](plans/binary_transform_inference_engine/plan.md).

---

## Samples

| File | Outcome |
|------|---------|
| `ac240.ptx` | 2560 XOR + AES derived; typically no promote |
| `1ac240.ptx` | `already_at_reference_digest` |

Debug: `Hex editor/logs/`, or MCP probe with `promotion_evidence.reject_reasons`.
