# Datasets for CyberVault (synthetic + real)

## Already downloaded in this workspace

| Dataset | Path | Notes |
|---------|------|--------|
| **CERT r4.2** | `cert/logon.csv` (~56MB, 854k rows) | From HuggingFace mirror; labels in `cert/answers.json` (70 insider users) |
| **LANL cyber1** | `lanl/auth.txt` (150k-line sample) + `redteam_raw.txt` (749 events) | Via LANL data-fence API |
| **Synthetic** | built-in generator | `seed=42` for the paper |
| **PAM** | `pam/` | Drop your anonymized JumpServer JSONL here |

## Re-download

```bash
cd ai-security-service
python -m aiss.evaluation.download_datasets
python -m aiss.evaluation.download_datasets --auth-lines 300000
```

## Notebook usage (both worlds)

```python
DATASET_SOURCE = 'synthetic'     # Expérience 1 — reproductible
# then later:
RUN_MULTI_DATASET = True
MULTI_SOURCES = ['synthetic', 'cert', 'lanl']
```

Each source trains **its own** model weights; you compare **methods** across tables.

## Sources / license

- CERT: Lindauer, CMU KiltHub DOI 10.1184/R1/12841247 — mirror used for automation
- LANL: https://csr.lanl.gov/data/cyber1/ — token fence; academic use disclosure required
