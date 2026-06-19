# Detecting Code Vulnerabilities with Large Language Models: An Empirical Study
Bachelor Thesis — Università della Svizzera Italiana, 2026  
**Author:** Enio Peza  
**Advisor:** Prof. Silvia Santini  
**Co-Advisor:** Catarina Morais

---

## Overview
This repository contains the full experimental materials for the bachelor 
thesis studying whether large language models (LLMs) can spontaneously 
detect hidden security threats in source code when performing a 
**simple code review**, without being told to look for vulnerabilities.

Eight open-weight LLMs (four code-specialized, four general-purpose) were 
evaluated on a purpose-built dataset of 14 Python code samples. Each sample 
either contains a single hidden threat (SQL injection, OS command injection, 
or hard-coded backdoor) or is a clean baseline.

## Dataset
The dataset consists of 14 Python snippets:

| Tier | Length | Vulnerable samples | Clean baselines |
|------|--------|--------------------|-----------------|
| Short | ≤ 600 chars | 3 (CWE-89, CWE-78, CWE-798) | 1 |
| Medium | 601–2000 chars | 3 (CWE-89, CWE-78, CWE-798) | 1 |
| Long | > 2000 chars | 3 (CWE-89, CWE-78, CWE-798) | 3 (SQLAlchemy, GitPython, Flask) |

**Vulnerability classes:**
- **CWE-89** — SQL injection 
- **CWE-78** — OS command injection
- **CWE-798** — Hard-coded credentials / hidden backdoor

## Models

### Code-specialized
| Model | Provider | Params |
|-------|----------|--------|
| Qwen2.5-Coder-14B-Instruct | Alibaba | 14.8B |
| Codestral-22B-v0.1 | Mistral AI | 22.2B |
| Yi-Coder-9B-Chat | 01.AI | 8.8B |
| StarCoder2-15B | BigCode | 15B |

### General-purpose
| Model | Provider | Params |
|-------|----------|--------|
| Gemma-3-12B-it | Google | 12B |
| Apertus-8B-Instruct | Swiss AI | 8B |
| Llama-3.2-3B-Instruct | Meta | 3.2B |
| Mistral-7B-Instruct-v0.3 | Mistral AI | 7.2B |

---

## Running the Experiment

### Requirements
```bash
pip install torch transformers accelerate
```

A CUDA-capable GPU with sufficient VRAM is required. Models up to 22B 
parameters were run on a single machine using 4-bit quantization.

Each script:
1. Verifies all models are reachable before starting
2. Iterates over every (model, sample) pair
3. Writes one JSON file per pair to a timestamped run directory under 
`results/raw/`
4. Logs progress to `experiment.log`

## Results
`results/raw/` contains one JSON file per `(model, sample, run)` triplet 
with the following fields:

```json
{
  "model_id": "...",
  "sample_id": "...",
  "length": "short | medium | long",
  "cwe": "89 | 78 | 798 | null",
  "prompt": "...",
  "model_response": "...",
  "status": "ok | error",
  "elapsed_sec": 12.4
}
```

`results/clean/` contains the manually annotated scoring: approve/reject 
verdict and whether the CWE was explicitly identified in the model's response.

---

## Prompt
The same prompt template is used for every model and every sample. The model 
is cast as a generic software engineer (not a security expert) and asked to 
produce two sections: a summary of what the code does and an approve/reject 
decision with a brief justification. The prompt never mentions security, 
vulnerabilities, or malicious behavior.
