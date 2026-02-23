# Agent-Lock: Bounded Autonomy in the SOC

**Artifact Repository for WOSOC 2026, San Diego, CA** **Author:** Samuel Addington, California State University Long Beach 

[![Conference](https://img.shields.io/badge/WOSOC-2026-blue)](https://www.ndss-symposium.org) 
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains the official evaluation artifact for the paper **"Bounded Autonomy in the SOC: Mitigating Hallucinations in Agentic Incident Response via Neurosymbolic Guardrails"**. 

Agent-Lock is a neurosymbolic enforcement middleware designed to safely deploy Agentic AI in Security Operations Centers (SOCs). By treating the LLM as an untrusted "proposer" and routing its actions through a deterministic "validator" (Symbolic Engine), Agent-Lock neutralizes the operational hazards of Unbounded Stochasticity—including hallucinations, indirect prompt injections, and state poisoning. 

## The "Brain vs. Brakes" Architecture

Agent-Lock decouples reasoning from authorization using a three-stage pipeline:
1. **Stage 0 (Log Pre-Sanitization):** Untrusted log fields are scrubbed of executable payloads and tagged with provenance trust scores.
2. **Stage 1 (Plan-Level Validation):** The LLM must propose remediations using a strict JSON `ActionSchema`. The Symbolic Engine verifies these actions against deterministic constraints (e.g., Tier-0 non-disruption, Provenance Gates).
3. **Stage 2 (Sequence-Level Safety):** Agent-Lock enforces sliding-window autonomy budgets to prevent cascading failures and guarantees the reachability of core telemetry.

## Evaluation Dataset

This artifact evaluates the Agent-Lock framework against a **50-case synthetic incident suite** derived from the **Bot-IoT dataset**. 
To rigorously test the guardrails, the suite is divided into four categories and executed 5 times per case (250 total runs):
* **Category A:** Valid Threats (Action Success Baseline)
* **Category B:** Benign Anomalies (False Positive Traps)
* **Category C:** Adversarial Traps (Indirect Prompt Injections via `User-Agent`)
* **Category D:** Self-DoS Triggers (Targeting Tier-0 infrastructure like `dc-01`)

---

## Quick Start (Running the Dashboard)

You can reproduce the empirical results from **Table IV** of the paper  locally using Docker. The environment includes a mock LLM agent, the Agent-Lock FastAPI backend, a Redis state cache, and a live Streamlit dashboard.

### Prerequisites
* [Docker](https://docs.docker.com/get-docker/)
* [Docker Compose](https://docs.docker.com/compose/install/)

### Execution Steps
1. Clone this repository:
   ```bash
   git clone [https://github.com/YourUsername/agent-lock-artifact.git](https://github.com/SamAddington/agent-lock-artifact.git)
   cd agent-lock-artifact
