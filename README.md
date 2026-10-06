# IT Security & ISMS Compliance Q&A Agent

AI agent for answering IT security policy and ISMS compliance questions, built with Agentic Star.

> **Category**: Cat 2 (a domain pipeline: a retrieval workflow behind the fixed agent backbone)
> **Industry**: Services
> **Template ID**: SVC-C2-013

## Overview

Answers IT-security-policy and ISMS compliance questions for enterprise IT and compliance
teams — what a standard clause requires, which Japanese regulation applies, what an
organisation must do about breach notification — grounded strictly in a corpus of standard
and regulation excerpts (ISO/IEC 27001 and 27002 Annex A material, the 不正アクセス禁止法,
the 個人情報保護法, and the METI サイバーセキュリティ経営ガイドライン). Every answer cites the
standard or regulation clause it is grounded in and ends with an action checklist and a
standing disclaimer. When no corpus passage clears the relevance threshold the agent says so
and recommends a professional consultant rather than inventing a requirement.

A caller may also submit compliance focus terms — control names, policy areas — alongside the
question. Those terms take part in retrieval and ranking, and the answer states which focus
was applied. They travel on a separate structured channel for a concrete reason: an English
control name is written as consecutive capitalised words, which is the shape the platform's
input screen masks on the question field, so a term sent inside the question would arrive as
a mask token and retrieval would key off the mask. The structured channel is screened by this
template instead, and a term carrying a contact identifier is refused rather than masked.

Retrieval and answer composition are deterministic and offline: the shipped corpus is scored
by keyword and standard-reference overlap and the answer is assembled from the retrieved
text, so the same question always returns the same answer. Swapping in a vector store and a
constrained model is a configuration change, not a rewrite.

This is an agent template built with the **AGENTIC STAR** development platform and the
**AgentCore Framework**. It is intended to be taken as a starting point: fork it, adapt it to
your own data and policies, and run it inside your own AGENTIC STAR deployment.

## Requirements

**This template does not run standalone.** It requires:

| Requirement | Notes |
|---|---|
| **AGENTIC STAR platform** | The agent connects to the platform at start-up. Without it, start-up fails immediately (see *Behaviour without the platform* below). Deployment guides and API documentation: [AGENTIC STAR Developers](https://developers.fd.agenticstar.tm.softbank.jp/) |
| **AgentCore Framework** (`agenticstar-agentcore`) | Installed from PyPI as a dependency. |
| Python | >=3.11 |

```bash
pip install -e .
```

### Behaviour without the platform

The framework is designed to run **only** on AGENTIC STAR. There is no fallback or degraded
mode. If the platform is unreachable or the SDK version does not match, the agent fails at
graph compile / start-up preflight rather than starting in a partially working state. This is
intentional — a half-running agent is worse than one that refuses to start.

## Quick Start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest tests/ -v
```

Tests run without a platform connection. Running the agent itself does not.

## Project Structure

```
src/          agent implementation (nodes, graphs, schemas)
tests/        unit and boundary tests
config/       agent manifest and runtime parameters
prompts/      grounded-generation prompt template
docs/         design and test documentation
```

See `docs/02_design.md` for the architecture and the security boundaries, and
`docs/03_test_spec.md` for what the suite covers.

## Customising

1. Replace the seeded corpus in `src/nodes/retrieve_node.py` with your own standards and
   policy material — each entry carries `chunk_id`, `source`, `standard_ref`, `text` and
   `keywords`; the retrieval contract does not change. A production deployment swaps the
   in-module corpus for a real vector store behind the same node.
2. Tune `config/config.yaml` — the result count and the relevance threshold. Those values are
   read at start-up and reach the pipeline; the module defaults are only a floor for a key
   you leave out.
3. Adapt the disclaimer in `src/nodes/output_format_node.py` to your own advisory duty, and
   the standard-reference keyword table in `src/nodes/input_validate_node.py` to the
   standards your organisation answers for.
4. Re-run the test suite.

## License

MIT — see [LICENSE](LICENSE).

## Status of this repository

This template is published **as is**, by its individual author, under the MIT license. It carries
**no warranty and no support commitment**, and no organisation stands behind its behaviour or
fitness for any purpose. Issues and pull requests may or may not receive a response; that is at
the sole discretion of the repository owner.
