# Research notes

Verified on 2026-09-06. This is a design investigation, not a benchmark or a security certification of the referenced projects.

## The two posts

The [first post by 0x0SojalSec](https://x.com/0x0sojalsec/status/2074622871771717837) links an article comparing locally deployable cybersecurity models. It names VulnLLM-R-7B, Foundation-Sec-8B-Reasoning, CyberSecQwen-4B, and Meta-SecAlign-8B, among smaller/general alternatives. Its useful design idea is local specialist inference; the proposed model ranking and hardware claims still require validation for our workload.

The [second post by 7h3h4ckv157](https://x.com/7h3h4ckv157/status/2096412820384653656) points to [mukul975/cve-mcp-server](https://github.com/mukul975/cve-mcp-server). It describes correlated vulnerability and threat intelligence. This supplies external facts to an analyst; it does not provide an end-to-end target-testing workflow.

Direct X page retrieval did not expose the full content. The article blocks and second post text were recovered through the public FxTwitter API, then their technical claims were checked against upstream model cards and repository files. No social-media benchmark assertion is treated as a measured result on this Mac.

## Model candidates

| Candidate and primary source | Verified scope | Argo decision |
| --- | --- | --- |
| [VulnLLM-R-7B](https://huggingface.co/Virtue-AI-HUB/VulnLLM-R-7B) | Specialized software vulnerability analysis. The earlier UCSB-SURFI URL redirects to Virtue-AI-HUB. The [paper](https://arxiv.org/abs/2512.07533) evaluates Python, C/C++, and Java. | Candidate for source review, with separate TypeScript/JavaScript evaluation for AgentLab projects. Published benchmark comparisons do not establish general pentest or tool-use superiority. |
| [Foundation-Sec-8B-Reasoning](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning) | Cisco's instruction/reasoning model for security analysis; its documented data cutoff is April 2025. | First analyst candidate. Current vulnerability facts must come from sources, not model memory. Validate quantization, final-answer parsing, and action-schema adherence. |
| [CyberSecQwen-4B](https://huggingface.co/athena129/CyberSecQwen-4B) | A Qwen3-based CTI specialist evaluated for CWE mapping and CTI questions. The authors release BF16 weights and do not validate community quantizations. | Optional small classifier. The model card does not demonstrate general autonomous pentesting or Apple Silicon performance. |
| [Meta-SecAlign-8B](https://huggingface.co/facebook/Meta-SecAlign-8B) | A defensive LoRA adapter with a specific trusted/untrusted input representation. | Optional hostile-input experiment. It is not a standalone drop-in guard, and its name alone provides no runtime isolation. |

The exact GGUF artifacts remain unselected. No model is automatically downloaded. Track source revision, quantizer/conversion provenance, checksum, license reference, template, and evaluation results before promoting a model. Model terms are separate from Argo's MIT license.

Native Ollama is a reasonable serving candidate because its [hardware documentation](https://docs.ollama.com/gpu) supports Apple Metal and its [structured-output interface](https://docs.ollama.com/capabilities/structured-outputs) accepts JSON Schemas. This does not prove a particular converted model can follow an action contract accurately.

## CVE MCP source inspection

Inspected upstream commit: [`d666bac3743574cecc98bcbf524558c2bf0d8e61`](https://github.com/mukul975/cve-mcp-server/commit/d666bac3743574cecc98bcbf524558c2bf0d8e61).

Source files were downloaded to a temporary review directory and read, not executed. No upstream package was installed and no upstream test suite was run.

| Observation | Source | Integration consequence |
| --- | --- | --- |
| AST inspection finds 28 registered MCP tools. Examples in the README do not consistently match their Python names/signatures. | [server.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/server.py) | Discover and verify the actual tool schema before enabling calls. |
| Actual signatures include `check_kev(cve_id)`, `get_epss_score(cve_ids)` where `cve_ids` is a string, and `scan_dependencies(dependency_list)` where the input is text. | [server.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/server.py) | Do not use the README's alternate names or argument shapes. Parse lockfiles ourselves to preserve resolved versions. |
| Startup validates NVD access and fetches KEV; `triage_cve` can invoke fallback providers, and its default depth adds PoC discovery. | [server.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/server.py) | Offline mode must bypass the online sidecar. Review the transitive call graph before enabling composite tools. |
| Tool results are largely formatted strings; errors can also be returned as text. | [server.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/server.py) | Build normalization and missing-data tests. Never interpret an empty/error response as a clean scan. |
| Real environment names include `ABUSEIPDB_KEY`, `VIRUSTOTAL_KEY`, `SHODAN_KEY`, and `CIRCL_PDNS_PASS`; modules call `load_dotenv()`. | [config.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/config.py) | Use an isolated environment and working directory. Inject credentials through Hush rather than ambient project files. |
| Validators contain provider hostname and public-address checks. | [validators.py](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/src/cve_mcp/utils/validators.py) | These do not replace Argo's per-engagement scope or network enforcement. End-to-end SSRF behavior has not been tested. |
| Dependencies use broad lower bounds; the license classifier says MIT, while the inspected LICENSE contains Apache 2.0 text. | [pyproject.toml](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/pyproject.toml), [LICENSE](https://github.com/mukul975/cve-mcp-server/blob/d666bac3743574cecc98bcbf524558c2bf0d8e61/LICENSE) | Produce a locked environment and resolve inconsistent packaging metadata before redistribution. Argo does not vendor this code. |

The repository's description of itself as production-grade is not an assurance we inherit. The narrow adapter should first test individual CVE/EPSS/KEV calls using recorded fixtures, then test permitted live provider calls separately.

## Scanner references

- [Nuclei running documentation](https://docs.projectdiscovery.io/opensource/nuclei/running): use a reviewed and pinned template subset. A category or severity filter alone does not establish that every template is appropriate for an engagement.
- [ZAP baseline documentation](https://www.zaproxy.org/docs/docker/baseline-scan/): baseline scanning includes a spider followed by passive analysis. It still sends target requests and therefore needs scoped crawling and a request budget.

## Local observations

| Check | Observed result |
| --- | --- |
| Hardware | MacBook Pro, Apple M1 Max, 10 CPU cores, 64 GB unified memory |
| Operating system | macOS 26.6.2, build 25G83 |
| Disk | Approximately 81 GiB available at inspection time |
| Ollama | Client 0.30.7 installed; loopback API on port 11434 was not reachable during inspection |
| Docker | Client 29.7.2, ARM64, desktop-linux context; initial daemon query was denied at the socket boundary, so daemon readiness is unverified |
| Language tooling | Python, Node.js, and `uv` are installed |

No serial numbers, hardware UUIDs, credentials, private source, or model outputs were collected for this document. Free disk space and service state are transient observations. Starting services and downloading weights are implementation steps, not completed setup.

A quantized 7B–8B model is a sensible first capacity experiment on a 64 GB machine. That is an engineering inference from model size and available memory, not a latency or quality benchmark. One-model scheduling avoids assuming that several models, long context caches, Docker workers, and everyday applications can all fit comfortably at once.

## Existing AgentLab references

Local inspection found a sibling Bowie runtime with task containers and MCP support, a Hush secrets tool, Mcaifee under `prot/`, and the GemmaCode Ollama launcher. Bowie currently exposes generic shell execution and does not configure the network restrictions required by this design. Reuse selected ideas and separately reviewed components; do not launch the existing general-purpose agent as the pentest controller.
