# Smart Contract Security Scanner Blueprint

## 1. Project Summary

Smart Contract Security Scanner is a web-based security analysis platform for Solidity/EVM smart contracts. The first version targets the Monad ecosystem, but the architecture must stay compatible with Arc and other EVM-compatible ecosystems.

Users can start a scan by either:

- Pasting Solidity source code
- Uploading a single `.sol` file

V1 is optimized for single-file or flattened Solidity contracts. For best results, users should upload a flattened Solidity file.

The scanner performs static analysis and returns an actionable report with risk level, findings, locations, explanations, exploit scenarios, fix suggestions, and JSON/Markdown exports.

The first version is intentionally limited to static analysis. GitHub repository scanning, contract address scanning, multi-file project analysis, dynamic testing, fuzzing, and automatic code rewriting are roadmap items.

## 2. Core Product Scope

### Included In V1

- Solidity/EVM static analysis
- Single `.sol` file input
- Pasted Solidity code input
- Slither static analysis integration
- LLM-based explanation layer
- Finding normalization and deduplication
- Risk scoring
- Web UI report
- JSON export
- Markdown export
- Basic abuse prevention (per-IP rate limit + max concurrent scans)
- Unguessable scan IDs (UUID v4)

### Not Included In V1

- GitHub repository scan
- Contract address scan
- Multi-file project scan
- Dynamic testing
- Fuzzing
- Custom deterministic Rule Engine
- Automatic full contract rewrite
- PDF export
- Code editor line-by-line annotations
- User accounts, authentication, and per-user authorization
- Durable job queue and separate worker service
- WebSocket/SSE live progress
- Multi-provider LLM fallback
- Automatic data retention/cleanup jobs

> Access model note: V1 has no user accounts. Scans are protected only by an unguessable UUID v4 `scan_id` (capability-style access: whoever has the link can view the report). Full authentication and per-user authorization are a deliberate Future item, not an oversight. See Section 20.

## 3. High-Level Pipeline

Every scan must follow this pipeline:

1. Input intake
2. Input validation
3. Solidity preprocessing
4. Solidity parsing, with fallback to pattern-based parsing
5. Slither analysis inside Docker sandbox
6. Slither JSON parsing
7. Raw finding normalization
8. Deduplication
9. LLM contract-level summary
10. LLM finding-level explanation
11. Risk scoring
12. Report generation

The pipeline must preserve source line numbers so every finding can point to a file, contract, function, and line range.

## 4. Analyzer Responsibilities

### Slither Integration

Slither is the only vulnerability detection source in V1. Slither findings are treated as issues detected by static analysis, not as guaranteed confirmed vulnerabilities. Slither provides professional static analysis coverage and must run inside a Docker sandbox, not directly on the host.

Slither output must be normalized before being shown to users. Raw Slither output should not be exposed directly in the UI.

If Slither fails in V1, the scan cannot produce detected findings. The scan should be marked as `failed` unless the failure is a partial issue where Slither still returns usable JSON output.

Slither execution flow:

1. Backend creates a temporary scan folder
2. Backend writes the submitted source as `Contract.sol`
3. Docker container starts with network disabled
4. Slither runs inside the container
5. Slither writes JSON output
6. Backend parses the JSON output
7. Backend normalizes each Slither detector result into the common finding model
8. Container and temporary files are removed

Practical Slither command:

```bash
slither /scan/Contract.sol --json /scan/slither-output.json
```

Import and dependency policy:

- V1 supports pasted Solidity code and one `.sol` file only
- V1 is optimized for single-file or flattened Solidity contracts
- External imports should be detected and shown in contract metadata
- V1 does not automatically resolve missing dependencies
- If imports or dependencies are required for compilation and unavailable, the scan must fail gracefully
- User-facing guidance should say: "For best results, upload a flattened Solidity file."

Required Slither output fields to preserve when available:

- Detector name
- Check type
- Impact
- Confidence
- Description
- Source mapping
- Filename
- Contract name
- Function name
- Line start
- Line end
- Code snippet or evidence text

Slither impact mapping:

- `High` -> `High`
- `Medium` -> `Medium`
- `Low` -> `Low`
- `Informational` -> `Informational`

Slither confidence mapping:

- `High` -> `High`
- `Medium` -> `Medium`
- `Low` -> `Low`

Slither detector category mapping:

- `reentrancy-*` -> Reentrancy
- `unchecked-*` -> Transfer Safety
- `tx-origin` -> Access Control
- `delegatecall` -> Dangerous EVM
- `controlled-delegatecall` -> Dangerous EVM / Access Control
- `timestamp` -> Randomness
- `assembly` -> Dangerous EVM
- `solc-version` -> Code Quality

### LLM Analysis Layer

The LLM is a bounded reporting layer. It does not detect vulnerabilities in V1 and does not create new findings. Its job is to summarize what the contract appears to do and generate readable report text from normalized Slither results.

The LLM may only:

- Summarize the apparent contract purpose from the provided source code
- Summarize high-level risk areas based only on Slither findings
- Rewrite Slither findings into developer-friendly report language
- Generate technical explanations for existing Slither finding IDs
- Generate exploit scenarios for existing Slither finding IDs
- Generate fix suggestions for existing Slither finding IDs
- Add false-positive notes for existing Slither finding IDs

The LLM must not:

- Create new findings
- Add new vulnerability categories
- Change Slither severity, confidence, status, source, location, or evidence
- Make final security decisions
- Create Critical or High findings
- Invent missing files, dependencies, or business logic
- Rewrite the whole contract
- Claim something is vulnerable unless the claim is tied to a provided Slither finding
- Output any finding ID that was not provided by the backend

In V1, every finding must come from Slither. There are no LLM-only findings, no LLM-only observations, and no separate `Potential` findings generated by the LLM.

LLM prompt rules:

- Analyze only the provided Solidity code, contract metadata, and normalized Slither findings
- Use Slither findings as the only vulnerability source
- Return text only for the finding IDs provided in the input
- Do not add, remove, merge, split, or reorder findings
- Do not change severity, confidence, status, source, location, score, or evidence
- Do not invent missing files or dependencies
- Do not assume hidden business logic
- Do not rewrite the full contract
- Provide fix suggestions, not full patched code
- Return structured JSON only

LLM input must be built by the backend, not by the frontend:

LLM source size policy (V1):

The `source_excerpt_policy` field controls how much source is sent to the LLM. V1 uses a single explicit threshold so behavior is deterministic on large contracts.

- Define `LLM_SOURCE_CHAR_LIMIT` in config. Recommended starting value: `45000` characters (roughly safe for an 8k–16k token context with room for findings and instructions). Tune to the chosen model.
- If `source_code` length <= `LLM_SOURCE_CHAR_LIMIT`: send full source. `source_excerpt_policy` = `"full_source"`.
- If `source_code` length > `LLM_SOURCE_CHAR_LIMIT`: do NOT send the full file. Instead send, per finding, a window of source lines around each finding's `line_start`/`line_end` (recommended: 30 lines before and after, merged when windows overlap), plus the contract metadata. `source_excerpt_policy` = `"windowed_excerpt"`.
- The LLM never blocks the scan on size. If even the windowed excerpt cannot be built or the provider rejects the request, treat it as `LLM_FAILED` (warning) and fall back to Slither-only report text (see LLM fallback behavior below).
- Slither always runs on the full source regardless of this limit. This policy only bounds what the LLM sees, never what is analyzed.

```json
{
  "contract_metadata": {},
  "source_excerpt_policy": "full_source_for_v1_if_under_limit",
  "source_code": "pragma solidity ...",
  "findings": [
    {
      "id": "FIND-001",
      "title": "Unchecked low-level call",
      "category": "Transfer Safety",
      "severity": "High",
      "confidence": "High",
      "location": {
        "contract": "Vault",
        "function": "withdraw",
        "line_start": 42,
        "line_end": 45
      },
      "evidence": ["msg.sender.call{value: amount}(\"\")"],
      "slither_description": "The return value of a low-level call is not checked."
    }
  ]
}
```

LLM output must use exactly this top-level shape:

```json
{
  "contract_summary": "",
  "main_risk_areas": [],
  "finding_explanations": []
}
```

LLM contract-level output:

```json
{
  "contract_summary": "This contract appears to manage deposits and withdrawals.",
  "main_risk_areas": [
    {
      "area": "External calls",
      "based_on_finding_ids": ["FIND-001", "FIND-002"]
    }
  ]
}
```

LLM finding-level output:

```json
{
  "finding_id": "FIND-001",
  "summary": "The function uses a low-level call and does not safely handle the result.",
  "technical_details": "Low-level calls can fail without reverting unless the return value is checked.",
  "exploit_scenario": "A failed transfer may be treated as successful, causing incorrect accounting.",
  "fix_suggestion": "Check the return value or use a safer transfer helper.",
  "false_positive_note": "Risk may be lower if the call target is fully trusted and failures are handled elsewhere."
}
```

Backend validation of LLM output is required:

- Reject any unknown `finding_id`
- Ignore any attempt to change severity, confidence, status, score, evidence, or location
- Ignore any extra finding not present in Slither-normalized findings
- Treat malformed JSON as `LLM_FAILED` and continue with Slither-only report text
- Never store LLM text as analyzer evidence

LLM fallback behavior:

```text
summary = Slither description
technical_details = Slither markdown or description
exploit_scenario = empty string
fix_suggestion = empty string
false_positive_note = empty string
```

Malformed LLM JSON must not fail the full scan. It should become an `LLM_FAILED` warning, and report generation should continue with Slither-only report text.

### Future Rule Engine

The custom Rule Engine is not part of V1. It is a future implementation that will add deterministic project-owned checks alongside Slither.

When added later, it should detect known risky Solidity patterns without relying on the LLM.

Future initial rule set:

- `tx.origin` usage
- `selfdestruct` usage
- `delegatecall` usage
- Inline assembly
- Floating pragma
- Outdated pragma
- Hardcoded address

Future advanced rule set:

- Unprotected admin-like functions
- Unchecked low-level calls
- Unsafe ERC20 transfers
- Missing events
- External call before state update
- Missing reentrancy guard
- Initializer or upgrade function protection issues

## 5. V1 Internal Analyzer Contracts

V1 should keep analyzer data flow explicit:

```text
Slither JSON
-> RawSlitherFinding
-> Normalized Finding
-> LLM report text for existing findings
-> Scored Finding
-> Report
```

### Contract Metadata

The preprocessing step should produce lightweight metadata. This metadata is used by the UI, LLM summary, and report generator.

```json
{
  "filename": "Vault.sol",
  "language": "Solidity",
  "pragma": "^0.8.20",
  "contracts": ["Vault"],
  "functions": ["deposit", "withdraw", "setFee"],
  "imports": ["@openzeppelin/contracts/access/Ownable.sol"],
  "unresolved_imports": [],
  "line_count": 180,
  "source_hash": "sha256:..."
}
```

`imports` should list import statements detected in the submitted source. `unresolved_imports` should be populated when dependency analysis or Slither compilation shows that required files are unavailable.

### Raw Slither Finding

The Slither adapter should convert Slither JSON into a small internal raw model before normalization.

```json
{
  "detector": "unchecked-lowlevel",
  "check": "Unchecked low-level calls",
  "impact": "Medium",
  "confidence": "High",
  "description": "The return value of a low-level call is not checked.",
  "markdown": "...",
  "file": "Contract.sol",
  "contract": "Vault",
  "function": "withdraw",
  "line_start": 42,
  "line_end": 45,
  "evidence": [
    "msg.sender.call{value: amount}(\"\")"
  ],
  "raw": {}
}
```

Rules for the Slither adapter:

- Do not score findings directly
- Do not ask the LLM for interpretation
- Preserve raw detector name and original Slither severity/confidence
- Preserve best-effort location even when Slither output is incomplete
- Return structured errors when JSON is missing, malformed, or unusable

### Normalized Finding Requirements

The normalizer owns all conversion from Slither-specific output to product-level output.

Normalizer responsibilities:

- Convert detector names to categories
- Convert Slither impact to product severity
- Convert Slither confidence to product confidence
- Generate stable finding IDs like `FIND-001`
- Generate a stable internal `finding_fingerprint`
- Normalize locations
- Deduplicate repeated Slither findings
- Keep evidence snippets
- Set `status` to `Detected` for valid Slither findings
- Set `sources` to `["slither"]` before LLM enrichment

## 6. Common Finding Model

All analyzer outputs must be converted into one normalized finding model.

```json
{
  "id": "FIND-001",
  "title": "Unchecked low-level call",
  "category": "Transfer Safety",
  "severity": "High",
  "confidence": "High",
  "status": "Detected",
  "sources": ["slither"],
  "finding_fingerprint": "sha256:...",
  "location": {
    "file": "Contract.sol",
    "contract": "Vault",
    "function": "withdraw",
    "line_start": 42,
    "line_end": 45
  },
  "summary": "",
  "technical_details": "",
  "exploit_scenario": "",
  "fix_suggestion": "",
  "evidence": [
    "msg.sender.call{value: amount}(\"\")"
  ],
  "score": {}
}
```

Allowed statuses:

- `Detected`
- `Potential`
- `Needs Review`
- `Confirmed`

V1 status rule:

- V1 findings use `Detected` for valid Slither results
- `Detected` means Slither detected the issue through static analysis; it does not mean the issue is a guaranteed vulnerability
- `Confirmed` is reserved for future manual review or stronger multi-source validation
- `Potential` and `Needs Review` are reserved for future analyzers or review workflows, not for LLM-created findings
- LLM must never change a finding status

Allowed sources:

- `slither`

V1 source rule:

- `slither` is the only analyzer source for findings
- LLM-generated text is stored in explanation fields, not in `sources`
- `rule_engine` is reserved for a future phase

UI wording:

- Show `Detected by Slither` or `Source: Slither`
- Avoid wording like `confirmed vulnerability` in V1
- Show Slither confidence clearly so users understand false positives are possible

Finding fingerprint:

```text
finding_fingerprint = hash(detector + contract + function + line_start + evidence)
```

Use `FIND-001`, `FIND-002`, and similar IDs for display within a scan. Use `finding_fingerprint` internally for future historical scan comparison, duplicate tracking, regression detection, and reopened findings. Do not expose the fingerprint as the main UI ID in V1 unless useful.

## 7. Deduplication Rules

The same security issue may appear more than once in Slither output, especially when a detector reports related elements in the same function. Users must see one merged finding, not noisy duplicates.

Deduplication key:

```text
vulnerability_type + contract + function + approximate_line_range
```

V1 deduplication behavior:

- Merge findings when detector/category, contract, function, and nearby lines match
- Keep all evidence snippets from merged findings
- Keep Slither as the detection source
- Attach LLM text as explanation, not as separate proof
- Sort final findings by severity, then final score, then source location

Future deduplication behavior:

- When the Rule Engine is added, merge Rule Engine and Slither findings if they describe the same issue
- Increase confidence when independent deterministic sources agree
- Keep source badges visible so users know which analyzer detected the issue

## 8. Risk Scoring

Each finding must receive a numeric final score and mapped severity.

V1 scoring must be deterministic and testable. The backend computes the final score using Slither detector/category/severity mappings. The LLM does not assign exploitability, asset impact, severity, confidence, or final score.

Base severity:

- Critical = 10
- High = 8
- Medium = 5
- Low = 3
- Informational = 1

Confidence:

- High = 0.9
- Medium = 0.6
- Low = 0.3

Exploitability:

- High = 0.9
- Medium = 0.6
- Low = 0.3

Asset impact:

- High = 0.9
- Medium = 0.6
- Low = 0.3
- None = 0.1

Initial deterministic mapping:

```text
Detector/category              Exploitability   Asset Impact
reentrancy-*                   High             High
unchecked-*                    Medium           Medium
tx-origin                      High             High
delegatecall                   High             High
controlled-delegatecall        High             High
timestamp                      Medium           Medium
assembly                       Medium           Medium
solc-version                   Low              Low
unused-*                       Low              None
naming-convention              Low              None
informational/code-quality     Low              None
```

Fallback behavior:

```text
If detector-specific mapping is missing:
- High severity -> exploitability Medium, asset impact High
- Medium severity -> exploitability Medium, asset impact Medium
- Low severity -> exploitability Low, asset impact Low
- Informational -> exploitability Low, asset impact None
```

Final score formula:

```text
final_score =
  (base_severity * 0.45)
  + (confidence * 10 * 0.20)
  + (exploitability * 10 * 0.20)
  + (asset_impact * 10 * 0.15)
```

Final severity mapping:

- 9.0 to 10.0: Critical
- 7.0 to 8.9: High
- 4.0 to 6.9: Medium
- 2.0 to 3.9: Low
- 0.0 to 1.9: Informational

Critical reachability rule (V1):

Slither's highest impact is `High` (base severity 8), so the score formula alone tops out at ~8.55 and the Critical band (9.0+) would never trigger. To make Critical reachable without letting the LLM create severity, the backend applies a deterministic post-score escalation:

- If a finding's detector category is in the Critical-eligible set AND its Slither confidence is `High`, set final severity to `Critical` and clamp final score to `9.0`.
- Critical-eligible detector set (V1): `reentrancy-eth`, `reentrancy-no-eth`, `controlled-delegatecall`, `arbitrary-send-eth`. Tune this set as detector coverage grows.
- This escalation is deterministic, lives entirely in the backend `RiskScorer`, and is independent of the LLM. The LLM still cannot create or change severity.
- If a contract has no detector in the Critical-eligible set, Critical simply does not appear, which is correct.

Overall scan risk:

- Any Critical finding -> Critical
- One or more High findings -> High
- Three or more Medium findings -> Medium
- Only Low/Informational findings -> Low
- No major findings -> No major issues found

## 9. Backend Architecture

Backend stack:

- Rust
- Axum
- Tokio
- SQLx
- PostgreSQL
- Docker sandbox runner
- Slither CLI adapter
- LLM provider adapter

Use a layered architecture:

- API Layer
- Service Layer
- Repository Layer
- Analyzer Layer
- Infrastructure Layer

### API Layer

Responsibilities:

- Receive HTTP requests
- Trigger input validation
- Call services
- Return structured responses

### Service Layer

Responsibilities:

- Create scans
- Update scan status
- Run analyzer pipeline
- Handle recoverable and fatal failures
- Trigger report generation

Suggested services:

- `ScanService`
- `ReportService`
- `ExportService`

### Repository Layer

Responsibilities:

- Store scan records
- Update scan statuses
- Store findings
- Load report data

Suggested repositories:

- `ScanRepository`
- `FindingRepository`
- `ReportRepository`

### Analyzer Layer

Suggested modules:

- `InputProcessor`
- `SolidityPreprocessor`
- `SlitherAdapter`
- `LlmAnalyzer`
- `FindingNormalizer`
- `RiskScorer`
- `ReportGenerator`

### Infrastructure Layer

Suggested modules:

- `DockerRunner`
- `SlitherRunner`
- `LlmClient`
- `TempFileManager`
- `Config`

## 10. Suggested Rust Folder Structure

```text
src/
  main.rs
  app.rs
  api/
    mod.rs
    scan_routes.rs
    report_routes.rs
  services/
    mod.rs
    scan_service.rs
    report_service.rs
  repositories/
    mod.rs
    scan_repository.rs
    finding_repository.rs
  analyzers/
    mod.rs
    input_processor.rs
    solidity_preprocessor.rs
    slither_adapter.rs
    llm_analyzer.rs
    finding_normalizer.rs
    risk_scorer.rs
    report_generator.rs
  infra/
    mod.rs
    config.rs
    docker_runner.rs
    slither_runner.rs
    llm_client.rs
    temp_files.rs
  models/
    mod.rs
    scan.rs
    finding.rs
    report.rs
    dto.rs
  error/
    mod.rs
```

## 11. Scan Job Lifecycle

Scan statuses:

- `awaiting_payment`
- `queued`
- `running`
- `analyzing_slither`
- `analyzing_llm`
- `scoring`
- `report_ready`
- `failed`

> Payment gate: in V1 a scan is created in `awaiting_payment` and does not enter `queued` (and spawns no sandbox) until the backend observes an on-chain payment. See Section 21.

Initial execution model:

1. `POST /api/scans` creates a scan record with status `awaiting_payment` and a snapshotted price
2. Backend returns the `scan_id` plus payment details (contract address, encoded scan id, price)
3. User pays on-chain by calling the payment contract for that `scan_id`
4. The backend `PaymentWatcher` observes the `ScanPaid` event, validates it, and sets status to `queued`
5. Backend starts a background Tokio task
6. Status is updated after each pipeline step
7. Final status becomes `report_ready` or `failed`

V1 limitation:

```text
In V1, scans run as background Tokio tasks inside the API service. If the server restarts while a scan is running, that scan may be lost or marked failed. This is acceptable for MVP. A durable queue and separate worker service are planned for a future version.
```

Future execution model:

```text
API Service -> Queue -> Worker Service -> Analyzer Sandbox
```

## 12. Database Model

Start with three main tables:

### scans

- `id` (UUID v4, primary key, unguessable — never sequential)
- `status`
- `input_type`
- `filename`
- `source_hash`
- `overall_risk`
- `ip_hash` (hashed client IP for rate limiting and abuse tracking; never store raw IP)
- `price_amount` (required payment in wei, snapshotted at scan creation so verification is independent of later config changes)
- `payer_address` (nullable; set when payment is observed)
- `payment_tx_hash` (nullable; set when payment is observed)
- `paid_at` (nullable; set when status leaves `awaiting_payment`)
- `started_at` (set when status leaves `queued`)
- `finished_at` (set on `report_ready` or `failed`)
- `duration_ms` (derived: `finished_at - started_at`; stored for fast querying/log correlation)
- `created_at`
- `updated_at`
- `error_message`

> Note: `scan_id` exposed in URLs and APIs is the UUID v4 `id`. Earlier examples use `scan_123` for readability only; real IDs must be UUIDs so reports cannot be enumerated.

### findings

- `id`
- `scan_id`
- `title`
- `category`
- `severity`
- `confidence`
- `status`
- `sources`
- `finding_fingerprint`
- `contract_name`
- `function_name`
- `line_start`
- `line_end`
- `summary`
- `technical_details`
- `exploit_scenario`
- `fix_suggestion`
- `evidence`
- `score`
- `created_at`

### reports

- `id`
- `scan_id`
- `json_report`
- `markdown_report`
- `created_at`

## 13. API Contract

### Start Scan

```http
POST /api/scans
```

Request:

```json
{
  "input_type": "pasted_code",
  "filename": "Vault.sol",
  "source_code": "pragma solidity ^0.8.20; contract Vault { ... }"
}
```

Uploaded files use the same JSON shape. In V1, the frontend reads the uploaded `.sol` file content client-side and sends it as `source_code`. No separate multipart upload endpoint is required.

```json
{
  "input_type": "uploaded_file",
  "filename": "Vault.sol",
  "source_code": "pragma solidity ^0.8.20; contract Vault { ... }"
}
```

Response:

```json
{
  "scan_id": "scan_123",
  "status": "queued",
  "message": "Scan created successfully."
}
```

### Get Scan Status

```http
GET /api/scans/{scan_id}
```

Response:

```json
{
  "scan_id": "scan_123",
  "status": "analyzing_slither",
  "current_step": "Running Slither static analysis",
  "progress": 45,
  "created_at": "2026-06-22T16:00:00Z",
  "updated_at": "2026-06-22T16:00:12Z",
  "warnings": []
}
```

Dependency/import failure status response example:

```json
{
  "scan_id": "scan_123",
  "status": "failed",
  "current_step": "Running Slither static analysis",
  "progress": 100,
  "created_at": "2026-06-22T16:00:00Z",
  "updated_at": "2026-06-22T16:00:12Z",
  "warnings": [],
  "error": {
    "code": "UNRESOLVED_IMPORTS",
    "message": "Slither could not compile this contract because one or more imports are missing. For best results, upload a flattened Solidity file.",
    "details": {
      "imports": ["@openzeppelin/contracts/access/Ownable.sol"]
    }
  }
}
```

### Get UI Report

```http
GET /api/scans/{scan_id}/report
```

Response:

```json
{
  "scan_id": "scan_123",
  "status": "report_ready",
  "summary": {
    "overall_risk": "High",
    "total_findings": 7,
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "informational": 1
  },
  "contract_metadata": {
    "filename": "Vault.sol",
    "language": "Solidity",
    "pragma": "^0.8.20",
    "contracts": ["Vault"],
    "functions": ["deposit", "withdraw", "setFee"],
    "imports": [],
    "unresolved_imports": []
  },
  "main_risk_areas": [
    {
      "area": "External calls",
      "based_on_finding_ids": ["FIND-001", "FIND-002"]
    },
    {
      "area": "Access control",
      "based_on_finding_ids": ["FIND-003"]
    }
  ],
  "findings": []
}
```

### Export JSON

```http
GET /api/scans/{scan_id}/export/json
```

Returns the full machine-readable report.

### Export Markdown

```http
GET /api/scans/{scan_id}/export/markdown
```

Suggested response:

```json
{
  "filename": "smart-contract-security-report.md",
  "content": "# Smart Contract Security Report\n\n## Summary\n..."
}
```

Markdown report template (V1):

The Report Owner must produce a consistent document. Findings are ordered the same way as the UI: by severity (Critical → Informational), then final score, then source location. Structure:

```markdown
# Smart Contract Security Report

## Summary
- Overall risk: <overall_risk>
- Total findings: <n>
- Critical: <n> · High: <n> · Medium: <n> · Low: <n> · Informational: <n>
- File: <filename>  ·  Pragma: <pragma>  ·  Scanned: <timestamp>

## Contract Metadata
- Contracts: <list>
- Functions: <list>
- Imports: <list>
- Unresolved imports: <list>

## Main Risk Areas
- <area> (based on <finding ids>)

## Findings

### [<SEVERITY>] FIND-001 — <title>
- Category: <category>
- Severity: <severity>  ·  Confidence: <confidence>  ·  Status: Detected
- Source: Detected by Slither
- Location: <contract>.<function> (lines <start>–<end>)

**Summary**
<summary>

**Technical details**
<technical_details>

**Exploit scenario**
<exploit_scenario>

**Fix suggestion**
<fix_suggestion>

**False-positive note**
<false_positive_note>   <!-- omit this block if empty -->

**Evidence**
```solidity
<evidence snippet(s)>
```

**Score breakdown**
- Base severity / confidence / exploitability / asset impact / final score

---

<repeat per finding>

## Notes
- This report is based on Slither static analysis. Detected findings are not guaranteed vulnerabilities; review confidence and false-positive notes.
- <LLM warning text, if the scan had LLM_FAILED>
```

Empty fields (e.g. from LLM fallback) should be rendered as a short placeholder like `_Not available._` rather than left blank, except the false-positive block which is omitted entirely when empty.

### Error Format

All API errors must use the same shape:

```json
{
  "error": {
    "code": "INVALID_SOLIDITY_INPUT",
    "message": "Input does not look like a valid Solidity contract.",
    "details": {
      "filename": "Vault.txt"
    }
  }
}
```

Suggested error codes:

- `INVALID_INPUT`
- `INVALID_SOLIDITY_INPUT`
- `FILE_TOO_LARGE`
- `EMPTY_INPUT`
- `UNSUPPORTED_FILE_TYPE`
- `DEPENDENCY_MISSING`
- `UNRESOLVED_IMPORTS`
- `SCAN_NOT_FOUND`
- `SCAN_NOT_READY`
- `SLITHER_FAILED`
- `SLITHER_COMPILATION_FAILED`
- `LLM_FAILED`
- `REPORT_GENERATION_FAILED`
- `INTERNAL_ERROR`
- `RATE_LIMITED`
- `TOO_MANY_CONCURRENT_SCANS`
- `PAYMENT_NOT_RECEIVED`
- `PAYMENT_UNDERPAID`
- `PAYMENT_VERIFICATION_FAILED`

### Input Validation Rules

Validation runs before any scan job starts. The goal is to reject obviously invalid input cheaply while NOT rejecting valid Solidity through overly strict keyword matching. Final authority on compilability is Slither, not the validator.

Hard rejects (return error immediately):

- Empty or whitespace-only input -> `EMPTY_INPUT`
- File larger than 1 MB -> `FILE_TOO_LARGE`
- More than 5000 lines -> `FILE_TOO_LARGE`
- Uploaded filename does not end in `.sol` -> `UNSUPPORTED_FILE_TYPE`

Soft Solidity heuristic (lenient, `INVALID_SOLIDITY_INPUT` only if it clearly is not Solidity):

- Accept if the source contains at least one of: `pragma solidity`, `contract `, `library `, `interface `, or `abstract contract`. This intentionally allows interfaces and libraries that may legitimately omit a pragma.
- Do NOT require a `contract` keyword specifically, and do NOT enforce a Solidity version range in the validator. Version/compilation concerns are handled by Slither, which reports `SLITHER_COMPILATION_FAILED` or `UNRESOLVED_IMPORTS` if needed.
- This heuristic only catches "user pasted plain text / wrong file"; anything plausibly Solidity passes through to Slither.

Supported version range: whatever the Slither/solc toolchain in the Docker image supports. The validator does not gate on version; the sandbox image's installed solc selector (e.g. solc-select) determines real support.

## 14. Frontend Blueprint

Frontend pages:

- `/scans/new`
- `/scans/{scan_id}`
- `/scans/{scan_id}/report`

Main user flow:

1. User pastes Solidity code or uploads one `.sol` file
2. Frontend validates basic input and reads uploaded `.sol` file content client-side
3. Frontend calls `POST /api/scans`
4. Frontend polls `GET /api/scans/{scan_id}`
5. Frontend loads `GET /api/scans/{scan_id}/report`
6. User can export JSON or Markdown

Polling strategy (V1):

- Poll interval: 2 seconds while status is `queued`, `running`, `analyzing_slither`, `analyzing_llm`, or `scoring`.
- Stop polling on `report_ready` (load report) or `failed` (show error).
- Client-side timeout: stop after ~3 minutes of polling and show a "Scan is taking longer than expected" message with a manual retry/refresh action. This ceiling sits above the Slither timeout (30–60s) plus LLM time, so a healthy scan always finishes first.
- On transient network errors during polling, retry with simple backoff (e.g. 2s, 4s, 8s) up to a few times before showing a connection error; do not fail the scan itself, only the polling UI.
- Live progress via WebSocket/SSE is a Future item; V1 polling is sufficient for MVP.

Input guidance:

- V1 works best with single-file or flattened Solidity contracts
- External imports are shown in metadata, but missing dependencies are not resolved automatically
- If Slither cannot compile because imports are missing, show the backend error and tell the user to upload a flattened Solidity file

Report UI must show:

- Overall risk badge
- Finding count summary
- Severity distribution
- Contract metadata
- Main risk areas
- Finding cards
- Finding detail view
- Source badges
- JSON export action
- Markdown export action

Finding cards must show:

- Title
- Severity
- Confidence
- Detection status
- Source, shown as `Detected by Slither` or `Source: Slither`
- Contract/function/line
- Short summary

Finding detail must show:

- Summary
- Technical details
- Exploit scenario
- Fix suggestion
- False-positive note (shown when present; helps users judge Slither false positives)
- Evidence
- Source list
- Score breakdown

UI principles:

- Technical but readable
- Finding-focused
- No unnecessary text clutter
- Clear severity colors
- Visible source badges
- Useful for both developers and technical founders

## 15. Sandbox And Security Rules

User-submitted code must never run directly on the host system.

V1 is static analysis only:

- Do not deploy contracts
- Do not simulate transactions
- Do not run on a testnet
- Do not run on a local chain

Slither must run in Docker with:

- Network disabled
- CPU limit
- RAM limit
- Timeout
- Temporary filesystem
- Scan folder mounted only as needed
- Container removed after scan

The temporary scan folder may be mounted read-write in V1 so Slither can write `/scan/slither-output.json`. The folder must be deleted after scan completion. Future hardening can split input and output mounts so source input is read-only and analyzer output is written to a separate writable mount.

Initial limits:

- Max file size: 1 MB
- Max lines: 5000
- Slither timeout: 30 to 60 seconds
- Container memory: 512 MB to 1 GB
- CPU limit: 1 core
- Network: disabled

Abuse prevention limits (V1):

Because every scan spawns a resource-heavy sandbox, missing limits are a denial-of-service and cost risk, not just a fairness issue. V1 ships a simple, in-process guard (no extra infrastructure):

- Per-IP rate limit: e.g. 5 scans per hour, keyed on `ip_hash`. On exceed, return `RATE_LIMITED` with a clear message and (optionally) a `Retry-After` hint.
- Max concurrent scans (global): cap the number of simultaneously running sandbox tasks (e.g. a semaphore sized to available CPU/RAM). When full, either queue briefly or reject new scans with `TOO_MANY_CONCURRENT_SCANS`.
- Optional per-IP concurrent cap (e.g. 1 running scan per IP) to stop a single client from filling all slots.
- Idempotency: dedupe accidental double-submits by short-circuiting if the same `ip_hash` + `source_hash` produced a scan within a small recent window; return the existing `scan_id` instead of starting a second identical scan.
- V1 keeps this state in-process (in-memory counters/semaphore). A shared store (e.g. Redis) for multi-instance rate limiting is a Future item.

Temporary files:

```text
/tmp/scans/{scan_id}/Contract.sol
/tmp/scans/{scan_id}/slither-output.json
```

Container command example:

```bash
slither /scan/Contract.sol --json /scan/slither-output.json
```

After scan completion:

- Delete temporary Solidity file
- Parse and store Slither output in DB
- Remove container
- Clean temporary folder

Orphan cleanup (V1):

Containers and `/tmp/scans/{scan_id}` folders can leak if a scan crashes, times out at the wrong moment, or the server restarts mid-scan (see Section 11). To avoid disk and leftover-source buildup, run a lightweight reaper:

- On startup and then periodically (e.g. every few minutes), remove any scan containers and `/tmp/scans/*` folders older than a safe threshold (e.g. 2× the Slither timeout) that have no active scan task.
- Always run cleanup in a way that triggers even on scan failure (e.g. a guard/`Drop` on the temp-folder handle, or a `finally`-style block), not only on the success path.
- The reaper is deliberately simple (filesystem age + container label check), not a full job system. A durable queue/worker is a Future item.

Logging rules:

Allowed logs:

- `scan_id`
- `status`
- `duration`
- `error_code`
- `analyzer_step`
- `source_hash`

Do not log:

- Full Solidity source code
- Private business logic
- Secrets or private-key-like values

## 16. Failure Policy

Failure behavior must be consistent:

- Fatal Slither failure -> scan failed in V1 because there is no other detection source
- Dependency/import failure -> scan failed with user guidance to upload a flattened Solidity file
- Partial Slither output -> scan may continue only if Slither returns usable JSON findings
- LLM failure (including oversized source the LLM cannot handle) -> warning, scan continues with Slither-only report text
- Report generation failure -> scan failed
- Rate limit / concurrency limit hit -> request rejected before a scan record runs, with `RATE_LIMITED` or `TOO_MANY_CONCURRENT_SCANS`; this is not a scan failure, just a rejected request

Fatal Slither failure:

- Slither could not run
- Docker failed
- Slither timed out
- Slither produced no usable JSON
- Solidity could not be compiled at all

Result:

- Scan status becomes `failed`
- Error code should be specific, such as `SLITHER_FAILED` or `SLITHER_COMPILATION_FAILED`

Dependency/import failure:

- Source has unresolved imports
- Required dependencies are unavailable
- Single-file scan cannot compile because external files are missing

Result:

- Scan status becomes `failed`
- Error code should be `UNRESOLVED_IMPORTS` or `DEPENDENCY_MISSING`
- Error message should tell the user to upload a flattened Solidity file

Partial Slither output:

- Use only if Slither returns usable JSON findings despite warnings or partial issues
- Continue report generation
- Add warnings to the scan/report response
- Do not invent findings to fill missing analysis

Warnings should be returned through the status/report APIs and shown in the UI.

Example warning:

```text
LLM explanations could not be completed. Slither findings are still available.
```

## 17. Team Work Boundaries

To let different people build parts separately, use these ownership boundaries.

### Backend Core Owner

Owns:

- Axum setup
- App state
- Routing
- Scan lifecycle
- Background task execution
- Error format

Must not change analyzer output models without coordinating with Analyzer and Frontend owners.

### Database Owner

Owns:

- PostgreSQL schema
- SQLx migrations
- Repository implementations
- JSON storage for reports and scores

Must preserve the common finding model fields.

### Slither Owner

Owns:

- Docker sandbox execution
- Slither command runner
- Timeout and resource limits
- Slither JSON parsing
- Slither-to-category mapping

Must return structured errors when Slither cannot produce usable JSON output. In V1, this makes the scan fail because Slither is the only detection source.

### LLM Owner

Owns:

- Prompt templates
- LLM provider adapter
- Contract-level review
- Finding-level explanations
- JSON-only response parsing

Must enforce the rule that the LLM cannot create findings. LLM output may only fill report text for existing Slither finding IDs and contract summary fields.

### Normalizer And Scoring Owner

Owns:

- Common finding model
- Slither finding normalization
- Duplicate merging
- Deduplication
- Final score calculation
- Overall risk calculation

Must keep scoring deterministic and testable.

### Report Owner

Owns:

- UI report response
- JSON export
- Markdown export

Must use normalized findings only.

### Frontend Owner

Owns:

- New scan page
- Scan progress page
- Report page
- Finding list and detail views
- Export actions

Must consume the API contract instead of inventing separate frontend-only models.

## 18. Development Order

Recommended backend-first order:

1. Rust backend project setup
2. Axum API skeleton (health endpoint + shared error format from Section 13)
3. PostgreSQL + SQLx setup
4. Scan database model — write the **full schema in the first migration**: UUID v4 `id`, `ip_hash`, timing columns (`started_at`/`finished_at`/`duration_ms`), and the payment columns (`price_amount`, `payer_address`, `payment_tx_hash`, `paid_at`), plus the `chain_watcher_state` table (Section 21). Cheap now, painful to retrofit.
5. `POST /api/scans` — create the scan in `awaiting_payment`, snapshot `price_amount`, return the payment block (Section 21)
6. `GET /api/scans/{scan_id}`
7. Basic scan job lifecycle (transitions from `queued` onward), behind a **dev payment-bypass flag** (e.g. `PAYMENT_BYPASS=true`) so the full pipeline can be driven locally without on-chain payment
8. Input validation (Section 13 rules)
9. Solidity preprocessing
10. Slither Docker integration
11. Slither command execution
12. Slither JSON parsing
13. Finding model
14. Slither output normalization
15. Deduplication
16. Risk scoring (including Critical escalation rule)
17. LLM source size policy + contract summary
18. LLM finding explanations
19. JSON report generation
20. Markdown report generation (Section 13 template)
21. Full report endpoint
22. Payment gate — deploy the `ScanPayments` contract, build the `PaymentWatcher` (event subscription + restart-safe backfill), wire `awaiting_payment -> queued`, then disable the dev bypass (Section 21)
23. Rate limiting + concurrency guard + idempotency (idempotency returns the existing `awaiting_payment` scan and its payment block)
24. Orphan container/temp reaper
25. Frontend integration (with polling strategy)
26. Sandbox hardening
27. Roadmap features

> Schema-first: everything in step 4 (UUID ids, `ip_hash`, timing columns, payment columns, `chain_watcher_state`) belongs in the first migration, not retrofitted later.

> Pure modules build in isolation: the `RiskScorer` (Section 8), `FindingNormalizer`, and deduplication (Section 7) are deterministic and have no Slither/LLM/Docker dependencies. Build and unit-test them early — even in parallel with the sandbox plumbing — against fixture Slither JSON.

> Dev payment-bypass: the flag from step 7 lets you build steps 8–21 without paying 10 MON per run on testnet; step 22 turns it off. Gate it so it can never be enabled in production config, and never ship with it on.

## 19. Deferred Decisions (Conscious Future Items)

These were evaluated and intentionally left out of V1 to keep the MVP shippable on a tight timeline. They are deferred decisions, not oversights.

- **Authentication & per-user authorization.** V1 uses unguessable UUID v4 `scan_id` as capability-style access (link holder can view). No login, no ownership model. Add real auth when multi-user or private-workspace needs arrive.
- **Durable job queue + separate worker service.** V1 runs scans as in-process Tokio tasks; a server restart can lose an in-flight scan (acceptable for MVP, see Section 11). Move to API → queue → worker when reliability/scale matter.
- **Distributed rate limiting.** V1 rate limit and concurrency state is in-process. Multi-instance deployments need a shared store (e.g. Redis).
- **Automatic data retention/cleanup of stored reports.** V1 keeps reports in the DB indefinitely; the orphan reaper only handles temp files/containers, not stored report rows. A retention policy/TTL job is future. (Note: raw source code is already not logged per Section 15; stored reports still contain evidence snippets, so retention matters for privacy.)
- **Live progress (WebSocket/SSE).** V1 uses polling (Section 14).
- **Multi-provider LLM fallback.** V1 has one provider via `LlmClient`; on failure it degrades to Slither-only text (`LLM_FAILED`), it does not switch providers.

## 20. Future Roadmap

After the V1 core is stable, possible roadmap items are:

- GitHub repository scan
- Multi-file project analysis
- Contract address scan
- Explorer source code fetch
- Foundry/Hardhat project support
- Dynamic testing
- Fuzzing
- CI/CD integration
- Team dashboard
- Historical scan comparison
- PDF report
- Custom deterministic Rule Engine

## 21. Payment & Billing (V1)

### Overview

V1 gates each scan behind an on-chain payment on **Monad testnet**. Because testnet MON has no real value, payment serves two purposes: (a) demonstrating the crypto-payment flow end to end, and (b) acting as an extra anti-spam gate layered on top of the Section 15 rate limits. The flow is designed so a flat testnet price can later become tiered or mainnet pricing without changing the lifecycle.

Pricing model:

- **Fixed price per scan: 10 MON.** The price is hardcoded as an immutable constant in the contract for the MVP — there is no on-chain fee admin and no `setPrice`. Changing the price means deploying a new contract.
- **File length does NOT change the price in V1.** Input is already capped at 1 MB / 5000 lines (Section 15) and Slither cost is bounded by its timeout, so there is no variable cost to recover with a free testnet token.
- Tiered-by-line-count pricing and mainnet/stablecoin pricing are Future items.

### Agreed Integration Decision

- **The backend watches contract events.** The scan starts when the backend observes the payment event on-chain.
- The frontend only initiates the wallet payment; it does **not** submit transaction hashes for verification. It continues to poll scan status (Section 14) and sees the status flip from `awaiting_payment` to `queued` automatically once the backend confirms payment.

### Payment Contract

Deployed once on Monad testnet; its address is backend config `PAYMENT_CONTRACT_ADDRESS`.

```solidity
// Uses OpenZeppelin Ownable2Step for safe (two-step) ownership transfer.
// Price is immutable: no setPrice, no fee admin. MON is the 18-decimal native
// token (verified: chain ID 10143), so 10 MON == 10 * 10**18 wei. Written out
// explicitly rather than as the `ether` keyword to avoid implying ETH.
contract ScanPayments is Ownable2Step {
    uint256 public constant PRICE = 10 * (10 ** 18); // 10 MON, fixed for the MVP
    mapping(bytes32 => bool) public paid;

    event ScanPaid(bytes32 indexed scanId, address indexed payer, uint256 amount);

    function pay(bytes32 scanId) external payable {
        require(msg.value >= PRICE, "underpaid");
        require(!paid[scanId], "already paid");
        paid[scanId] = true;
        emit ScanPaid(scanId, msg.sender, msg.value);
    }

    function withdraw(address payable to) external onlyOwner {
        // recipient is the owner's own EOA; checks-effects-interactions still applies
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "withdraw failed");
    }
}
```

- **`scanId` encoding:** the scan `id` is a UUID v4 (16 bytes). It is encoded as `bytes32` by left-padding the 16-byte UUID with zeros (decode by taking the low 16 bytes). The backend and the frontend/contract must use the same encoding so an emitted `ScanPaid.scanId` matches the DB row.
- **Replay safety:** `paid[scanId] = true` makes one payment unlock exactly one scan; a second `pay()` for the same `scanId` reverts. The backend never has to track used tx hashes for correctness — it can also read `paid[scanId]` directly.

### Admin / Ownership Model

There is **no fee admin**: the price is an immutable constant, so no one can change it on-chain. The only privileged action is `withdraw`, and the owner cannot touch scans, user source, or anything else. The contract should pass our own scanner (no unprotected functions, no `suicidal`/missing-access-control findings).

V1 (testnet):

- `owner` = a **dedicated deployer wallet**, separate from any personal main wallet. Not a multisig — overkill for a worthless-token demo.
- Blast radius of a compromised owner key is tiny: withdraw worthless testnet funds. It cannot change the price, affect scans, or touch user contracts.
- `Ownable2Step` is used so ownership can't be bricked by transferring to a wrong address.

Future (mainnet):

- Move `owner` to a Gnosis Safe multisig.
- If pricing ever needs to change without redeploying, reintroduce a bounded, access-controlled `setPrice` (with a `MAX_PRICE` cap) — deliberately left out of V1.

### `PaymentWatcher` (Infrastructure module, backend-owned)

Add `PaymentWatcher` to the Infrastructure Layer (Section 9). Responsibilities:

1. Subscribe to `ScanPaid` logs for `PAYMENT_CONTRACT_ADDRESS` via Monad RPC (`eth_subscribe` over WebSocket; fall back to polling `eth_getLogs` every few seconds if WS is unavailable).
2. On each `ScanPaid(scanId, payer, amount)`:
   - Decode `scanId` -> UUID and load the scan.
   - Ignore if the scan is missing or not in `awaiting_payment` (idempotent — duplicates/reorgs are no-ops).
   - Verify `amount >= scan.price_amount`.
   - Wait for `PAYMENT_CONFIRMATIONS` confirmations (V1 testnet: 1–2).
   - Record `payer_address`, `payment_tx_hash`, `paid_at`; set status to `queued`; spawn the existing pipeline Tokio task. From `queued` onward, Section 11 is unchanged.
3. **Restart-safe backfill (critical):** persist `last_processed_block`. On startup, replay `eth_getLogs` from `last_processed_block` to head so any payment that landed while the backend was down still starts its scan. Because the entire start trigger is event-driven, a silently missed event would otherwise leave a scan stuck in `awaiting_payment` forever.
4. **Idempotency:** dedupe by `(scanId, tx_hash)`; on-chain `paid[scanId]` plus the DB status check both guard against double-starting a scan across reorgs/restarts.

### Expiry

- Scans left in `awaiting_payment` beyond `PAYMENT_WINDOW_SECS` (e.g. 1800) move to `failed` with `PAYMENT_NOT_RECEIVED`. No sandbox was created, so cleanup is cheap. The Section 15 reaper can sweep their temp state if any.

### DB Additions

`scans` table (already listed in Section 12): `price_amount`, `payer_address`, `payment_tx_hash`, `paid_at`.

Plus a small watcher-state table:

```text
chain_watcher_state
- id (single row)
- last_processed_block
- updated_at
```

### API Additions

`POST /api/scans` response now returns `awaiting_payment` plus a payment block:

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "awaiting_payment",
  "message": "Scan created. Complete payment to start analysis.",
  "payment": {
    "contract_address": "0x...",
    "chain_id": 10143,
    "scan_id_bytes32": "0x00000000000000000000000000000000550e8400e29b41d4a716446655440000",
    "price_wei": "10000000000000000000",
    "expires_at": "2026-06-27T16:30:00Z"
  }
}
```

`GET /api/scans/{scan_id}` while in `awaiting_payment` returns the same payment block so the frontend can render pay instructions and a countdown.

Optional `POST /api/scans/{scan_id}/payment/refresh`: forces an `eth_getLogs` re-check for that `scanId` (a manual nudge if the user believes they paid but the watcher has not caught up yet). Optional in V1.

New error codes (added to Section 13):

- `PAYMENT_NOT_RECEIVED` — payment window elapsed without a valid payment.
- `PAYMENT_UNDERPAID` — defensive; the contract already rejects underpayment.
- `PAYMENT_VERIFICATION_FAILED` — RPC/chain error during verification.

### Config Additions

- `PAYMENT_CONTRACT_ADDRESS`
- `MONAD_RPC_WS_URL` and/or `MONAD_RPC_HTTP_URL`
- `CHAIN_ID`
- `SCAN_PRICE_WEI` — must equal the contract's immutable `PRICE` (10 MON = `10000000000000000000`). Used by the backend to snapshot `price_amount` and verify `amount >= price`.
- `PAYMENT_CONFIRMATIONS` (1–2 on testnet)
- `PAYMENT_WINDOW_SECS` (e.g. 1800)

### Interaction With Abuse Prevention (Section 15)

- Rate limit and idempotency still apply at `POST /api/scans`, **before** payment. Payment is an additional gate, not a replacement for rate limiting.
- The Section 15 idempotency dedupe (`ip_hash` + `source_hash` within a recent window) must return the existing `awaiting_payment` `scan_id` **and its payment block**, so an accidental double-submit never causes the user to pay twice.

### Seam Ownership

- **Backend owner:** `PaymentWatcher`, payment verification, the `awaiting_payment -> queued` lifecycle flip, payment config, and the DB columns.
- **Smart-contract owner:** the `ScanPayments` contract (`pay`/`paid`/`ScanPaid`/owner functions), its deployment and address, and the shared `scanId` <-> `bytes32` encoding.
- **Shared contract between the two halves:** the `ScanPaid(bytes32 scanId, address payer, uint256 amount)` event signature and the `scanId` encoding. Neither side changes these without the other.

### Future

- Tiered/by-line-count pricing; mainnet + stablecoin pricing.
- **Refund/credit on post-payment failure.** In V1, a scan that is paid and then fails in the pipeline (e.g. `SLITHER_FAILED`) is **not** auto-refunded; this must be stated to users. Refund or credit logic is a Future item.
