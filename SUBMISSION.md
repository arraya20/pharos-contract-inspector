# Pharos Agent Center — Skill Submission Package

Salin ISI BLOK di bawah ini ke Discord #skill-submission (sebagai SATU pesan,
sesuai aturan kampanye). Ganti `<EMAIL>` dengan email lo dulu.

---

**Skill Name:** Pharos Contract Inspector

**Description:** ABI-free EVM contract introspection for Pharos. Point it at any
address and get proxy detection (EIP-1167 / 1967 / OZ legacy / getter), bytecode
function selector extraction, ERC-165 interface probing, standard fingerprinting
(ERC-20/721/1155/Ownable/AccessControl/Pausable/UUPS/2612), live metadata reads
(name/symbol/decimals/totalSupply/owner), privileged-function flagging
(mint/pause/upgrade/transferOwnership/role/changeAdmin), value-moving signature
flagging (approve/permit/transferFrom/setApprovalForAll), and a deterministic
Low/Medium/High risk summary with evidence. Works on unverified contracts with
no source, no explorer API, no ABI — pure JSON-RPC bytecode analysis. Sits
above Agent Center's `readContract` / `sendTransaction` primitives and answers
the two questions a developer actually has before interacting:
"what can I even call?" and "should I trust this?"

**GitHub:** https://github.com/arraya20/pharos-contract-inspector

**Release:** v1.1.0 — https://github.com/arraya20/pharos-contract-inspector/releases/tag/v1.1.0

**Email:** <EMAIL>

**Supported Frameworks:** OpenClaw (`~/.openclaw/skills/`), Claude Code
(`~/.claude/skills/`), Codex (`~/.codex/skills/`). Skill is defined in `SKILL.md`
at the repo root and loads under any of these frameworks. Also runnable as a
standalone CLI (`node inspect.js`) and as a dependency-free HTTP API
(`npm run serve` → `POST /inspect`) for non-skill agents.

**How to use:**
```
git clone https://github.com/arraya20/pharos-contract-inspector.git
cd pharos-contract-inspector

# CLI — Pharos USDC on Atlantic Testnet
node inspect.js 0xcfC8330f4BCAB529c625D12781b1C19466A9Fc8B --network testnet

# CLI — Permit2 on Pacific Mainnet (4byte.directory resolution online)
node inspect.js 0x000000000022D473030F116dDEE9F6B43aC78BA3 --network mainnet

# JSON output for programmatic use
node inspect.js 0xcA11bde05977b3631167028862bE2a173976CA11 --json

# HTTP API
npm run serve
curl -X POST http://127.0.0.1:8790/inspect \
  -H 'Content-Type: application/json' \
  --data '{"address":"0xcfC8330f4BCAB529c625D12781b1C19466A9Fc8B","network":"testnet"}'
```

**Demo:** README in repo includes example output against Pharos USDC testnet.
The HTTP API lets agents inspect any address in one POST call.

**Notes / Dependencies:**
- Node.js ≥ 18 (uses native `fetch`, `AbortController`).
- ZERO runtime npm dependencies.
- Networks supported: Pharos Atlantic Testnet (chainId 688689) and Pharos
  Pacific Mainnet (chainId 1672), configurable via `networks.json` or
  `--rpc <URL>`.
- 4byte.directory lookup is optional and degrades gracefully when offline
  (`--offline` flag).
- HTTP API rejects custom RPC URLs by default (SSRF safe); opt in for trusted
  local deployments via `ALLOW_CUSTOM_RPC=1`.
- v1.1.0 added an RPC retry layer that distinguishes transient failures
  (timeout/5xx/429, retried with backoff) from permanent ones (revert/4xx,
  fail fast), so the risk score stays deterministic on flaky public RPCs.
- Full unit coverage (6 test files, no network): `npm test`.
- License: MIT-0 (no attribution required).

---

## Pre-submit checklist

- [ ] `<EMAIL>` di atas sudah diganti dengan email aktif
- [ ] Repo masih public dan tag v1.1.0 visible di Releases
- [ ] `npm test` masih hijau dari clean clone (sanity)
- [ ] Discord #skill-submission udah ke-join
- [ ] Pesan dikirim sebagai SATU message (campaign rule), bukan multi-message
