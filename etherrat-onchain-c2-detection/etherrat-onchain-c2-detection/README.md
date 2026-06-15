# EtherRAT On-Chain C2 — DPRK/Iran Shared-Builder Resolver Family

### Novel on-chain enumeration of an EtherRAT/Tsundere EtherHiding resolver family, with wire-level C2 confirmation

**Classification:** TLP:CLEAR · **Analytic standard:** ICD-203 · **As of:** 15 June 2026
**Author:** Yanky Wilson — independent CTI researcher ([github.com/yankywilson](https://github.com/yankywilson))
**Reporting window:** Dec 2025 – Jun 2026 · **Methodology:** passive OSINT, on-chain-first

> **Method & sourcing.** Findings are tagged **NOVEL** (first-published here; absent from external reporting), **CORROBORATED** (independently confirmed in this investigation across ≥2 sources), **PUBLISHED** (already in vendor reporting; reproduced for completeness), or **EXCLUDED** (investigated and ruled out — logged as a finding, not an omission). Confidence follows ICD-203; estimative likelihood uses the standard lexicon (*likely* = 55–80%, *highly likely* = 80–95%). Single-vendor attribution is capped at MODERATE. This work is strictly passive and air-gapped: read-only blockchain explorers and third-party scan data only — **no contact with live C2 infrastructure**.

---

## BLUF

On-chain enumeration of the EtherRAT EtherHiding C2 resolver family surfaced a **fourth resolver contract not present in any public reporting** (`0x40A7d723F5Df6c88464bC95DBf7D96573fBc4f85`), bytecode-identical to the contracts named by Sysdig and eSentire and bound to the same `StringChanged` event-topic anchor that also binds the Iranian MuddyWater/Tsundere resolver family. Decoding the family's `setString` calldata yielded **multiple previously-unpublished C2 hosts**, one of which — `91.215.85.42` — was confirmed as a **live EtherRAT C2 panel** by three independent methods: the on-chain write, a Shodan banner carrying the EtherRAT `X-Bot-Server` header, and a behavioral PCAP showing a victim beaconing to it. The DPRK and Iranian resolver families share an **identical contract builder/codebase** (HIGH confidence) but **do not share operator or financier wallets** (funding traces walked to terminus at the no-KYC exchange SideShift). The investigation's novelty is the **resolver-family enumeration** and the **on-chain code-level link between the DPRK and Iranian clusters** — not the discovery of EtherHiding itself, which Google/Mandiant (GTIG) and Sysdig have already documented.

---

## What's new (this assessment vs. public reporting)

| # | Finding | Status vs. public reporting |
|---|---|---|
| 1 | Resolver contract `0x40A7d723…fBc4f85` | **NOVEL** — in no vendor report; surfaced via funding-graph pivot |
| 2 | DPRK EtherRAT ↔ Iran Tsundere resolvers are **bytecode-identical + share event-topic `0x3ca6280d…`** | **NOVEL** (on-chain, code-level) — eSentire reported *code overlap*; this confirms it on-chain |
| 3 | C2 `91.215.85.42` = **live EtherRAT panel** (on-chain + `X-Bot-Server` + PCAP) | **NOVEL** — unpublished; triple-corroborated |
| 4 | C2 `api-gateway-prod.com` → `193.200.17.66` w/ cert-bounded campaign window | **NOVEL** — unpublished |
| 5 | Six further novel C2 domains/IP from contract #1 calldata | **NOVEL** |
| 6 | EtherRAT (`:3000`) + Tsundere (`:3001`) **co-hosted on one server** | **NOVEL** (observed) — infrastructure-level analogue of the code overlap |
| 7 | No shared DPRK↔Iran financier; DPRK peels to **SideShift** | **EXCLUDED / null** — financier link ruled out, walked to terminus |
| 8 | `173.249.8.102` decoded but hosts an **unrelated Moroccan spam kit** | **EXCLUDED** — decoy or recycled co-tenant IP |

---

## 1. Key Judgments

**KJ-1 — HIGH CONFIDENCE.** The EtherRAT C2 resolver family on Ethereum mainnet comprises **at least four smart contracts** (three published, one — `0x40A7d723…` — first published here), all compiled from a **single source**: byte-for-byte-identical runtime bytecode, identical function selectors (`0x7d434425` read / `0x7fcaf666` write), identical Solidity compiler-metadata IPFS hash (`1de57633…`), and the shared `StringChanged` event topic `0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47`.

**KJ-2 — HIGH CONFIDENCE.** The DPRK-attributed EtherRAT resolver family and the Iranian (MuddyWater/Tsundere) resolver family **share a common builder/codebase at the bytecode and event-signature level.** This independently corroborates, on-chain, eSentire's reported source-code overlap between EtherRAT and Tsundere, and is consistent with a shared Malware-as-a-Service kit or builder rather than independent re-implementation.

**KJ-3 — HIGH CONFIDENCE.** `91.215.85.42` is a **live EtherRAT command-and-control host**. It is written into the resolver family on-chain (contract #1), presents the EtherRAT-specific `X-Bot-Server` CORS header on its `:3000` panel (per Shodan, last seen 2026-06-14), and was observed receiving a live beacon from a detonated sample in a behavioral packet capture. Ports `3000` (EtherRAT) and `3001` (Tsundere WebSocket C2) are open on the same host.

**KJ-4 — MODERATE CONFIDENCE.** The DPRK and Iranian operations are **operated and financed separately** despite the shared builder. Operator and deployer wallets are disjoint across the two clusters, and the DPRK funding chain (`SideShift → 0x564aa223 → 0x14afdDD6 → operator`) terminates at a no-KYC instant-swap exchange with **no observed link to any Iranian operator wallet.** The clusters share funding *typology* (no-KYC swaps) but not funding *infrastructure*; typology is non-discriminating and is not treated as an attribution link.

**KJ-5 — HIGH CONFIDENCE (methodological).** Resolver-contract calldata contains entries that are **decoys or recycled co-tenant IPs**, not all of which are live actor C2. This is demonstrated by `173.249.8.102` (decoded from contract #1 but hosting a live, unrelated Moroccan email-marketing/phishing operation) and by the prior-tenant phishing history on `91.215.85.42`'s bulletproof IP. Every decoded indicator therefore requires independent validation before being classified as C2.

---

## 2. The resolver family

EtherRAT implements EtherHiding via a minimal `string`-storage contract. The implant reads its C2 by calling the contract's getter (`getString`, selector `0x7d434425`) with the operator address; the operator rotates C2 by calling `setString` (selector `0x7fcaf666`), which writes the new value to storage and emits `StringChanged(address indexed account, string newString)`. That event's topic-0 is the durable family anchor.

| # | Contract (Ethereum mainnet) | Operator wallet | `setString` writes | Window | Source |
|---|---|---|---|---|---|
| 1 | `0x22f96D61cF118efaBC7C5bF3384734FaD2f6eaD4` | `0xE941A9b2…5951c4C8D` | 9 | Dec 5–8 2025 | Sysdig (PUBLISHED) |
| 2 | `0xe26c57B7fA8de030238b0a71b3d063397aC127D3` | `0x8D7e3Cc5…A4d398C12` | 25 | Jan 20 – May 18 2026 | eSentire (PUBLISHED) |
| 3 | `0xDf0B529043Ef7a2BB9111bAd26de624a326baCf9` | `0x5953f27F…583Dd2E4e` | 25 | Apr 24 – May 5 2026 | DFIR Report (PUBLISHED) |
| **4** | **`0x40A7d723F5Df6c88464bC95DBf7D96573fBc4f85`** | `0x14afdDD6…1eCb1C708` | 1 | Dec 4 2025 | **NOVEL (this report)** |

Contracts #1, #2, #4 are **byte-for-byte identical**. Contract #3 is a minor variant: it adds two constant-returning getters (`0x62b57aeb`, `0x62bf2985`) and emits a different topic (`0x3c520374…`) — a fork of the same kit, useful as a clustering fingerprint for further variants.

**Cross-cluster anchor.** The Iranian MuddyWater/Tsundere resolver family (separately documented at `github.com/yankywilson/muddywater-etherhiding-resolver-family`) emits the **same** `StringChanged` topic `0x3ca6280d…`. The shared topic + identical bytecode is the on-chain link between the two clusters (KJ-2).

See [`analysis/contract_bytecode.md`](analysis/contract_bytecode.md) for the decompiled resolver and reproduction steps, and [`analysis/funding_chain.md`](analysis/funding_chain.md) for the deployer/financier walk.

---

## 3. Live C2 confirmation — `91.215.85.42`

`91.215.85.42` was decoded from contract #1's calldata (`http://91.215.85.42:3000`). It is confirmed live EtherRAT C2 by three independent methods:

**(a) On-chain.** Written via `setString` on contract #1 by operator `0xE941A9b2…`, Dec 2025.

**(b) Shodan banner (host scan, last seen 2026-06-14).** Open ports `22, 3000, 3001, 5432, 6379`. The `:3000` HTTP response carries the EtherRAT server fingerprint:
```
HTTP/1.1 404 Not Found
Access-Control-Allow-Headers: Content-Type, Authorization, X-Bot-Server
ETag: W/"9-0gXL1ngzMqISxa6S1zx3F4wtLyg"
```
`X-Bot-Server` is the EtherRAT C2 header documented by Sysdig. Port `3001` corresponds to the Tsundere WebSocket C2 listener; `5432` (PostgreSQL, no auth) and `6379` (Redis, NOAUTH) are the panel's data backends. Hosting: **PROSPERO OOO, AS200593, St. Petersburg RU** (bulletproof).

**(c) Behavioral PCAP.** A detonated sample (victim `10.127.0.206`) beaconed to `91.215.85.42` over ports `80` and `3000` — the most-contacted external host in the capture (268 packets). The server returned the same `X-Bot-Server` header and identical `ETag` observed by Shodan, confirming a stable server build. The implant contacted the C2 **by direct IP with no preceding DNS lookup** — the EtherHiding resolver model working as designed (C2 address comes from the blockchain, not DNS). All other DNS in the capture was benign Microsoft/Google OS telemetry.

> **Calibration.** The passive DNS history of `91.215.85.42` (2023–2024) is dominated by Japanese/Turkish payment-phishing and fake-news domains on PROSPERO. These are **prior tenants of a recycled bulletproof IP** and are **EXCLUDED** from this actor's IOC set. The IP is treated as live EtherRAT C2 *now*; the 2023–24 domains are not attributed to this actor.

---

## 4. Decoded C2 inventory

Full machine-readable inventory in [`IOCs/c2_hosts.csv`](IOCs/c2_hosts.csv). Summary:

| Indicator | Contract | Type | Confidence | Verdict |
|---|---|---|---|---|
| `91.215.85.42` | #1 | EtherRAT C2 (`:3000`) + Tsundere (`:3001`) | **HIGH** | Live — triple-confirmed |
| `api-gateway-prod.com` → `193.200.17.66` | #4 | C2 domain | **HIGH** | Validated (cert + Censys) |
| `173.249.8.102` | #1 | — | **LOW / EXCLUDED** | Decoy or recycled co-tenant (Moroccan spam kit) |
| `rubysen.com` | #1 | C2 domain | MODERATE | Novel; passive validation pending |
| `ager-stp.org` | #1 | C2 domain | MODERATE | Novel; passive validation pending |
| `twicegrand.com` | #1 | C2 domain | MODERATE | Novel; passive validation pending |
| `aabstone.com` | #1 | C2 domain | MODERATE | Novel; passive validation pending |
| `grabify.link/SEFKGU` | #1 | IP-logger (recon) | n/a | **Not C2** — victim-recon link |
| `aurineuroth.com`, `jariosos.com`, `hayesmed.com`, `regancontrols.com`, `salinasrent.com`, `justtalken.com`, `mebeliotmasiv.com`, `euclidrent.com`, `o-parana.com`, `palshona.com` | #2 | C2 domains | — | **PUBLISHED** (eSentire) |

> Contract #3 (`0xDf0B5290`, 25 writes, Apr–May 2026) is the newest infrastructure and is **pending calldata decode** at time of writing; its hosts will be appended to `c2_hosts.csv`.

**`api-gateway-prod.com` campaign window (cert-bounded).** Two Let's Encrypt certs (the SCT pre-cert + leaf pair), both issued **2025-11-29**, no renewals, expiry **2026-02-27**. No subdomains were ever issued. On-chain write was 2025-12-04. This yields a clean, bounded lifecycle: provisioned Nov 29 → weaponized Dec 4 → abandoned ~Feb 27. Cert SHA-256: `720db1bac2a7a9b682ca84e7a6b897d994bd05d9eb0956c73059d8639d4b17a5`. The current `193.200.17.66` resolution (BlueVPS, AS62005, a MikroTik tenant) is treated as **point-in-time and likely recycled**; the durable indicators are the domain and the cert hash.

---

## 5. Funding & attribution

The DPRK funding chain was walked to termination (full detail in [`analysis/funding_chain.md`](analysis/funding_chain.md)):

```
SideShift (no-KYC swap) → 0x564aa223 → 0x14afdDD6 → 0xE941A9b2 (operator, contract #1)
                                            └── also deploys contract #4 (0x40A7d723)
```

The intermediaries are single-use, near-drained wallets (Nonce 0/1), a disposable-hop pattern consistent with both DPRK and Russian-speaking laundering. The Iranian operators (`0x002E9EB3…`, `0x73625B6c…`) are funded by **different** upstream wallets (`0xC43636B1…`, `0x635DE420…`). **No shared funding wallet exists between the clusters.**

**Confidence scorecard:**

| Claim | Confidence | Basis |
|---|---|---|
| EtherRAT resolver family = single builder | **HIGH** | identical bytecode + IPFS metadata + topic, 4 contracts |
| DPRK ↔ Iran shared builder/codebase | **HIGH** | identical bytecode + shared topic across both clusters |
| `91.215.85.42` = live EtherRAT C2 | **HIGH** | on-chain + `X-Bot-Server` + PCAP |
| EtherRAT attributed to DPRK | **MODERATE** | single-vendor (Sysdig), self-hedged; treat as MODERATE |
| Tsundere attributed to Russian-speaking actor (koneko) | **MODERATE–HIGH** | Kaspersky + Outpost24, multi-artifact |
| DPRK ↔ Iran share operator/financier | **NULL (excluded)** | disjoint wallets; DPRK peels to SideShift |
| Shared funding typology (no-KYC swaps) | **LOW** | common to many actors; non-discriminating |

> **On attribution.** This report does **not** assert that the DPRK and Iranian operations are the same actor. The defensible conclusion is a **shared builder/MaaS lineage** with **independent operation and financing**. The "DPRK" and "Russian-speaking" labels on the respective clusters are single-/few-vendor and are carried at MODERATE.

---

## 6. ATT&CK mapping

| Technique | ID | Evidence |
|---|---|---|
| Web Service: Dead Drop Resolver | T1102.001 | C2 address stored/retrieved via Ethereum smart-contract storage |
| Application Layer Protocol: Web | T1071.001 | HTTP beacon to `:3000`; `X-Bot-Server` header |
| Non-Application Layer Protocol | T1095 | Tsundere WebSocket C2 on `:3001` |
| Ingress Tool Transfer | T1105 | Node.js runtime pulled from nodejs.org; payload staged |
| Obfuscated Files or Information | T1027 | Obfuscator.io-packed JS (per Sysdig/eSentire) |
| Proxy: Multi-hop / disposable funding wallets | T1090 | single-use Nonce 0/1 intermediaries; SideShift terminus |

---

## 7. Reproduction (passive, no API key required)

1. Open each contract on Etherscan → **Logs** tab → read each `StringChanged` event's decoded `newString` field (toggle **Dec**) to recover C2 hosts. The contract `#events` page lists all writes on one page.
2. Verify any contract is a family member: pull its bytecode (**Contract → Code**) and confirm selectors `7d434425`/`7fcaf666` + topic `3ca6280d` + IPFS hash `1de57633…`.
3. Surface new contracts by pivoting on **operator/deployer wallets** (each wallet's transaction list shows every contract it deployed and the wallet that funded it).
4. Validate decoded C2 passively: Shodan host page (look for `X-Bot-Server` on `:3000`), crt.sh (cert history), VirusTotal community search (bare lowercase: `etherrat`, `etherhiding`, `tsundere`).

---

## 8. Detections

Durable detection content (the `X-Bot-Server` response header and `:3000` direct-IP beacon survive IP rotation) in [`detections/`](detections/):

- `etherrat_xbotserver.rules` — Suricata: EtherRAT C2 server fingerprint (`X-Bot-Server` in HTTP response headers)
- `etherrat_beacon.yml` — Sigma: outbound HTTP to a bare IP on `:3000` with no preceding DNS
- `etherhiding_rpc.yml` — Sigma: EtherHiding C2 resolution (process contacting public Ethereum RPC endpoints + Node.js runtime fetch)
- `hunting_queries.md` — KQL (Defender/Sentinel) + the Shodan/Censys banner-hunt queries for the `X-Bot-Server` / `ETag` panel fingerprint

---

## License & citation

Indicators and detection content are released **TLP:CLEAR** for community defensive use. Confidence levels and estimative likelihoods follow ICD-203 and are the author's own. Please retain attribution when redistributing.

> Wilson, Y. (2026). *EtherRAT On-Chain C2: A DPRK/Iran Shared-Builder Resolver Family.* TLP:CLEAR. github.com/yankywilson
