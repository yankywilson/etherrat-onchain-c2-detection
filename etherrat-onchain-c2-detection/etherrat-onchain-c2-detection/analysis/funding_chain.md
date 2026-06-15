# Annex B — Funding & Deployer Chain

Author: Yanky Wilson (github.com/yankywilson) — TLP:CLEAR

This annex documents the on-chain funding walk for the DPRK EtherRAT cluster, the
discovery of the novel contract via that walk, and the **excluded** financier-link
hypothesis.

---

## The chain (DPRK cluster)

```
SideShift (no-KYC swap)
   │  0.00249 ETH, 2025-12-04 22:42
   ▼
0x564Aa2230f9c4944bEf4c9e1aBF8F75cb2e4a23A      (Nonce 1 — single-use)
   │  0.00241 ETH, 2025-12-04 22:45
   ▼
0x14afdDD627Fb0e039365554f8bbDB881eCb1C708      (Nonce 2→3 — single-use)
   ├─ 0.00167 ETH, 2025-12-05 19:10 ──► 0xE941A9b2…5951c4C8D   (operator, contract #1)
   └─ deploys + setString ───────────► 0x40A7d723…fBc4f85       (contract #4, NOVEL)
```

## How the novel contract surfaced

The walk *up* the funding chain from operator #1 is what surfaced contract #4. The
funder `0x14afdDD6` was not a passive money-mover: on 2025-12-04 it **created a
contract** and called `setString` on `0x40A7d723…` (writing `api-gateway-prod.com`),
then 18 minutes later funded operator #1. Pulling that wallet's transaction list
exposed the deployment of contract #4 — a resolver in no public report. This is the
funding-graph analogue of the resolver-family enumeration: pivot on wallets, not just
contracts.

## Tradecraft observations

- **Disposable single-use intermediaries.** `0x564aa223` (Nonce 1) and `0x14afdDD6`
  (Nonce 2→3) are fresh wallets holding a few dollars, drained after one or two sends.
  A per-deployment one-time-wallet pattern, consistent with both DPRK and
  Russian-speaking laundering.
- **Terminus = no-KYC swap.** The chain ends at the SideShift hot wallet
  (`0xcdd37ada…`). Contract #3's operator (`0x5953f27F…`) was independently funded via
  **FixedFloat** and **ChangeNOW** — the same class of no-KYC instant-swap service.

## EXCLUDED — shared financier hypothesis

The hypothesis that the DPRK and Iranian clusters share a financier was **tested and
ruled out**:

| Cluster | Operator wallet(s) | Funded by |
|---|---|---|
| DPRK | `0xE941A9b2…`, `0x5953f27F…` | `0x14afdDD6` → `0x564aa223` → SideShift; FixedFloat/ChangeNOW |
| Iran | `0x002E9EB3…`, `0x73625B6c…` | `0xC43636B1…`, `0x635DE420…` |

**No shared funding wallet exists.** The clusters share funding *typology* (no-KYC
swaps) but not funding *infrastructure*. Typology is common to a very large population
of threat actors and is **non-discriminating** — it is carried at LOW and is **not**
treated as an attribution link. This is a logged null result, not an omission.

## Bottom line

The funding walk produced a real positive (the novel contract #4) and a real negative
(no shared financier). Both are findings. The defensible conclusion remains a **shared
builder/MaaS lineage with independent operation and financing** between the DPRK and
Iranian clusters (KJ-2, KJ-4).
