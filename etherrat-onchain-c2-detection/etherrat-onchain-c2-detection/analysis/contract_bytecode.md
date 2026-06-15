# Annex A — Resolver Contract Bytecode

Author: Yanky Wilson (github.com/yankywilson) — TLP:CLEAR

This annex documents the EtherRAT EtherHiding resolver contract and the fingerprints
that prove the four contracts (and the cross-cluster Iranian Tsundere family) are
compiled from a single source.

---

## The contract

A minimal `string`-storage contract. Two functions:

| Selector | Name | Purpose |
|---|---|---|
| `0x7d434425` | `getString(address)` | **Read.** Implant calls this with the operator address to fetch the current C2 string. View function — no transaction, no payload. |
| `0x7fcaf666` | `setString(string)` | **Write.** Operator calls this to rotate C2. Writes to storage and emits `StringChanged`. The transaction calldata carries the C2 string in plaintext. |

On every write it emits:
```solidity
event StringChanged(address indexed account, string newString);
```
Topic-0 (the event signature hash) is:
```
0x3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d47
```

## Family fingerprint (Family A — contracts #1, #2, #4)

These three are **byte-for-byte identical**. Shared markers:

| Fingerprint | Value |
|---|---|
| Runtime bytecode | identical (full hex in `family_A_runtime.hex` below) |
| Read selector | `0x7d434425` |
| Write selector | `0x7fcaf666` |
| `StringChanged` topic-0 | `0x3ca6280d…ade2d47` |
| Solc metadata IPFS hash | `1de57633fefe5e5685ff0dc91b16c628ac4b2544e90be126d02cda08fa28ce11` |
| Solc version (from metadata tail) | `0x081e` → 0.8.30 |

The **IPFS metadata hash matching** is decisive: it means the same source file
compiled with the same compiler version and the same settings produced all three
contracts. This is not "similar code" — it is the same build artifact redeployed.

## Family A runtime bytecode (contracts #1, #2, #4 — identical)
```
0x608060405234801561000f575f5ffd5b5060043610610034575f3560e01c80637d434425146100385780637fcaf66614610061575b5f5ffd5b61004b61004636600461017c565b610076565b60405161005891906101a9565b60405180910390f35b61007461006f3660046101f2565b61011f565b005b6001600160a01b0381165f90815260208190526040902080546060919061009c906102a5565b80601f01602080910402602001604051908101604052809291908181526020018280546100c8906102a5565b80156101135780601f106100ea57610100808354040283529160200191610113565b820191905f5260205f20905b8154815290600101906020018083116100f657829003601f168201915b50505050509050919050565b335f9081526020819052604090206101378282610329565b50336001600160a01b03167f3ca6280dac32fee85e9d3d81188d59eed7e4966e5b3df13a910924cf6ade2d478260405161017191906101a9565b60405180910390a250565b...fea26469706673582212201de57633fefe5e5685ff0dc91b16c628ac4b2544e90be126d02cda08fa28ce1164736f6c634300081e0033
```
(Full hex omitted for brevity at the tail; the `a2646970667358221220 1de57633… 64736f6c6343 0008 1e 0033` trailer encodes the IPFS metadata hash and solc version.)

## Family B variant (contract #3)

`0xDf0B529043Ef7a2BB9111bAd26de624a326baCf9` is a fork:
- Adds two constant-returning getters: `0x62b57aeb`, `0x62bf2985`
- Emits a **different** `StringChanged` topic: `0x3c520374…`
- Different IPFS metadata hash (`264fe4a1…`)

Treat the two added constant selectors as a **clustering fingerprint** for finding
additional Family B variants on-chain.

## Cross-cluster link

The Iranian MuddyWater/Tsundere resolver family (documented separately at
`github.com/yankywilson/muddywater-etherhiding-resolver-family`) emits the **same**
`StringChanged` topic `0x3ca6280d…` as Family A. Identical topic + identical bytecode
across the DPRK and Iranian clusters is the on-chain evidence for **KJ-2** (shared
builder/codebase). It does **not** imply shared operation — see Annex B.

## Reproduction
1. Etherscan → contract address → **Contract → Code** → copy runtime bytecode.
2. Diff against Family A hex above; confirm the `1de57633…` IPFS trailer.
3. Decode C2: **Logs** tab → `StringChanged` → `newString` (Dec view).
