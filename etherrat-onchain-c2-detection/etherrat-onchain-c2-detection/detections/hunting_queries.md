# Hunting Queries — EtherRAT On-Chain C2

Author: Yanky Wilson (github.com/yankywilson) — TLP:CLEAR

The two highest-value hunts are the **`X-Bot-Server` server fingerprint** and the
**direct-IP `:3000` beacon**. Both survive IP rotation, unlike the raw C2 IPs.

---

## Microsoft Defender / Sentinel (KQL)

### 1. Direct-IP beacon to :3000 with no preceding DNS (EtherHiding behavior)
```kql
let window = 1h;
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 3000 and ActionType == "ConnectionSuccess"
| where RemoteIP matches regex @"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
| where not(ipv4_is_private(RemoteIP))
| join kind=leftanti (
    DeviceEvents
    | where ActionType == "DnsQueryResponse"
    | where Timestamp > ago(7d)
    | project DeviceId, ResolvedIP = tostring(parse_json(AdditionalFields).IP), DnsTime = Timestamp
) on DeviceId
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort
```

### 2. Non-browser process contacting public Ethereum RPC (C2 resolution)
```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl in~ (
    "eth.llamarpc.com","rpc.flashbots.net","rpc.mevblocker.io",
    "eth-mainnet.public.blastapi.io","ethereum-rpc.publicnode.com",
    "rpc.payload.de","eth.drpc.org","eth.merkle.io",
    "mainnet.gateway.tenderly.co","1rpc.io")
| where InitiatingProcessFileName in~ ("node.exe","conhost.exe","mshta.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteUrl
```

### 3. Known live C2 + Node.js runtime pulled from nodejs.org
```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP == "91.215.85.42"
   or (RemoteUrl has "nodejs.org" and RemoteUrl has "node-v")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
```

---

## Shodan — panel fingerprint hunt (find sibling C2s)

```
# EtherRAT panel by server header
http.html:"X-Bot-Server"
# scoped to the panel port
http.html:"X-Bot-Server" port:3000
# known host's hosting AS, to find neighbours
asn:AS200593 port:3000
```

## Censys — same, by header / ASN
```
services.http.response.headers.access_control_allow_headers: "X-Bot-Server"
autonomous_system.asn: 200593 and services.port: 3000
```

## ETag pivot (static-asset hash on the panel)
The `:3000` panel returned `ETag: W/"9-0gXL1ngzMqISxa6S1zx3F4wtLyg"` on both Shodan
and in the PCAP. Searching this ETag across scan data surfaces other servers running
the same panel build:
```
# Shodan
http.html:"0gXL1ngzMqISxa6S1zx3F4wtLyg"
```

---

## On-chain hunt (Etherscan, passive)
- Decode any contract's `StringChanged` events (topic `0x3ca6280d…`) → recover C2 hosts.
- Confirm Family A membership: bytecode selectors `7d434425`/`7fcaf666` + IPFS hash `1de57633…`.
- Pivot operator/deployer wallets → enumerate further contracts and the funding chain.

> **OPSEC.** All network hunts above use third-party scan data or local telemetry.
> Do not connect directly to suspected live C2 (e.g. do not curl `91.215.85.42:3000`).
