# Northpeak Descent

**Community threat hunt // Cyber Range — designed and built by Dogukan Oruc during his internship at Log(N) Pacific**

![Status](https://img.shields.io/badge/status-live-ef4444)
![Difficulty](https://img.shields.io/badge/difficulty-intermediate-ef9f27)
![Flags](https://img.shields.io/badge/flags-18-0e0e16)
![Telemetry](https://img.shields.io/badge/telemetry-Sentinel%20%2F%2F%20MDE-2563eb)

> *An operator held the front door open while everyone watched the noise.*

**Play it live:** [hunt.lognpacific.com/hunt-10-brief](https://hunt.lognpacific.com/hunt-10-brief) · *Cyber Range membership required*

---

## Overview

Northpeak Descent is a cross-platform intrusion investigation set at **Northpeak Logistics**, a fictional company whose estate spans Windows infrastructure and a Linux host. On the evening of 16 June, an operator established multiple parallel footholds, moved across the estate, staged tooling, set persistence, beaconed to command-and-control infrastructure, and exfiltrated sensitive data — all inside roughly four and a half hours.

The telemetry tells a loud story of a brute-force break-in. That story is bait. The real entry authenticated cleanly with valid credentials and never tripped an alert. Hunters have to separate the decoy noise from the genuine intrusion, prove the order of the footholds instead of assuming it, and reason from evidence that *isn't there* — because some of the strongest findings in this hunt are things that deliberately did not happen.

## Hunt structure

The hunt is 18 flags across a setup gate and five investigative phases, worked in order:

| Stage | Focus |
|-------|-------|
| **00 — Setup gate** | Confirm access to the correct Sentinel workspace before touching the case |
| **01 — Initial access** | The real entry, the true order of the footholds, the operator's client, and how the server was reached |
| **02 — Linux recon & tooling** | Escalation checks, reachability testing without a scanner, and the tooling installed to pivot |
| **03 — Pivot, execution, persistence** | The internal hop, hands-on-keyboard shells hidden in automation noise, and what was planted to survive a reboot |
| **04 — Command & control** | A look-alike channel, one domain the network saw, two it didn't, and what the beacon rhythm proves |
| **05 — Impact & judgement** | The theft, the session it left in, and the trust model that let the operator run freely without touching the security stack |

## Telemetry and tooling

All evidence lives in a shared Microsoft Sentinel workspace (`law-cyber-range`) and is hunted with **KQL** across the Microsoft Defender for Endpoint advanced hunting tables:

`DeviceProcessEvents` · `DeviceFileEvents` · `DeviceNetworkEvents` · `DeviceRegistryEvents` · `DeviceLogonEvents` · `DeviceEvents`

Because the workspace is shared across multiple hunt estates, scoping discipline is part of the exercise — every query must be filtered to the Northpeak hosts (`npt-ws01`, `npt-srv01`, `npt-linux01`) or it returns someone else's telemetry.

## Design notes

A few things I built into this hunt deliberately:

- **Noise as a decoy.** A failed-logon storm makes the intrusion look like brute force. The actual entry is a clean, valid-account authentication — hunters who chase volume lose the thread.
- **An order-of-events trap.** The shape of the data suggests Linux was compromised first and Windows second. Building a single cross-platform timeline proves otherwise.
- **Absence as evidence.** Quiet tables aren't dead ends. No tampering and nothing dropped are findings in themselves, pointing at a stealthier tradecraft the hunter has to name.
- **Blind spots as signal.** Part of the C2 channel never appears in network telemetry. The trace it leaves at the point of launch — and the blindness of one console — is the finding.
- **Human vs. machine.** The operator's hands-on-keyboard activity is buried in routine estate automation; separating the two is a core skill the hunt exercises.

## What's in this repo

- **`index.html`** — a standalone, self-contained copy of the operation brief exactly as it appears on the platform (original styling preserved, all platform code removed).
- **`assets/`** — cover art for the brief.

**Not** in this repo: flags, answers, KQL solutions, or the underlying attack emulation. The hunt is live and stays playable — only the public-facing brief is published here.

## View the brief

**Live page:** [loransee.github.io/Northpeak-Descent](https://loransee.github.io/Northpeak-Descent/) *(hosted with GitHub Pages)*

Or open `index.html` locally in any browser — it has no dependencies beyond Google Fonts.

## Author

**Dogukan Oruc** — threat hunt design, attack emulation, telemetry engineering, and brief.

Built during an internship at **Log(N) Pacific** for **Josh Madakor**'s Cyber Range community threat hunt series, live at [hunt.lognpacific.com](https://hunt.lognpacific.com).
