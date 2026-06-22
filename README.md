# 🧠 Memory Forensics Labs

> Windows memory forensics · Malware analysis · Volatility 2 & 3 · 

Hands-on memory forensics investigations against real public malware samples using
Volatility 2 and the standard DFIR methodology: identify → baseline → pivot to behaviour
→ prove injection → extract & verify → find persistence.

Both cases use the same core workflow applied at increasing complexity — Cridex as the
entry-level baseline, Zeus as the advanced multi-stage investigation.

---

## 📁 Cases

| # | Case | Malware | Target OS | Key Technique | Status |
|---|---|---|---|---|---|
| 01 | [Cridex Banking Trojan](#01--cridex-banking-trojan) | Cridex / Bugat | Windows XP SP3 | Process injection · C2 detection | ✅ Complete |
| 02 | [Zeus / Zbot Banking Trojan](#02--zeus--zbot-banking-trojan) | Zeus / Zbot | Windows XP SP2 | malfind · vaddump · persistence registry | ✅ Complete |

---

## 🔬 Volatility Workflow Reference

Every investigation follows this standard funnel:

```
info / imageinfo   → confirm profile + capture timestamp
pslist             → OS-linked process list (what Windows reports)
pstree             → parent-child tree (spot wrong parents)
psscan             → raw memory scan (catches hidden/exited processes)
connscan / netscan → network connections (find C2 behaviour)
malfind            → RWX + MZ header = injected executable
cmdline            → what arguments a process was launched with
dlllist            → which DLLs a process loaded (spot anomalous ones)
```

**Vol2 vs Vol3:**
- Volatility 2 (`/opt/volatility`) — required for legacy targets (WinXP NT 5.1). `netscan` fails on NT 5.1; use `connscan` instead.
- Volatility 3 (`/opt/vol3-venv`) — required for Win10/Win11 targets.

**malfind injection signature — three conditions must all be present:**

| Condition | What it means |
|---|---|
| `PAGE_EXECUTE_READWRITE` (RWX) | Memory is executable + writable — unusual for legitimate code |
| `PrivateMemory: 1` | Not backed by a file on disk — injected, not loaded |
| `4d 5a` (MZ header) | Starts with a PE/executable header — this is code, not data |

---

### 01 · Cridex Banking Trojan

**Tools:** Volatility 2.6.1 · Kali Linux  
**Sample:** `cridex.vmem` — 512 MB · public sample (Malware Analyst's Cookbook)  
**Profile:** WinXPSP3x86 (Windows XP SP3, 32-bit)  
**Host:** 172.16.112.128  
**Date completed:** June 2026 — self-directed lab (SCI CSS Module 8 prep)

**Executive Summary:**  
A Windows XP SP3 memory image was found infected with the Cridex banking trojan.
The dropper `reader_sl.exe` disguised itself as an Adobe SpeedLauncher process and
injected malicious code into `explorer.exe`. Two C2 connections were identified via
`connscan`. The infection was confirmed via `malfind` (RWX + MZ header in both
processes) and the anomalous presence of `WS2_32.dll` (network socket library) in
a process with no legitimate reason to make network calls.

**Investigation Phases:**

**Phase 1 — Identify the image**
```bash
volatility -f cridex.vmem imageinfo
# Profile: WinXPSP3x86
# Capture: 2012-07-22 (UTC)
```

**Phase 2 — Baseline the processes**
```bash
volatility -f cridex.vmem --profile=WinXPSP3x86 pslist
volatility -f cridex.vmem --profile=WinXPSP3x86 pstree
volatility -f cridex.vmem --profile=WinXPSP3x86 psscan
```

Finding: `reader_sl.exe` (PID 1640) appeared under `explorer.exe` — positioned
to look like a legitimate Adobe helper. Name and parent were plausible enough to
pass surface inspection.

**Phase 3 — Pivot to network behaviour**
```bash
# Vol3 netscan FAILS on NT 5.1 (WinXP) — must use Vol2 connscan
volatility -f cridex.vmem --profile=WinXPSP3x86 connscan
```

Finding: Two C2 connections identified:

| PID | Process | Remote IP | Port |
|---|---|---|---|
| 1484 | explorer.exe | 41.168.5.140 | 8080 |
| 1484 | explorer.exe | 125.19.103.198 | 8080 |

`explorer.exe` has no legitimate reason to make outbound connections to port 8080.
This is the behaviour pivot — the infection is provable by what it does, not what it looks like.

**Phase 4 — Prove code injection (malfind)**
```bash
volatility -f cridex.vmem --profile=WinXPSP3x86 malfind -p 1484
volatility -f cridex.vmem --profile=WinXPSP3x86 malfind -p 1640
```

Finding: Both `explorer.exe` (1484) and `reader_sl.exe` (1640) showed
`PAGE_EXECUTE_READWRITE` + `PrivateMemory: 1` + `MZ` header — the three-part
injection signature. Code had been written into both processes' memory.

**Phase 5 — DLL analysis**
```bash
volatility -f cridex.vmem --profile=WinXPSP3x86 dlllist -p 1640
volatility -f cridex.vmem --profile=WinXPSP3x86 cmdline -p 1640
```

Finding: `reader_sl.exe` had loaded `WS2_32.dll` — the Windows socket library.
An Adobe SpeedLauncher helper has no legitimate reason to open network sockets.
This is the dlllist tell that confirms `reader_sl.exe` is the dropper.

**Findings Summary:**

| # | Finding | Evidence | Plugin |
|---|---|---|---|
| 1 | C2 communication | explorer.exe → 41.168.5.140:8080 + 125.19.103.198:8080 | connscan |
| 2 | Code injection — explorer.exe | RWX + MZ header in PID 1484 | malfind |
| 3 | Code injection — reader_sl.exe | RWX + MZ header in PID 1640 | malfind |
| 4 | Anomalous DLL | WS2_32.dll loaded by non-network process | dlllist |
| 5 | Dropper identified | reader_sl.exe — faked Adobe SpeedLauncher | cmdline + dlllist |

**IOCs:**

```
C2 IP:   41.168.5.140:8080
C2 IP:   125.19.103.198:8080
File:    reader_sl.exe (dropper — disguised as Adobe SpeedLauncher)
MITRE:   T1055 — Process Injection
MITRE:   T1071.001 — Application Layer Protocol: Web Protocols (C2 over HTTP)
```

**Key lesson:**  
Vol3 `netscan` fails silently on WinXP (NT 5.1 not supported). Vol2 `connscan`
is required for legacy targets. This is why Mat's course requires both Vol2 and Vol3
to be installed — the right tool depends on the target OS, not personal preference.

---

### 02 · Zeus / Zbot Banking Trojan

**Tools:** Volatility 2.6.1 · Kali Linux · VirusTotal  
**Sample:** `zeus.vmem` — 128 MB · public sample (Malware Analyst's Cookbook)  
**Profile:** WinXPSP2x86 (Windows XP SP2, 32-bit, 1 processor)  
**Host:** BILLY-DB5B96DD3 · user: Administrator  
**Capture date:** 2010-08-15 19:17:56 UTC  
**Malware family:** Zeus / Zbot (banking credential-stealing trojan)  
**Date completed:** June 2026 — self-directed lab (SCI CSS Module 8)

**Executive Summary:**  
A 128 MB Windows XP SP2 memory image was found infected with the Zeus/Zbot
banking trojan. Every process name, path, and parent looked entirely legitimate —
standard process-tree analysis revealed nothing. The infection was uncovered by
pivoting to behaviour: `svchost.exe` (PID 856) was communicating with an external
C2 server. `malfind` proved malicious code had been injected into that legitimate
process. Following the persistence artefact (`sdra64.exe`) led to a second injected
process, `winlogon.exe` (PID 632). The injected region was confirmed as Zeus/Zbot
by 63 of 71 AV engines on VirusTotal.

**Key forensic principle:**
> A clean process list does NOT mean a clean machine. Zeus hides by injecting into
> legitimate processes — genealogy finds nothing. When "what it looks like" is clean,
> pivot to "what it does" (network behaviour), then prove injection with malfind.

**Investigation Stages:**

**Stage 1 — Identify the image**
```bash
volatility -f zeus.vmem imageinfo
# Profile: WinXPSP2x86
# Capture: 2010-08-15 19:17:56 UTC
# Single processor — dictates Vol2 + connscan (not netscan)
```

**Stage 2 — Baseline the processes (deliberate dead end)**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 pslist
volatility -f zeus.vmem --profile=WinXPSP2x86 pstree
volatility -f zeus.vmem --profile=WinXPSP2x86 psscan
```

Finding: Process list looked completely legitimate — no misspelled names, correct
parents, sane svchost count. **This is the lesson**: Zeus injects into legitimate
processes, so genealogy cannot find it.

Notable: `VMip.exe` (PID 1944) appeared in `psscan` only, not in `pslist` or
`pstree` — a DKOM (Direct Kernel Object Manipulation) indicator. Process visible
in raw memory scan but absent from the OS linked list = hiding or short-lived.

**Stage 3 — Pivot to network behaviour**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 connscan
volatility -f zeus.vmem --profile=WinXPSP2x86 connections
```

Finding: `connscan` revealed PID 856 connecting to `193.104.41.75:80`.
Does this process have any business talking to the internet?

**Stage 4 — Identify the owning process**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 psscan | grep 856
volatility -f zeus.vmem --profile=WinXPSP2x86 cmdline -p 856
volatility -f zeus.vmem --profile=WinXPSP2x86 dlllist -p 856
```

Finding: PID 856 = `svchost.exe` — correctly pathed, correctly parented
(`services.exe`). `cmdline` and `dlllist` showed nothing suspicious. Yet
`svchost` hosts internal Windows services and has **no legitimate reason** to make
outbound web connections. Legitimate process + malicious behaviour = injected code.

**Stage 5 — Prove code injection (malfind)**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 malfind -p 856
```

Finding:
- Region `0xb70000`: `PAGE_EXECUTE_READWRITE` + `PrivateMemory: 1` + `4d 5a` (MZ) = **injected PE**
- Region `0xcb0000`: small JMP stub = API hook (not a full PE)

**Stage 6 — Extract & verify**
```bash
mkdir -p dump
volatility -f zeus.vmem --profile=WinXPSP2x86 procdump -p 856 --dump-dir=./dump
volatility -f zeus.vmem --profile=WinXPSP2x86 malfind -p 856 --dump-dir=./dump
volatility -f zeus.vmem --profile=WinXPSP2x86 vaddump -p 856 --base=0xb70000 --dump-dir=./dump
sha256sum ./dump/*
```

**Critical distinction — procdump vs vaddump:**

| Dump | What it is | VirusTotal |
|---|---|---|
| `procdump` (executable.856.exe) | Legitimate svchost shell (ImageBase 0x01000000) | 0/71 — clean |
| `vaddump` (0xb70000 region) | **Injected Zeus PE** | **63/71 — Zeus/Zbot** |

`procdump` rebuilds the process's main image — for PID 856 that is the genuine,
clean `svchost`. The malware lives in a **separate injected region** — only
`vaddump` / `malfind --dump-dir` extracts it.

> **Evidence handling note:** Hash only — never upload live samples to VirusTotal.
> SHA256 search only. Extracted dumps retained inside the isolated analysis VM,
> never executed, never transferred off-host (revDSG Art. 8).

**Stage 7 — Persistence**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 \
  printkey -K "Microsoft\Windows NT\CurrentVersion\Winlogon"
```

Finding: `Userinit` value normally reads only `userinit.exe`. Here:
```
Userinit: C:\WINDOWS\system32\userinit.exe,C:\WINDOWS\system32\sdra64.exe,
```

Zeus appended `sdra64.exe` — its own dropped file. Windows launches this at
every logon. The same key revealed: host = `BILLY-DB5B96DD3`, user = `Administrator`.

**Stage 8 — Pivot to the second injected process**
```bash
volatility -f zeus.vmem --profile=WinXPSP2x86 filescan | grep -i sdra64
volatility -f zeus.vmem --profile=WinXPSP2x86 handles | grep -i sdra64
volatility -f zeus.vmem --profile=WinXPSP2x86 psscan | grep 632
volatility -f zeus.vmem --profile=WinXPSP2x86 malfind -p 632
```

Finding: `handles` showed PID 632 holding `sdra64.exe` open. PID 632 =
`winlogon.exe`. `malfind -p 632` revealed region `0xae0000` with identical
signature — `PAGE_EXECUTE_READWRITE` + `4d 5a` + private memory. Second injected
process confirmed — found purely by following the evidence chain.

**Findings Summary:**

| # | Finding | Evidence | Plugin |
|---|---|---|---|
| 1 | C2 communication | svchost.exe (856) → 193.104.41.75:80 | connscan |
| 2 | Code injection #1 | RWX + MZ header @ 0xb70000 in PID 856 | malfind |
| 3 | Malware identity | Injected region: 63/71 — Zeus/Zbot (password stealer) | vaddump + VirusTotal |
| 4 | Persistence | Userinit = userinit.exe,sdra64.exe (runs each logon) | printkey |
| 5 | Code injection #2 | RWX + MZ header @ 0xae0000 in winlogon (632) | filescan→handles→malfind |
| 6 | Hidden / short-lived process | VMip.exe (1944) — psscan only, not in pslist | psscan vs pslist |
| 7 | Host / user | BILLY-DB5B96DD3 / Administrator | printkey |

**IOCs:**

```
C2 IP:    193.104.41.75:80
File:     C:\WINDOWS\system32\sdra64.exe (dropped payload + persistence)
Registry: HKLM\...\Winlogon\Userinit += sdra64.exe
SHA256:   8e3be5dc65aa35d68fd2aba1d3d9bf0f40d5118fe22eb2e6c97c8463bd1f1ba1
          (injected region 0xb70000 — 63/71 VT detections)
Family:   Zeus / Zbot (Trojan-Spy / PSW — password stealer)
MITRE:    T1055   — Process Injection
MITRE:    T1547.001 — Boot/Logon Autostart: Registry Run Keys / Userinit
MITRE:    T1071.001 — C2 over HTTP
```

📄 **[Download Full Investigation Report (PDF)](./04-zeus/Zeus_Memory_Forensics_Report.pdf)**

---

## 🧰 Tools Used

| Category | Tools |
|---|---|
| Memory Forensics | Volatility 2.6.1 · Volatility 3 |
| Threat Intel | VirusTotal (hash lookup only) |
| Samples | Public malware images — Malware Analyst's Cookbook |
| Platform | Kali Linux · VirtualBox (isolated analysis VM) |

---

## ⚖️ Legal & Ethical Notice

All memory images analysed are **public research samples** from the Malware Analyst's
Cookbook, used exclusively for educational forensics practice.

- No live malware was executed
- Extracted dumps were retained inside an isolated analysis VM and never transferred off-host
- Hash-only VirusTotal lookups — no sample uploads (evidence handling discipline, revDSG Art. 8)
- All work complies with Swiss law and ethical research standards
- Completed as part of the Swiss Cyber Institute CSS EFA Program — Module 8 Memory Forensics
