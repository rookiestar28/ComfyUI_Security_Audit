# 🛡️ ComfyUI Security Audit (AST & Runtime Monitor)

[![ComfyUI](https://img.shields.io/badge/ComfyUI-Custom_Node-blue)](https://github.com/comfyanonymous/ComfyUI)
[![Security](https://img.shields.io/badge/Security-AST_Analysis-green)]()
[![License](https://img.shields.io/badge/License-MIT-orange)]()

<div align="center">

[繁體中文 (Traditional Chinese)](README.zh-TW.md) | [English](README.md)

</div>

---

### Introduction

**ComfyUI Security Audit** is a lightweight, dual-layer security extension designed for ComfyUI. As the ecosystem of custom nodes grows, so does the risk of malicious code. This node provides a safety check mechanism using **Static Analysis (AST)** and **Runtime Monitoring** to help users detect potential threats in third-party nodes.

It acts as a "smoke detector" for your ComfyUI environment, identifying risky operations like shell commands, dynamic code execution, and unauthorized network requests.

### Key Features

1. **AST-Based Static Analysis**:
   * Uses Python's **Abstract Syntax Tree (AST)** engine instead of simple Regex.
   * Accurately identifies dangerous function calls (e.g., `os.system`, `subprocess`) while ignoring comments and strings, significantly reducing false positives.
   * **Smart Caching**: Caches scan results based on file timestamps for instant subsequent scans.

2. **Real-time Runtime Monitor**:
   * Uses **Monkey Patching** to hook into sensitive system APIs (`os`, `subprocess`, `shutil`).
   * **Async Network Support**: Monitors both synchronous (`requests`, `urllib`) and asynchronous (`aiohttp`) network traffic to detect hidden data exfiltration.
   * **Thread-Safe**: Designed with locking mechanisms to ensure stability in multi-threaded ComfyUI workflows.
   * **Tracing**: Identifies exactly *which* custom node initiated the risky action.

3. **Integrated UI Report**:
   * Displays scan results directly in the ComfyUI interface.
   * Supports **English** and **Traditional Chinese**.

### Installation

Navigate to your ComfyUI `custom_nodes` directory and clone this repository:

```bash
cd ComfyUI/custom_nodes
git clone https://github.com/YourUsername/ComfyUI-Security-Audit.git
```

Restart ComfyUI to load the node.

### Usage

1. **Add Node**: Right-click in the workflow → `🛡️ Security` → `🛡️ ComfyUI Security Audit`.

2. **Parameters**:
   * `scan_trigger`: Increment this number (or randomize) to force a new static scan.
   * `language`: Switch between English and Traditional Chinese for the report.
   * `realtime_monitor`:
     * **DISABLE**: Monitor is off (default).
     * **ENABLE**: Activates the runtime hooks. High-risk actions and network requests will be logged to the console and `security_audit.log`.
   * `show_recent_logs`: Number of recent log entries to display in the node output.
   * `custom_path`: Target directory to scan (default is `custom_nodes`).

### Detected Risks (Examples)

* **Critical**: Keyloggers (`pynput`), Remote Access Tools.
* **High**: System shell commands (`os.system`, `popen`), Dynamic execution (`eval`, `exec`), Base64 decoding (obfuscation).
* **Warning**: File deletion (`rmtree`), Network uploads (`POST` requests), Socket connections.

### ⚠️ Disclaimer & Limitations (Important)

**PLEASE READ CAREFULLY BEFORE USE:**

1.  **Not an Antivirus**: This tool is a Python-level script analyzer. It **CANNOT** detect malware hidden in compiled binary files (`.pyd`, `.so`, `.dll`) or sophisticated zero-day exploits.

2.  **Bypass Possibility**: Advanced attackers may use techniques (e.g., highly complex obfuscation, C-level system calls) to bypass the AST scanner and runtime hooks.

3.  **Accuracy & Verification**: The scan results **may contain false positives** (flagging safe code as risky) or **false negatives** (missing actual threats). Users should **independently verify** the findings before taking action. Do not rely solely on this tool for security decisions.

4.  **Runtime Monitor Risks**: The runtime monitor intercepts system calls. While designed to be safe, there is a theoretical risk that it could conflict with certain complex nodes or cause instability.

5.  **No Liability**:
    * This software is provided "AS IS", without warranty of any kind.
    * The developer is **NOT liable** for any damages, data loss, hardware failure, or security breaches resulting from the use or misuse of this tool.
    * For maximum security, always run ComfyUI in an isolated environment (Docker/VM).