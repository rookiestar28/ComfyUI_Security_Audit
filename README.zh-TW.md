# 🛡️ ComfyUI Security Audit (AST & Runtime Monitor)

[![ComfyUI](https://img.shields.io/badge/ComfyUI-Custom_Node-blue)](https://github.com/comfyanonymous/ComfyUI)
[![Security](https://img.shields.io/badge/Security-AST_Analysis-green)]()
[![License](https://img.shields.io/badge/License-MIT-orange)]()

<div align="center">

[繁體中文 (Traditional Chinese)](README.zh-TW.md) | [English](README.md)

</div>

---

### 簡介

**ComfyUI Security Audit** 是一款專為 ComfyUI 設計的輕量級雙層安全防護插件。隨著 ComfyUI 第三方節點生態的爆炸式增長,惡意代碼的風險也隨之增加。本插件透過 **AST 靜態分析** 與 **即時行為監控**,協助使用者發現潛在的安全威脅。

它就像是您 ComfyUI 環境的「煙霧探測器」,能夠識別 Shell 指令、動態代碼執行以及未授權的網絡請求等高危操作。

### 核心功能

1. **基於 AST 的靜態掃描**:
   * 使用 Python **抽象語法樹 (Abstract Syntax Tree)** 引擎,而非簡單的正則表達式。
   * 能精準識別危險函數調用（如 `os.system`）,並自動忽略註釋與字串內容,大幅降低誤報率。
   * **智能緩存 (Smart Cache)**：根據文件修改時間緩存掃描結果,二次掃描極速完成。

2. **即時行為監控 (Runtime Monitor)**:
   * 利用 **Monkey Patching** 技術,掛鉤敏感的系統 API（`os`, `subprocess`, `shutil`）。
   * **異步網絡支援**：不僅監控同步請求 (`requests`, `urllib`),也能監控 `aiohttp` 等異步請求,防止背景數據外洩。
   * **線程安全**：內建線程鎖機制,確保在多線程環境下穩定運行。
   * **精準溯源**：當危險發生時,能回溯並指出是「哪一個自定義節點」發起的調用。

3. **整合式 UI 報告**:
   * 直接在 ComfyUI 節點介面上顯示掃描報告與監控日誌。
   * 支援 **繁體中文** 與 **英文** 介面切換。

### 安裝方式

請進入您的 ComfyUI `custom_nodes` 資料夾並複製此專案：

```bash
cd ComfyUI/custom_nodes
git clone https://github.com/YourUsername/ComfyUI-Security-Audit.git
```

重新啟動 ComfyUI 即可加載節點。

### 使用方法

1. **新增節點**: 在工作區右鍵 → `🛡️ Security` → `🛡️ ComfyUI Security Audit`。

2. **參數說明**:
   * `scan_trigger`: 更改此數值（或設為隨機）以觸發新的靜態掃描。
   * `language`: 選擇報告語言（English / Traditional Chinese）。
   * `realtime_monitor`:
     * **DISABLE**: 關閉監控（預設）。
     * **ENABLE**: 啟用運行時掛鉤。高危行為與網絡請求將被攔截並記錄到控制台與 `security_audit.log`。
   * `show_recent_logs`: 在節點輸出中顯示最近幾筆日誌。
   * `custom_path`: 指定要掃描的目標資料夾（預設為 `custom_nodes`）。

### 可檢測的風險 (範例)

* **嚴重 (Critical)**: 鍵盤監聽 (`pynput`)、遠端控制工具引用。
* **高危 (High)**: 系統 Shell 指令 (`os.system`, `popen`)、動態代碼執行 (`eval`, `exec`)、Base64 隱藏代碼。
* **警告 (Warning)**: 檔案刪除 (`rmtree`)、網絡數據上傳 (`POST` 請求)、Socket 底層連線。

### ⚠️ 免責聲明與限制 (重要)

**使用前請務必仔細閱讀：**

1.  **非防毒軟體**: 本工具僅為 Python 層面的腳本分析器，**無法檢測** 隱藏在編譯文件（`.pyd`, `.so`, `.dll`）中的惡意代碼，也無法防禦零日漏洞 (Zero-day exploits)。

2.  **可能被繞過**: 高級攻擊者可能使用複雜的混淆技術或底層 C 語言調用來繞過 AST 掃描與運行時監控。

3.  **準確性與驗證**: 掃描結果**可能包含誤判**（將安全代碼標記為風險）或**漏報**（未能發現真實威脅）。使用者應**自行查證**掃描結果。請勿完全依賴本工具作為安全決策的唯一依據。

4.  **運行風險**: 運行時監控涉及攔截系統底層調用。雖然我們已盡力確保安全，但在極少數情況下可能會與某些特定節點發生衝突或導致不穩定。

5.  **無責任聲明**:
    * 本軟體按「原樣 (AS IS)」提供，不提供任何形式的保證。
    * 開發者**不對**因使用或濫用本工具而導致的任何損失、數據丟失、硬體損壞或安全漏洞承擔任何責任。
    * 為了最高等級的安全，建議在隔離環境（Docker/VM）中運行 ComfyUI。