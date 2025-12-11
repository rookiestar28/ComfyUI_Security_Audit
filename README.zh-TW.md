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
   * 能精準識別危險函數調用（如 `os.system`, `subprocess`, `pickle`, `ctypes`）,並自動忽略註釋與字串內容,大幅降低誤報率。
   * **智能緩存 (Smart Cache)**：根據文件修改時間緩存掃描結果,二次掃描極速完成。

2.  **懶加載即時監控 (Lazy Loading)**:
    *   **效能優先**: 監控 Hook 僅在您明確啟用「Real-time Monitor」時才會安裝。若未啟用監控，將完全不影響節點的正常運作。

3. **即時行為監控 (Runtime Monitor)**:
   * 利用 **Monkey Patching** 技術,掛鉤敏感的系統 API（`os`, `subprocess`, `shutil`）。
   * **異步網絡支援**：不僅監控同步請求 (`requests`, `urllib`),也能監控 `aiohttp` 等異步請求,防止背景數據外洩。
   * **線程安全**：內建線程鎖機制,確保在多線程環境下穩定運行。
   * **精準溯源**：當危險發生時,能回溯並指出是「哪一個自定義節點」發起的調用。

4. **整合式 UI 報告**:
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
   * `whitelist_edit`: 直接在 UI 節點編輯白名單規則（會覆寫 `monitor_whitelist.txt`）。
   * `custom_path`: 指定要掃描的目標資料夾（預設為 `custom_nodes`）。

3. **白名單配置**

如果您發現某些受信任的節點頻繁觸發誤報（例如某些數學節點合法使用 `eval`），您可以將其加入白名單以屏蔽警報。

**選項 A: 介面編輯 (新增)**
1. 在節點設定與輸入區找到 `whitelist_edit` 文字框。
2. 直接輸入或貼上您的規則。
3. 執行節點以儲存並套用。
   * *注意*: 若留空則保留既有規則。

**選項 B: 手動編輯文件**

1.  打開節點根目錄下的 `monitor_whitelist.txt` 文件。
2.  按照格式 `節點資料夾名稱: 行為` 新增規則。
    * **範例**: `ComfyUI_smZNodes: eval` (忽略該節點的 `eval` 警告)。
    * **忽略所有**: `ComfyUI-Manager: *` (忽略該節點的所有行為)。
3.  **熱重載**: 修改後無需重啟 ComfyUI，只需在介面上切換 **"realtime_monitor"** 開關（開啟 -> 關閉 -> 開啟）即可立即套用新規則。

### 可檢測的風險 (範例)

* **嚴重 (Critical)**: 鍵盤側錄 (`pynput`)、遠端控制工具引用、不安全反序列化 (`pickle`)、隱藏導入 (`__import__`)、底層調用 (`ctypes`)。
* **高危 (High)**: 系統 Shell 指令 (`os.system`, `subprocess.run`)、動態代碼執行 (`eval`, `exec`)、Base64 隱藏代碼。
* **警告 (Warning)**: 檔案刪除 (`rmtree`)、網絡數據上傳 (`POST` 請求)、Socket 底層連線。

### ⚠️ 免責聲明與限制 (重要)

**使用前請務必仔細閱讀：**

1.  **非防毒軟體**: 本工具僅為 Python 層面的腳本分析器，**無法檢測** 隱藏在編譯文件（`.pyd`, `.so`, `.dll`）中的惡意代碼，也無法防禦零日漏洞 (Zero-day exploits)。

2.  **可能被繞過**: 高級攻擊者可能使用複雜的混淆技術或底層 C 語言調用來繞過 AST 掃描與運行時監控。

3.  **準確性與驗證**: 掃描結果**可能包含誤判**（將安全代碼標記為風險）或**漏報**（未能發現真實威脅）。使用者應**自行查證**掃描結果。請勿完全依賴本工具作為安全決策的唯一依據。

4.  **運行風險**: 運行時監控涉及攔截系統底層調用。雖然我們已盡力確保安全，但在極少數情況下可能會與某些特定節點發生衝突或導致不穩定。

5.  **免責聲明**:
    * 本專案採用**MIT License**開源授權，依照授權條款，軟體以「現狀」（AS IS）提供，不附帶任何明示或暗示的保證。
    * 開發者**不承擔**因使用或濫用本工具而導致的一切法律與賠償責任，包括但不限於：
      - 直接或間接損失
      - 資料遺失或損毀
      - 硬體設備損壞
      - 安全性漏洞或隱私洩露
      - 業務中斷或其他商業損失 

   **使用者須知**
    * 使用前，強烈建議進行充分測試，並備份重要資料。
    * 為了最高等級的安全，建議在隔離環境（Docker/VM）中運行 ComfyUI。