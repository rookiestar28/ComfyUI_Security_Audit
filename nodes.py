# nodes.py
import os
import folder_paths
from .scanner_core import execute_scan, format_ui_report
from . import monitor

UI_TEXT = {
    "en": {
        "status_active": "🟢 Active (Async Monitored)",
        "status_inactive": "⚪ Inactive",
        "monitor_title": "🛡️ Real-time Monitor",
        "log_file": "📂 Log File",
        "recent_logs": "📋 Recent {} logs:",
        "no_logs": "(No logs found)",
        "read_fail": "Failed to read log: {}",
        "scan_title": "\n🔍 AST Static Analysis Report:"
    },
    "zh": {
        "status_active": "🟢 運行中 (含異步監控)",
        "status_inactive": "⚪ 已停用 (Inactive)",
        "monitor_title": "🛡️ 即時行為監控",
        "log_file": "📂 日誌文件",
        "recent_logs": "📋 最近 {} 筆操作紀錄:",
        "no_logs": "(尚無日誌記錄)",
        "read_fail": "讀取日誌失敗: {}",
        "scan_title": "\n🔍 AST 靜態代碼分析報告:"
    }
}

class AuditScannerNode:
    @classmethod
    def INPUT_TYPES(s):
        return {
            "required": {
                "scan_trigger": ("INT", {"default": 0, "min": 0, "max": 0xffffffffffffffff}),
                "language": (["English", "Traditional Chinese"], {"default": "English"}),
                "realtime_monitor": (["DISABLE", "ENABLE"], {"default": "DISABLE"}),
                "show_recent_logs": ("INT", {"default": 20, "min": 0, "max": 100}),
            },
            "optional": {
                "custom_path": ("STRING", {"multiline": False, "default": "custom_nodes"}),
                "whitelist_edit": ("STRING", {"multiline": True, "default": "", "placeholder": "Format: NodeName: action1, action2\n(Leave empty to keep existing)"}),
            }
        }

    RETURN_TYPES = ("STRING",)
    RETURN_NAMES = ("report_text",)
    FUNCTION = "scan_nodes"
    OUTPUT_NODE = True
    CATEGORY = "🛡️ Security"

    def scan_nodes(self, scan_trigger, language, realtime_monitor, show_recent_logs, custom_path="custom_nodes", whitelist_edit=""):
        lang_code = "zh" if language == "Traditional Chinese" else "en"
        t = UI_TEXT[lang_code]
        
        # Handle Whitelist Update
        if whitelist_edit.strip():
            try:
                whitelist_path = os.path.join(os.path.dirname(__file__), "monitor_whitelist.txt")
                with open(whitelist_path, "w", encoding="utf-8") as f:
                    f.write(whitelist_edit)
                # Force reload rules
                monitor.load_whitelist_from_file()
            except Exception as e:
                print(f"[Security Audit] Failed to save whitelist: {e}")

        monitor_active = (realtime_monitor == "ENABLE")
        monitor.set_config(monitor_active, lang_code)
        
        output_text = []
        
        status = t["status_active"] if monitor_active else t["status_inactive"]
        output_text.append(f"{t['monitor_title']}: {status}")
        
        # Display current whitelist
        current_whitelist = ""
        try:
             whitelist_path = os.path.join(os.path.dirname(__file__), "monitor_whitelist.txt")
             if os.path.exists(whitelist_path):
                 with open(whitelist_path, "r", encoding="utf-8") as f:
                     current_whitelist = f.read().strip()
        except: pass
        
        if current_whitelist:
            output_text.append(f"\n[Whitelist Rules Loaded]\n{current_whitelist}\n")

        output_text.append(f"{t['log_file']}: security_audit.log")
        output_text.append("=" * 50)

        log_file = "security_audit.log"
        if os.path.exists(log_file):
            output_text.append(t["recent_logs"].format(show_recent_logs))
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                    last_n = lines[-show_recent_logs:][::-1]
                    for line in last_n:
                        output_text.append(line.strip())
            except Exception as e:
                output_text.append(t["read_fail"].format(e))
        else:
            output_text.append(t["no_logs"])

        output_text.append("=" * 50)
        
        output_text.append(t["scan_title"])
        base_path = folder_paths.base_path
        target_dir = os.path.join(base_path, custom_path)
        if not os.path.exists(target_dir):
            target_dir = custom_path
            
        if os.path.exists(target_dir):
            grouped_issues, stats = execute_scan(target_dir)
            scan_report = format_ui_report(grouped_issues, stats, target_dir, lang=lang_code)
            output_text.append(scan_report)
        
        final_text = "\n".join(output_text)

        return (final_text, {"ui": {"text": [final_text]}})

NODE_CLASS_MAPPINGS = {
    "ComfyUI_Security_Audit": AuditScannerNode
}
NODE_DISPLAY_NAME_MAPPINGS = {
    "ComfyUI_Node_Audit": "🛡️ ComfyUI Security Audit"
}