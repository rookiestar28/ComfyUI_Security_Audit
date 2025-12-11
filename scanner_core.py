# scanner_core.py
import os
import ast
import time
from collections import defaultdict
from datetime import datetime

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

AST_RISKS = {
    "os.system": {"score": 10, "level": "HIGH", "desc": {"en": "Shell Command (os.system)", "zh": "執行系統指令 (os.system)"}},
    "os.popen": {"score": 10, "level": "HIGH", "desc": {"en": "Shell Command (os.popen)", "zh": "執行系統指令 (os.popen)"}},
    "subprocess.call": {"score": 9, "level": "HIGH", "desc": {"en": "Subprocess Call", "zh": "調用系統子進程"}},
    "subprocess.Popen": {"score": 9, "level": "HIGH", "desc": {"en": "Subprocess Popen", "zh": "調用系統子進程"}},
    "eval": {"score": 10, "level": "HIGH", "desc": {"en": "Dynamic Code (eval)", "zh": "動態代碼執行 (eval)"}},
    "exec": {"score": 10, "level": "HIGH", "desc": {"en": "Dynamic Code (exec)", "zh": "動態代碼執行 (exec)"}},
    "base64.b64decode": {"score": 8, "level": "HIGH", "desc": {"en": "Base64 Decoding", "zh": "Base64 解碼 (可能隱藏代碼)"}},
    "shutil.rmtree": {"score": 3, "level": "WARNING", "desc": {"en": "Recursive Delete", "zh": "遞迴刪除目錄"}},
    "requests.post": {"score": 2, "level": "WARNING", "desc": {"en": "HTTP POST", "zh": "發送 POST 請求"}},
    "urllib.request.urlopen": {"score": 2, "level": "WARNING", "desc": {"en": "URL Open", "zh": "打開網絡連結"}},
    "pynput": {"score": 10, "level": "CRITICAL", "desc": {"en": "Keylogger Lib (pynput)", "zh": "引用鍵盤監聽庫 (pynput)"}, "type": "import"},
    "subprocess.run": {"score": 9, "level": "HIGH", "desc": {"en": "Subprocess Run", "zh": "執行子進程 (subprocess.run)"}},
    "__import__": {"score": 9, "level": "CRITICAL", "desc": {"en": "Dynamic Import", "zh": "動態導入 (__import__)"}},
    "getattr": {"score": 6, "level": "WARNING", "desc": {"en": "Dynamic Attribute Access", "zh": "動態屬性訪問 (getattr)"}},
    "pickle.loads": {"score": 10, "level": "CRITICAL", "desc": {"en": "Unsafe Deserialization", "zh": "不安全反序列化 (pickle.loads)"}},
    "ctypes": {"score": 9, "level": "CRITICAL", "desc": {"en": "Low-level C Bindings", "zh": "底層 C 語言調用 (ctypes)"}, "type": "import"}
}

UI_STRINGS = {
    "en": {
        "report_title": "📊 ComfyUI Node Security Report (AST Engine)",
        "scan_stats": "Total Files: {} | Risky Nodes: {} | Cache Hits: {}",
        "time": "Time", "path": "Path", "count": "Count",
        "folded": "... ({} more items hidden)",
        "path_err": "Path does not exist"
    },
    "zh": {
        "report_title": "📊 ComfyUI 節點安全審計報告 (AST 引擎)",
        "scan_stats": "總文件: {} | 風險節點: {} | 緩存命中: {}",
        "time": "時間", "path": "掃描路徑", "count": "數量",
        "folded": "... (還有 {} 筆已隱藏)",
        "path_err": "路徑不存在"
    }
}

_SCAN_CACHE = {}

class SecurityVisitor(ast.NodeVisitor):
    def __init__(self):
        self.issues = []

    def visit_Call(self, node):
        """檢查函數調用"""
        func_name = self._get_func_name(node.func)
        if func_name in AST_RISKS and "type" not in AST_RISKS[func_name]:
            risk = AST_RISKS[func_name]
            self.issues.append({
                "line": node.lineno,
                "risk": risk,
                "code": f"Call: {func_name}(...)"
            })
        self.generic_visit(node)

    def visit_Import(self, node):
        """檢查 import"""
        for alias in node.names:
            if alias.name in AST_RISKS:
                risk = AST_RISKS[alias.name]
                if risk.get("type") == "import":
                    self.issues.append({
                        "line": node.lineno,
                        "risk": risk,
                        "code": f"Import: {alias.name}"
                    })
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        """檢查 from ... import"""
        if node.module and node.module in AST_RISKS:
            risk = AST_RISKS[node.module]
            if risk.get("type") == "import":
                 self.issues.append({
                    "line": node.lineno,
                    "risk": risk,
                    "code": f"From Import: {node.module}"
                })
        self.generic_visit(node)

    def _get_func_name(self, node):
        """遞迴解析函數名稱 (例如 os.path.join)"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_func_name(node.value)}.{node.attr}"
        return ""

def get_node_name(root_dir, file_path):
    rel_path = os.path.relpath(file_path, root_dir)
    parts = rel_path.split(os.sep)
    return parts[0] if len(parts) > 1 else "Root"

def analyze_file(file_path):
    """讀取文件並進行 AST 分析 (帶緩存)"""
    global _SCAN_CACHE
    try:
        mtime = os.path.getmtime(file_path)
        
        if file_path in _SCAN_CACHE:
            entry = _SCAN_CACHE[file_path]
            if entry['mtime'] == mtime:
                return entry['issues'], True # True = Cache Hit

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        tree = ast.parse(content)
        visitor = SecurityVisitor()
        visitor.visit(tree)
        
        _SCAN_CACHE[file_path] = {
            'mtime': mtime,
            'issues': visitor.issues
        }
        return visitor.issues, False

    except (SyntaxError, Exception):
        return [], False

def execute_scan(target_dir):
    grouped_issues = defaultdict(list)
    stats = {
        "total_files": 0, 
        "risky_nodes": set(), 
        "cache_hits": 0
    }
    
    if not os.path.exists(target_dir):
        return None, "PATH_ERROR"

    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                stats["total_files"] += 1
                file_path = os.path.join(root, file)
                node_name = get_node_name(target_dir, file_path)
                
                issues, is_hit = analyze_file(file_path)
                if is_hit:
                    stats["cache_hits"] += 1
                
                if issues:
                    stats["risky_nodes"].add(node_name)
                    for issue in issues:
                        risk = issue['risk']
                        key = (risk["score"], risk["level"], str(risk)) 

                        dict_key = (risk["score"], risk["level"], risk["desc"]["en"]) 
                        
                        grouped_issues[dict_key].append({
                            "node": node_name,
                            "file": os.path.relpath(file_path, target_dir),
                            "line": issue["line"],
                            "code": issue["code"],
                            "desc_obj": risk["desc"] 
                        })

    return grouped_issues, stats

def format_ui_report(grouped_issues, stats, scan_path, lang="en"):
    if stats == "PATH_ERROR":
        return UI_STRINGS[lang]["path_err"]

    t = UI_STRINGS[lang]
    output = []
    output.append(t['report_title'])
    output.append(f"{t['time']}: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    output.append(f"{t['path']}: {scan_path}")
    output.append("-" * 50)
    output.append(t['scan_stats'].format(stats['total_files'], len(stats['risky_nodes']), stats['cache_hits']))
    output.append("=" * 50)

    sorted_keys = sorted(grouped_issues.keys(), key=lambda x: x[0], reverse=True)

    for key in sorted_keys:
        score, level, _ = key
        items = grouped_issues[key]
        desc = items[0]["desc_obj"][lang]
        
        prefix = "🛑 [HIGH/CRITICAL]" if level in ["CRITICAL", "HIGH"] else "⚠️ [WARNING]"
        output.append(f"\n{prefix} {desc}")
        output.append(f"{t['count']}: {len(items)}")
        
        items.sort(key=lambda x: x['node'])
        display_limit = 9999 if level in ["CRITICAL", "HIGH"] else 10
        
        for item in items[:display_limit]:
            output.append(f"  • {item['node']}")
            output.append(f"    📄 {item['file']} (Line {item['line']})")
            output.append(f"    💻 {item['code']}")
            
        if len(items) > display_limit:
            output.append(f"    {t['folded'].format(len(items) - display_limit)}")

    return "\n".join(output)

def format_console_output(grouped_issues, stats, lang="en"):
    pass