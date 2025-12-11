# monitor.py
import os
import sys
import builtins
import subprocess
import inspect
import logging
import threading
import time
from datetime import datetime

LOG_FILENAME = "security_audit.log"
WHITELIST_FILENAME = "monitor_whitelist.txt"

_monitor_lock = threading.Lock()
_config = {
    "enabled": False,
    "lang": "en"
}
HOOKS_INSTALLED = False
WHITELIST_RULES = {} 

_log_throttle = {} 
THROTTLE_SECONDS = 3.0 

LOG_MESSAGES = {
    "en": {
        "log_fmt": "[Node: {node}] [Action: {action}] [Target: {target}] [File: {file}:{line}]",
        "term_title": "[Security Monitor]",
        "monitor_on": "[Security] Real-time Monitor: ON (Whitelist loaded)",
        "monitor_off": "[Security] Real-time Monitor: OFF",
        "actions": {
            "os_system": "System Command (os.system)",
            "os_popen": "System Command (os.popen)",
            "subprocess": "Subprocess Call",
            "eval": "Dynamic Code (eval)",
            "exec": "Dynamic Code (exec)",
            "rmtree": "Delete Directory",
            "remove": "Delete File",
            "post": "Network Upload (POST)",
            "urlopen": "Network Request (urllib)",
            "aiohttp": "Async Network Request (aiohttp)"
        }
    },
    "zh": {
        "log_fmt": "[節點: {node}] [行為: {action}] [對象: {target}] [文件: {file}:{line}]",
        "term_title": "[安全監控]",
        "monitor_on": "[Security] 即時監控已開啟 (白名單已載入)",
        "monitor_off": "[Security] 即時監控已關閉",
        "actions": {
            "os_system": "執行系統指令 (os.system)",
            "os_popen": "執行系統指令 (os.popen)",
            "subprocess": "調用子進程 (subprocess)",
            "eval": "動態代碼執行 (eval)",
            "exec": "動態代碼執行 (exec)",
            "rmtree": "刪除目錄 (rmtree)",
            "remove": "刪除文件 (remove)",
            "post": "網絡請求 (POST)",
            "urlopen": "網絡請求 (urllib)",
            "aiohttp": "異步網絡請求 (aiohttp)"
        }
    }
}

logging.basicConfig(
    filename=LOG_FILENAME,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    encoding='utf-8'
)

class Colors:
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    ENDC = '\033[0m'

_orig = {
    "os_system": os.system,
    "os_popen": os.popen,
    "os_remove": os.remove,
    "subprocess_call": subprocess.call,
    "subprocess_Popen": subprocess.Popen,
    "eval": builtins.eval,
    "exec": builtins.exec,
    "shutil_rmtree": None,
    "requests_post": None,
    "urllib_urlopen": None,
    "aiohttp_request": None 
}

try:
    import shutil
    _orig["shutil_rmtree"] = shutil.rmtree
except ImportError: pass

try:
    import requests
    _orig["requests_post"] = requests.post
except ImportError: pass

try:
    import urllib.request
    _orig["urllib_urlopen"] = urllib.request.urlopen
except ImportError: pass

try:
    import aiohttp
    _orig["aiohttp_request"] = aiohttp.ClientSession._request
except ImportError: pass


def load_whitelist_from_file():
    """從 txt 文件讀取白名單配置"""
    global WHITELIST_RULES
    rules = {}
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, WHITELIST_FILENAME)
    
    if not os.path.exists(file_path):
        return

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                if ":" in line:
                    parts = line.split(":", 1)
                    node_name = parts[0].strip()
                    actions_str = parts[1].strip()
                    
                    if not node_name or not actions_str:
                        continue
                        
                    actions = [a.strip() for a in actions_str.split(",")]
                    rules[node_name] = actions
        
        WHITELIST_RULES = rules
    except Exception as e:
        print(f"{Colors.RED}[Security] Failed to load whitelist: {e}{Colors.ENDC}")

def set_config(enable: bool, lang: str = "en"):
    with _monitor_lock:
        _config["enabled"] = enable
        _config["lang"] = lang if lang in ["en", "zh"] else "en"
        
        if enable:
            install_hooks()
            load_whitelist_from_file()

        msgs = LOG_MESSAGES[_config["lang"]]
        status_msg = msgs["monitor_on"] if enable else msgs["monitor_off"]
        print(f"{Colors.YELLOW}{status_msg}{Colors.ENDC}")

def get_node_attribution():
    try:
        stack = inspect.stack()
        for frame in stack:
            filename = frame.filename
            if "monitor.py" in filename or "logging" in filename:
                continue
            if "custom_nodes" in filename:
                parts = filename.replace("\\", "/").split("custom_nodes/")
                if len(parts) > 1:
                    sub_path = parts[1]
                    node_name = sub_path.split("/")[0]
                    return node_name, filename, frame.lineno
        return "Unknown/ComfyUI-Core", "N/A", 0
    except Exception:
        return "TraceError", "Unknown", 0

def log_event(action_key, target_info):
    if not _config["enabled"]:
        return

    node_name, file_path, line_no = get_node_attribution()
    
    if node_name in WHITELIST_RULES:
        allowed_actions = WHITELIST_RULES[node_name]
        if "*" in allowed_actions or action_key in allowed_actions:
            return 

    current_time = time.time()
    throttle_key = (node_name, action_key)
    
    if throttle_key in _log_throttle:
        last_time = _log_throttle[throttle_key]
        if current_time - last_time < THROTTLE_SECONDS:
            return

    _log_throttle[throttle_key] = current_time

    msgs = LOG_MESSAGES[_config["lang"]]
    action_text = msgs["actions"].get(action_key, action_key)
    
    log_msg = msgs["log_fmt"].format(
        node=node_name, action=action_text, target=target_info, file=os.path.basename(file_path), line=line_no
    )
    logging.info(log_msg)

    title = msgs["term_title"]
    print(f"{Colors.RED}{title}{Colors.ENDC} {Colors.CYAN}{node_name}{Colors.ENDC} -> {Colors.YELLOW}{action_text}{Colors.ENDC}")
    print(f"  └── Info: {target_info}")


def hooked_os_system(command):
    log_event("os_system", f"Cmd: {command}")
    return _orig["os_system"](command)

def hooked_os_popen(cmd, *args, **kwargs):
    log_event("os_popen", f"Cmd: {cmd}")
    return _orig["os_popen"](cmd, *args, **kwargs)

def hooked_subprocess_call(args, *vargs, **kwargs):
    log_event("subprocess", f"Args: {str(args)}")
    return _orig["subprocess_call"](args, *vargs, **kwargs)

def hooked_subprocess_Popen(args, *vargs, **kwargs):
    log_event("subprocess", f"Args: {str(args)}")
    return _orig["subprocess_Popen"](args, *vargs, **kwargs)

def hooked_eval(source, *args, **kwargs):
    code = str(source)[:100].replace("\n", " ")
    log_event("eval", f"Code: {code}...")
    return _orig["eval"](source, *args, **kwargs)

def hooked_exec(source, *args, **kwargs):
    log_event("exec", "Dynamic Code Block")
    return _orig["exec"](source, *args, **kwargs)

def hooked_shutil_rmtree(path, *args, **kwargs):
    log_event("rmtree", f"Path: {path}")
    return _orig["shutil_rmtree"](path, *args, **kwargs)

def hooked_os_remove(path, *args, **kwargs):
    log_event("remove", f"Path: {path}")
    return _orig["os_remove"](path, *args, **kwargs)

def hooked_requests_post(url, *args, **kwargs):
    log_event("post", f"URL: {url}")
    return _orig["requests_post"](url, *args, **kwargs)

def hooked_urllib_urlopen(url, *args, **kwargs):
    target = url.get_full_url() if hasattr(url, 'get_full_url') else str(url)
    log_event("urlopen", f"URL: {target}")
    return _orig["urllib_urlopen"](url, *args, **kwargs)

async def hooked_aiohttp_request(self, method, str_or_url, *args, **kwargs):
    if method.upper() in ["POST", "PUT", "DELETE", "GET"]:
        log_event("aiohttp", f"[{method}] {str_or_url}")
    return await _orig["aiohttp_request"](self, method, str_or_url, *args, **kwargs)


def install_hooks():
    global HOOKS_INSTALLED
    if HOOKS_INSTALLED: return

    os.system = hooked_os_system
    os.popen = hooked_os_popen
    os.remove = hooked_os_remove
    subprocess.call = hooked_subprocess_call
    subprocess.Popen = hooked_subprocess_Popen
    builtins.eval = hooked_eval
    builtins.exec = hooked_exec
    
    if _orig["shutil_rmtree"]:
        import shutil
        shutil.rmtree = hooked_shutil_rmtree
        
    if _orig["requests_post"]:
        import requests
        requests.post = hooked_requests_post
        
    if _orig["urllib_urlopen"]:
        import urllib.request
        urllib.request.urlopen = hooked_urllib_urlopen

    if _orig["aiohttp_request"]:
        import aiohttp
        aiohttp.ClientSession._request = hooked_aiohttp_request

    HOOKS_INSTALLED = True
    load_whitelist_from_file()
    print(f"{Colors.GREEN}[Security] Monitor hooks installed (Smart Throttling Enabled).{Colors.ENDC}")

# install_hooks()  <-- Removed auto-install