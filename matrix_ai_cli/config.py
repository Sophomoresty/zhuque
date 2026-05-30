"""Configuration constants and environment helpers for matrix-ai-cli."""
from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Any

# --- URLs ---
WS_URL = "wss://matrix.tencent.com/ai_gen_txt_server/getClassify"
PIC_WS_URL = "wss://matrix.tencent.com/pic_server/ai_gen"
HTTP_BASE = "https://matrix.tencent.com"
MATRIX_TXT_URL = "https://matrix.tencent.com/ai-detect/ai_gen_txt"
MATRIX_PIC_URL = "https://matrix.tencent.com/ai-detect/ai_gen"
COS_PATH = "https://secbench-1258476245.cos.ap-guangzhou.myqcloud.com/"

# --- Defaults ---
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)
DEFAULT_REFERER = "https://matrix.tencent.com/ai-detect/ai_gen_txt"
DEFAULT_BOUND = "matrix-ai"
DEFAULT_MEDIA_BOUND = "matrix-risk"
AGENT_BROWSER_CLI = "agent-browser-cli"
AGENT_BROWSER_STATE_FILE = (
    Path.home() / ".local" / "share" / "agent-browser-cli" / "bridge-state.json"
)
VIDEO_CHUNK_SIZE = 10 * 1024 * 1024
DEFAULT_MEDIA_XFF = os.environ.get(
    "MATRIX_AI_MEDIA_XFF",
    f"10.214.{int(time.time()) % 240}.{os.getpid() % 240 + 1}",
)
DEFAULT_MEDIA_ROTATE_XFF = (
    os.environ.get("MATRIX_AI_MEDIA_ROTATE_XFF")
    or f"10.214.{(int(time.time()) // 60) % 240}.{{i}}"
)
FP_RE = re.compile(r"\b[a-f0-9]{32}\b")

# --- Windows LevelDB paths (env-driven, no hardcoded usernames) ---
_WIN_USER = os.environ.get("MATRIX_AI_WIN_USER", "")
_WIN_HOME = Path(f"/mnt/c/Users/{_WIN_USER}") if _WIN_USER else None


def _win_codex_chrome_leveldb() -> Path | None:
    if _WIN_HOME is None:
        return None
    return _WIN_HOME / "AppData" / "Local" / "CodexChrome" / "Default" / "Local Storage" / "leveldb"


def _win_chrome_leveldb_roots() -> list[Path]:
    if _WIN_HOME is None:
        return []
    base = _WIN_HOME / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
    return [
        base / "Default" / "Local Storage" / "leveldb",
        base / "Profile 1" / "Local Storage" / "leveldb",
    ]


WINDOWS_CODEX_CHROME_LEVELDB: Path | None = _win_codex_chrome_leveldb()
WINDOWS_GOOGLE_CHROME_LEVELDB_ROOTS: list[Path] = _win_chrome_leveldb_roots()
CODEX_TASKS_ROOT = Path.home() / ".codex" / "tasks"

# --- Captcha ---
CAPTCHA_APPID = "2089775896"
CAPTCHA_API_BASE = "https://t.captcha.qq.com"
CAPTCHA_ENTRY_URL = MATRIX_TXT_URL
CAPTCHA_FRAME_JS = "/tcaptcha-frame.9ef230b0.js"
CAPTCHA_IFRAME_REFERER = "https://captcha.gtimg.com/"
CAPTCHA_CURL_IMPERSONATE = "chrome142"
TERROR_TICKET_APPID = CAPTCHA_APPID
TERROR_TICKET_ERROR_CODE = "1001"
CAPTCHA_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)

# --- Mutable global state ---
JSON_PARSER_ARGV: list[str] = []
EGRESS_META_CACHE: dict[str, dict[str, Any]] = {}
EGRESS_META_LOCK = threading.Lock()


def int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except Exception:
        return default
