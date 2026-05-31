"""Zhuque CLI — text and image AI detection with auto-cooldown."""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path
from typing import Any

from matrix_ai_cli.captcha import captcha_ticket_pure
from matrix_ai_cli.text_detect import detect_with_ticket
from matrix_ai_cli.transport import build_ws_headers, make_fp
from matrix_ai_cli.media_detect import detect_media_with_ticket
from matrix_ai_cli.config import CAPTCHA_ENTRY_URL

BURST_LIMIT = 18
COOLDOWN_SEC = 1800
INTER_REQUEST_SEC = 5


def _random_xff() -> str:
    return f"10.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _detect_text(text: str, xff: str = "") -> dict[str, Any]:
    xff = xff or _random_xff()
    fp = make_fp()
    r = captcha_ticket_pure(
        timeout=30, wait_ms=1500,
        entry_url=CAPTCHA_ENTRY_URL, xff=xff,
    )
    payload = r.get("payload", {})
    if not payload:
        return {"ok": False, "error": "ticket_failed", "detail": r.get("verify_summary", {})}
    headers = build_ws_headers(xff=xff)
    report = detect_with_ticket(
        text=text, fp=fp,
        ticket=payload["ticket"], randstr=payload["randstr"],
        timeout=60, order="fp-ticket-text",
        additional_headers=headers, text_send_mode="on-code",
    )
    result = report.get("result") or {}
    if result.get("status") == "success" and "confidence" in result:
        return {"ok": True, "type": "text", **result}
    evil = result.get("evil_level")
    if evil == "100":
        return {"ok": False, "error": "rate_limited", "evil_level": 100}
    return {"ok": False, "error": result.get("msg") or result.get("status") or "unknown", "raw": result}


def _detect_image(image_path: Path, xff: str = "") -> dict[str, Any]:
    xff = xff or _random_xff()
    fp = make_fp()
    r = captcha_ticket_pure(
        timeout=30, wait_ms=1500,
        entry_url="https://matrix.tencent.com/ai-detect/ai_gen", xff=xff,
    )
    payload = r.get("payload", {})
    if not payload:
        return {"ok": False, "error": "ticket_failed", "file": str(image_path)}
    image_bytes = image_path.read_bytes()
    headers = build_ws_headers(xff=xff)
    result = detect_media_with_ticket(
        media_type="image", fp=fp,
        ticket=payload["ticket"], randstr=payload["randstr"],
        timeout=60, additional_headers=headers,
        image_bytes=image_bytes, media_send_mode="on-code",
    )
    inner = result.get("result") or result if isinstance(result, dict) else {}
    if isinstance(inner, dict) and inner.get("ai_generated") is not None and inner.get("status") == "success":
        return {"ok": True, "type": "image", "file": str(image_path), "ai_generated": inner["ai_generated"], "availableUses": inner.get("availableUses"), "img_type": inner.get("img_type"), "uuid": inner.get("uuid")}
    # Check evil_level in result or in logs
    evil = None
    if isinstance(inner, dict):
        evil = inner.get("evil_level")
    if not evil and isinstance(result, dict):
        for log in (result.get("logs") or []):
            recv = log.get("recv") or {}
            if recv.get("evil_level") == "100":
                evil = "100"
                break
    if evil == "100":
        return {"ok": False, "error": "rate_limited", "evil_level": 100, "file": str(image_path)}
    return {"ok": False, "error": "detect_failed", "file": str(image_path), "raw": result}


def _run_batch(items: list[tuple[str, Any]], detect_fn) -> list[dict[str, Any]]:
    """Run batch with auto-cooldown. items = [(label, arg), ...]"""
    results = []
    consecutive = 0
    for i, (label, arg) in enumerate(items):
        if consecutive >= BURST_LIMIT:
            msg = f"Rate limit reached ({BURST_LIMIT} requests). Cooling down {COOLDOWN_SEC}s..."
            print(json.dumps({"event": "cooldown", "after": consecutive, "wait_sec": COOLDOWN_SEC}), file=sys.stderr)
            time.sleep(COOLDOWN_SEC)
            consecutive = 0

        r = detect_fn(arg)
        results.append(r)
        print(json.dumps(r, ensure_ascii=False), flush=True)

        if r.get("error") == "rate_limited":
            print(json.dumps({"event": "cooldown", "reason": "evil100", "wait_sec": COOLDOWN_SEC}), file=sys.stderr)
            time.sleep(COOLDOWN_SEC)
            consecutive = 0
            # retry this one
            r2 = detect_fn(arg)
            results[-1] = r2
            print(json.dumps(r2, ensure_ascii=False), flush=True)
            if r2.get("ok"):
                consecutive += 1
        elif r.get("ok"):
            consecutive += 1
        else:
            consecutive += 1

        if i < len(items) - 1:
            time.sleep(INTER_REQUEST_SEC)

    return results


def cmd_check(args: argparse.Namespace) -> int:
    if args.image:
        r = _detect_image(Path(args.image))
    elif args.image_dir:
        d = Path(args.image_dir)
        images = sorted(p for p in d.rglob("*") if p.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".bmp"))
        if not images:
            print(json.dumps({"ok": False, "error": "no_images_found", "dir": str(d)}))
            return 1
        items = [(str(p), p) for p in images]
        _run_batch(items, _detect_image)
        return 0
    elif args.file:
        text = Path(args.file).read_text(encoding="utf-8")
        r = _detect_text(text)
    elif args.text:
        r = _detect_text(args.text)
    else:
        print(json.dumps({"ok": False, "error": "no_input", "hint": "provide --text, --file, --image, or --image-dir"}))
        return 1
    print(json.dumps(r, ensure_ascii=False))
    return 0 if r.get("ok") else 1


def cmd_batch(args: argparse.Namespace) -> int:
    manifest = Path(args.manifest)
    if not manifest.exists():
        print(json.dumps({"ok": False, "error": "manifest_not_found", "path": str(manifest)}))
        return 1
    lines = [l.strip() for l in manifest.read_text(encoding="utf-8").splitlines() if l.strip()]
    if not lines:
        print(json.dumps({"ok": False, "error": "empty_manifest"}))
        return 1
    # detect type by extension
    first = Path(lines[0])
    if first.suffix.lower() in (".png", ".jpg", ".jpeg", ".webp", ".bmp"):
        items = [(l, Path(l)) for l in lines]
        _run_batch(items, _detect_image)
    else:
        items = [(l, Path(l).read_text(encoding="utf-8")) for l in lines]
        _run_batch(items, _detect_text)
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    checks: dict[str, Any] = {}
    try:
        from matrix_ai_cli.captcha import captcha_prehandle
        pre = captcha_prehandle(timeout=10, entry_url=CAPTCHA_ENTRY_URL)
        checks["captcha_reachable"] = bool((pre.get("response") or {}).get("sess"))
    except Exception as e:
        checks["captcha_reachable"] = False
        checks["captcha_error"] = str(e)
    try:
        from matrix_ai_cli.text_detect import handshake_only
        fp = make_fp()
        r = handshake_only(fp)
        checks["ws_reachable"] = True
    except Exception as e:
        checks["ws_reachable"] = False
        checks["ws_error"] = str(e)
    checks["ok"] = checks.get("captcha_reachable", False) and checks.get("ws_reachable", False)
    print(json.dumps(checks, ensure_ascii=False, indent=2))
    return 0 if checks["ok"] else 1


def main():
    parser = argparse.ArgumentParser(prog="zhuque", description="Tencent Zhuque AI detection")
    sub = parser.add_subparsers(dest="command")

    p_check = sub.add_parser("check", help="Detect text or image")
    p_check.add_argument("text", nargs="?", help="Text to check (inline)")
    p_check.add_argument("--file", "-f", help="Text file path")
    p_check.add_argument("--image", "-i", help="Image file path")
    p_check.add_argument("--image-dir", "-d", help="Directory of images (batch)")
    p_check.set_defaults(func=cmd_check)

    p_batch = sub.add_parser("batch", help="Batch detect from manifest file (one path per line)")
    p_batch.add_argument("manifest", help="File listing paths (text files or images)")
    p_batch.set_defaults(func=cmd_batch)

    p_doc = sub.add_parser("doctor", help="Verify environment")
    p_doc.set_defaults(func=cmd_doctor)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main() or 0)
