"""Media (image/video) detection: CDP, pure WS, upload."""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import math
import mimetypes
import os
import random
import re
import string
import time
import zipfile
from pathlib import Path
from typing import Any

import requests
import websockets
import websockets.sync.client

from .config import (
    COS_PATH,
    DEFAULT_MEDIA_BOUND,
    DEFAULT_MEDIA_XFF,
    DEFAULT_UA,
    HTTP_BASE,
    MATRIX_PIC_URL,
    PIC_WS_URL,
    VIDEO_CHUNK_SIZE,
)
from .transport import (
    BrowserCdpConnection,
    agent_browser_action,
    agent_browser_close_tab,
    agent_browser_execute_js,
    agent_browser_open_new_tab,
    browser_cdp_eval,
    browser_cdp_wait_target_ready,
    browser_ws_endpoint,
    build_ws_headers,
    egress_meta,
    load_ticket_args,
    make_fp,
    make_fp_for_mode,
    normalize_cdp_context_proxy_server,
    recv_json,
    request_proxies,
    wait_browser_session_ready,
    ws_connect_kwargs_with_egress,
)
from .captcha import (
    CAPTCHA_ENTRY_URL,
    captcha_ticket_pure,
    extract_first_captcha_code,
    make_tdc_ft,
    make_tdc_profile,
)
from .text_detect import (
    captcha_risk_level,
    json_command_error,
    load_ticket_provider,
    TicketProviderError,
    write_json_file,
)
from .browser_state import ensure_matrix_media_bound


def make_image_zip_payload(image_bytes: bytes, *, arcname: str = "image.zip") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_STORED) as zf:
        zf.writestr(arcname, image_bytes)
    return buf.getvalue()



def strip_cos_path(cos_url: str) -> str:
    if cos_url.startswith(COS_PATH):
        return cos_url[len(COS_PATH):]
    return cos_url



def guess_file_mime(path: Path, fallback: str = "application/octet-stream") -> str:
    guessed, _encoding = mimetypes.guess_type(path.name)
    return guessed or fallback



def upload_video_file(
    video_path: Path,
    *,
    fp: str,
    xff: str = "",
    egress_proxy: str = "",
    timeout: float = 60.0,
    chunk_size: int = VIDEO_CHUNK_SIZE,
) -> dict[str, Any]:
    data = video_path.read_bytes()
    if not data:
        raise SystemExit(f"empty video file: {video_path}")
    total_chunks = max(1, math.ceil(len(data) / chunk_size))
    file_id = format(int(time.time() * 1000), "x") + "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    headers = {"fp": fp, "User-Agent": DEFAULT_UA}
    if xff:
        headers["X-Forwarded-For"] = xff
    upload_attempts: list[dict[str, Any]] = []
    mime = guess_file_mime(video_path, "video/mp4")
    for i in range(total_chunks):
        start = i * chunk_size
        end = min(start + chunk_size, len(data))
        chunk = data[start:end]
        form = {
            "filename": video_path.name,
            "fileId": file_id,
            "chunkIndex": str(i),
            "totalChunks": str(total_chunks),
            "chunkSize": str(chunk_size),
            "fileSize": str(len(data)),
        }
        resp = requests.post(
            HTTP_BASE + "/user/upload_video_chunk",
            headers=headers,
            data=form,
            files={"file": (video_path.name, chunk, mime)},
            proxies=request_proxies(egress_proxy),
            timeout=timeout,
        )
        try:
            parsed = resp.json()
        except Exception:
            parsed = {"raw": resp.text[:1000]}
        upload_attempts.append({"chunkIndex": i, "status_code": resp.status_code, "response": parsed})
        if resp.status_code != 200 or not parsed.get("success"):
            raise RuntimeError(f"video chunk upload failed at {i}: {parsed}")
    merge_resp = requests.post(
        HTTP_BASE + "/user/merge_video_chunks",
        headers=headers,
        json={
            "fileId": file_id,
            "filename": video_path.name,
            "totalChunks": total_chunks,
            "fileSize": len(data),
        },
        proxies=request_proxies(egress_proxy),
        timeout=timeout,
    )
    try:
        merge_parsed = merge_resp.json()
    except Exception:
        merge_parsed = {"raw": merge_resp.text[:1000]}
    cos_url = merge_parsed.get("cosURL") or (merge_parsed.get("data") or {}).get("cosURL") or ""
    if merge_resp.status_code != 200 or not cos_url:
        raise RuntimeError(f"video merge failed: {merge_parsed}")
    return {
        "file": str(video_path),
        "file_size": len(data),
        "mime": mime,
        "fp": fp,
        "xff": xff,
        "egress": egress_meta(egress_proxy) if egress_proxy else {"enabled": False},
        "fileId": file_id,
        "chunk_size": chunk_size,
        "totalChunks": total_chunks,
        "upload_attempts": upload_attempts,
        "merge": {"status_code": merge_resp.status_code, "response": merge_parsed},
        "cosURL": cos_url,
        "video_cos_url": strip_cos_path(cos_url),
    }



def detect_media_with_ticket(
    *,
    media_type: str,
    fp: str,
    ticket: str,
    randstr: str,
    timeout: float = 60.0,
    additional_headers: dict[str, str] | None = None,
    egress_proxy: str = "",
    image_bytes: bytes | None = None,
    video_cos_url: str = "",
    media_send_mode: str = "evil0-only",
) -> dict[str, Any]:
    if media_type not in {"image", "video"}:
        raise SystemExit(f"unsupported media_type: {media_type}")
    if not fp:
        raise SystemExit("missing fp for media detect")
    image_zip = b""
    if media_type == "image":
        if not image_bytes:
            raise SystemExit("missing image bytes")
        image_zip = make_image_zip_payload(image_bytes)
    else:
        if not video_cos_url:
            raise SystemExit("missing video_cos_url")
    logs: list[dict[str, Any]] = []
    final: dict[str, Any] | None = None
    payload_sent = False
    egress = egress_meta(egress_proxy)
    if media_send_mode not in {"evil0-only", "on-code"}:
        raise SystemExit(f"unsupported media_send_mode: {media_send_mode}")

    def should_send_after_code(msg: dict[str, Any]) -> bool:
        if msg.get("code") != "1":
            return False
        if media_send_mode == "on-code":
            return True
        return str(msg.get("evil_level") or "").strip() == "0"

    with websockets.sync.client.connect(
        PIC_WS_URL,
        **ws_connect_kwargs_with_egress(PIC_WS_URL, additional_headers, egress_proxy=egress_proxy, timeout=min(max(timeout, 10.0), 30.0)),
    ) as ws:
        ws.send(json.dumps({"fp": fp}, separators=(",", ":")))
        logs.append({"send": {"fp": fp}})
        first = recv_json(ws)
        logs.append({"recv": first})
        if first.get("status") != "success":
            return {
                "fp": fp,
                "media_type": media_type,
                "protocol_mode": "pure",
                "headers": additional_headers or {},
                "egress": egress,
                "media_send_mode": media_send_mode,
                "logs": logs,
                "payload_sent": False,
                "result": first,
            }
        ws.send(json.dumps({"ticket": ticket, "randstr": randstr}, separators=(",", ":")))
        logs.append({"send": {"ticket": "<ticket>", "randstr": randstr}})
        deadline = time.time() + timeout
        while time.time() < deadline:
            msg = recv_json(ws)
            logs.append({"recv": msg})
            if not payload_sent and should_send_after_code(msg):
                if media_type == "image":
                    ws.send(image_zip)
                    logs.append({
                        "send": {
                            "media_type": "image",
                            "zip_bytes": len(image_zip),
                            "zip_entry": "image.zip",
                            "send_mode": media_send_mode,
                            "after_code": msg.get("code"),
                            "after_evil_level": msg.get("evil_level"),
                        }
                    })
                else:
                    body = {"video_cos_url": video_cos_url, "data_type": "video"}
                    ws.send(json.dumps(body, separators=(",", ":")))
                    logs.append({
                        "send": {
                            "media_type": "video",
                            "video_cos_url": video_cos_url,
                            "data_type": "video",
                            "send_mode": media_send_mode,
                            "after_code": msg.get("code"),
                            "after_evil_level": msg.get("evil_level"),
                        }
                    })
                payload_sent = True
                continue
            if msg.get("code") and not (msg.get("code") == "1" and msg.get("evil_level") == "0"):
                final = msg
                break
            status = msg.get("status")
            if status == "waiting":
                continue
            if status in {"success", "failed", "limited", "reauth"}:
                final = msg
                break
        if final is None:
            final = {"status": "failed", "msg": "timeout waiting media result"}
    return {
        "fp": fp,
        "media_type": media_type,
        "protocol_mode": "pure",
        "headers": additional_headers or {},
        "egress": egress,
        "media_send_mode": media_send_mode,
        "logs": logs,
        "payload_sent": payload_sent,
        "result": final,
    }



def media_handshake_only(
    fp: str,
    *,
    additional_headers: dict[str, str] | None = None,
    egress_proxy: str = "",
    timeout: float = 15.0,
) -> dict[str, Any]:
    with websockets.sync.client.connect(
        PIC_WS_URL,
        open_timeout=timeout,
        close_timeout=min(timeout, 5.0),
        **ws_connect_kwargs_with_egress(PIC_WS_URL, additional_headers, egress_proxy=egress_proxy, timeout=timeout),
    ) as ws:
        ws.send(json.dumps({"fp": fp}, separators=(",", ":")))
        first = recv_json(ws)
        return {"fp": fp, "headers": additional_headers or {}, "egress": egress_meta(egress_proxy), "first": first}



def media_exit_code(report: dict[str, Any]) -> int:
    result = report.get("result") or {}
    media_type = str(report.get("media_type") or "")
    if media_type in {"image", "video"}:
        return 0 if result.get("status") == "success" and "ai_generated" in result and bool(report.get("payload_sent")) else 2
    return 0 if result.get("status") == "success" and "ai_generated" in result else 2



def media_failure_stage(report: dict[str, Any]) -> str:
    if media_exit_code(report) == 0:
        return ""
    cdp_result = report.get("cdp_result") or {}
    code_msg = extract_first_captcha_code(report)
    evil = str(code_msg.get("evil_level") or "").strip()
    if evil and evil != "0":
        return f"captcha-evil-level-{evil}"
    result = report.get("result") or {}
    status = str(result.get("status") or "").strip().lower()
    msg = str(result.get("msg") or result.get("msg_en") or "").strip().lower()
    if status == "handshake-failed" and msg == "invalid request":
        return "invalid-request"
    if "invalid request" in msg:
        return "invalid-request"
    if status == "success" and "ai_generated" in result and not report.get("payload_sent"):
        return "payload-not-sent"
    error_text = str(report.get("error") or msg or "").strip().lower()
    cdp_error_text = str(cdp_result.get("error") or "").strip().lower() if isinstance(cdp_result, dict) else ""
    if cdp_error_text == "component-not-found":
        media_tab = cdp_result.get("mediaTab") or {}
        if isinstance(media_tab, dict) and media_tab.get("clicked"):
            return "component-not-found-after-media-tab"
        return "component-not-found"
    if (
        "missing media ticket" in error_text
        or "missing input file" in error_text
        or "empty image file" in error_text
        or "empty video file" in error_text
        or "unsupported" in error_text
        or "missing fp" in error_text
    ):
        return "input-error"
    if "ticket" in msg or status == "ticket-rejected":
        return "ticket-rejected"
    if status:
        return status
    if result.get("msg") or result.get("msg_en"):
        return "detect-failed"
    return "detect-failed"



def media_risk_level_from_compact(item: dict[str, Any]) -> int:
    from .batch import batch_media_compact_failure_stage
    captcha = item.get("captcha") or {}
    evil = str(captcha.get("evil_level") or "").strip()
    if not evil:
        stage = str(item.get("failure_stage") or batch_media_compact_failure_stage(item) or "")
        match = re.search(r"captcha-evil-level-(\d+)", stage)
        evil = match.group(1) if match else ""
    try:
        return max(0, int(evil or 0))
    except Exception:
        return 0



def media_risk_event_from_compact(item: dict[str, Any]) -> dict[str, Any] | None:
    from .batch import batch_media_compact_failure_stage
    risk_level = media_risk_level_from_compact(item)
    if risk_level <= 0:
        return None
    return {
        "i": item.get("i"),
        "input_file": item.get("input_file"),
        "evil_level": str(risk_level),
        "failure_stage": batch_media_compact_failure_stage(item) or f"captcha-evil-level-{risk_level}",
        "xff": item.get("xff"),
        "status": item.get("status") or (item.get("result") or {}).get("status"),
        "msg": item.get("msg") or (item.get("result") or {}).get("msg") or (item.get("result") or {}).get("msg_en"),
        "report_json": item.get("report_json") or "",
    }



def media_risk_guard_config(args: argparse.Namespace) -> dict[str, Any]:
    risk_budget = max(0, int(getattr(args, "risk_budget", 0) or 0))
    cooldown_sec = max(0.0, float(getattr(args, "risk_cooldown_sec", 300.0) or 0.0))
    enabled = not bool(getattr(args, "no_risk_guard", False))
    return {
        "enabled": enabled,
        "risk_budget": risk_budget,
        "cooldown_recommended_sec": cooldown_sec,
        "action": "stop-before-next-item",
    }



def media_error_report(args: argparse.Namespace, media_type: str, error: BaseException | str) -> dict[str, Any]:
    input_file = str(getattr(args, "image_file", "") if media_type == "image" else getattr(args, "video_file", ""))
    input_size = None
    if input_file:
        with contextlib.suppress(OSError):
            input_size = Path(input_file).stat().st_size
    egress_proxy = str(getattr(args, "egress_proxy", "") or "")
    return {
        "fp": getattr(args, "fp", ""),
        "media_type": media_type,
        "protocol_mode": getattr(args, "driver", "pure"),
        "headers": build_ws_headers(xff=getattr(args, "xff", ""), headers=getattr(args, "header", [])),
        "egress": egress_meta(egress_proxy) if egress_proxy else {"enabled": False},
        "egress_scope": str(getattr(args, "egress_scope", "detect") or "detect"),
        "logs": [],
        "payload_sent": False,
        "result": {"status": "failed", "msg": str(error)},
        "error": str(error),
        "input_file": input_file,
        "input_size": input_size,
        "fp_mode": getattr(args, "fp_mode", ""),
        "xff": getattr(args, "xff", ""),
        "requested_xff": getattr(args, "xff", ""),
        "egress_proxy": egress_proxy,
        "attempts": [],
        "attempt_count": 0,
        "media_send_mode": getattr(args, "media_send_mode", "evil0-only"),
        "upload": None,
    }



def attach_check_images_top_level_aliases(summary: dict[str, Any]) -> dict[str, Any]:
    data = summary.get("data") if isinstance(summary.get("data"), dict) else {}
    queue_health = data.get("queue_health") if isinstance(data.get("queue_health"), dict) else {}
    aliases = {
        "requested_concurrency": data.get("requested_concurrency"),
        "concurrency": data.get("concurrency"),
        "peak_active_workers": data.get("peak_active_workers"),
        "observed_peak_concurrency": data.get("observed_peak_concurrency"),
        "route_state": queue_health.get("route_state") or {},
        "risk_guard": queue_health.get("risk_guard") or {},
        "failure_stage": queue_health.get("failure_stage") or "",
        "stop_loss_recommended": queue_health.get("stop_loss_recommended", False),
        "cooldown_recommended_sec": queue_health.get("cooldown_recommended_sec", 0),
        "agent_hint": queue_health.get("agent_hint") or "",
        "resume_command": queue_health.get("resume_command") or "",
        "remaining_manifest": queue_health.get("remaining_manifest") or "",
        "remaining_count": queue_health.get("remaining_count", 0),
    }
    for key, value in aliases.items():
        if value is not None:
            summary[key] = value
    return summary



def media_should_retry(report: dict[str, Any], *, retry_risk: bool = False) -> bool:
    if media_exit_code(report) == 0:
        return False
    code_msg = extract_first_captcha_code(report)
    if code_msg:
        evil = str(code_msg.get("evil_level") or "").strip()
        if evil and evil != "0":
            return bool(retry_risk)
        if code_msg.get("code") == "1" and evil == "0":
            return False
    result = report.get("result") or {}
    status = str(result.get("status") or "").strip().lower()
    if status in {"failed", "handshake-failed", "ticket-rejected", "submit-error", "timeout"}:
        msg = (result.get("msg") or result.get("msg_en") or "").strip()
        if msg.lower() == "invalid request":
            return True
        return not bool(msg)
    return result.get("status") in {None, "waiting"}



def issue_media_ticket(args: argparse.Namespace, *, fp: str, iteration: int) -> tuple[str, str, dict[str, Any]]:
    if args.ticket or args.randstr or args.ticket_json:
        ticket, randstr = load_ticket_args(args.ticket, args.randstr, args.ticket_json)
        return ticket, randstr, {"source": "manual", "ticket_json": args.ticket_json or ""}
    if args.ticket_command:
        ticket, randstr, _provided_fp, provider_meta, _provider_report = load_ticket_provider(
            args.ticket_command,
            iteration=iteration,
            fp=fp,
            xff=args.xff,
        )
        compact_meta = {
            "source": "ticket-command",
            "command": provider_meta.get("command"),
            "provider_try": provider_meta.get("provider_try"),
            "returncode": provider_meta.get("returncode"),
            "status": provider_meta.get("status"),
            "provider": provider_meta.get("provider"),
        }
        return ticket, randstr, compact_meta
    if not getattr(args, "auto_ticket", True):
        raise SystemExit("missing media ticket; use --auto-ticket, --ticket-command, or --ticket-json")
    last: dict[str, Any] | None = None
    wait_profile = getattr(args, "captcha_wait_profile", "auto")
    wait_values = [int(x) for x in (getattr(args, "captcha_wait_ms", "") or "").split(",") if x.strip()]
    if not wait_values:
        if wait_profile == "fast":
            wait_values = [0, 500, 1500, 2200]
        elif wait_profile == "steady":
            wait_values = [1800, 2600, 3500, 4800, 6500, 9000, 12000]
        else:
            wait_values = [500, 1500, 2600, 3800, 5200, 7000, 9000, 12000, 16000]
    for ticket_try in range(1, max(1, getattr(args, "ticket_attempts", 3)) + 1):
        wait_ms = wait_values[(ticket_try + iteration - 2) % len(wait_values)]
        wait_jitter_ms = max(0, int(getattr(args, "captcha_wait_jitter_ms", 0) or 0))
        if wait_jitter_ms:
            wait_ms += random.randint(0, wait_jitter_ms)
        seq = [{'ft': make_tdc_ft()}, {'isNewEntry': 1}, {'media': 'image', 'iter': iteration, 'try': ticket_try}]
        profile_mode = getattr(args, "tdc_profile_mode", "fixed")
        profile = make_tdc_profile(f"{fp}:{iteration}:{ticket_try}") if profile_mode == "random" else None
        entry_url = MATRIX_PIC_URL if getattr(args, "media_type", "") in {"image", "video"} else CAPTCHA_ENTRY_URL
        captcha_xff = getattr(args, "xff", "") if getattr(args, "captcha_xff_mode", "none") == "match" else ""
        egress_proxy = str(getattr(args, "egress_proxy", "") or "")
        egress_scope = str(getattr(args, "egress_scope", "detect") or "detect")
        ticket_egress_proxy = egress_proxy if egress_scope == "all" else ""
        out = captcha_ticket_pure(
            timeout=args.ticket_timeout,
            wait_ms=wait_ms,
            seq=seq,
            entry_url=entry_url,
            xff=captcha_xff,
            egress_proxy=ticket_egress_proxy,
            profile=profile,
        )
        last = out
        payload = out.get("payload") or {}
        verify_summary = out.get("verify_summary") or {}
        dynamic_tdc = verify_summary.get("dynamic_tdc") or {}
        if payload.get("ticket") and payload.get("randstr") and dynamic_tdc.get("ok"):
            return payload["ticket"], payload["randstr"], {
                "source": "internal-captcha-ticket-tdc",
                "ticket_try": ticket_try,
                "wait_ms": wait_ms,
                "seq": seq,
                "status": out.get("status"),
                "provider": out.get("provider"),
                "captcha_xff": out.get("xff"),
                "egress_proxy": out.get("egress_proxy"),
                "requested_egress_proxy": egress_proxy,
                "egress_scope": egress_scope,
                "tdc_profile_mode": profile_mode,
                "tdc_profile": out.get("tdc_profile"),
                "prehandle_summary": out.get("prehandle_summary"),
                "verify_summary": verify_summary,
            }
        last = {
            **(out or {}),
            "status": "rejected-dynamic-tdc",
            "reject_reason": (dynamic_tdc.get("error") or "dynamic-tdc-not-ok"),
        }
    raise RuntimeError(f"media ticket provider failed: {last}")



def media_check_result(report: dict[str, Any], *, report_json: str = "") -> dict[str, Any]:
    result = report.get("result") or {}
    code_msg = extract_first_captcha_code(report)
    upload = report.get("upload") or {}
    egress = report.get("egress") if isinstance(report.get("egress"), dict) else {}
    egress_scope = str(report.get("egress_scope") or "detect")
    failure_stage = media_failure_stage(report)
    input_file = str(report.get("input_file") or "")
    media_type = report.get("media_type") or "image"
    next_command = ""
    if failure_stage:
        media_cmd = "check-video" if media_type == "video" else "check-image"
        input_flag = "--video-file" if media_type == "video" else "--image-file"
        next_command = f"matrix-ai-cli {media_cmd} {input_flag} <{media_type}-file> --fp-mode fresh --out-dir <dir>"
    stop_loss_recommended = failure_stage.startswith("captcha-evil-level-") and failure_stage not in {"captcha-evil-level-0", ""}
    if stop_loss_recommended:
        agent_hint = "cooldown-and-retry-later"
    elif failure_stage:
        agent_hint = "switch-route-or-slow-down"
    else:
        agent_hint = "ok"
    return {
        "ok": media_exit_code(report) == 0,
        "protocol_mode": report.get("protocol_mode") or "pure",
        "cdp_ws_mode": report.get("cdp_ws_mode"),
        "cdp_fp_source": report.get("cdp_fp_source"),
        "cdp_target_mode": report.get("cdp_target_mode"),
        "cdp_context_proxy_server": report.get("cdp_context_proxy_server"),
        "cdp_reset_browser_fp": report.get("cdp_reset_browser_fp"),
        "cdp_auto_env": report.get("cdp_auto_env"),
        "cdp_auto_feedback": report.get("cdp_auto_feedback"),
        "media_type": report.get("media_type"),
        "status": result.get("status") or ("failed" if result.get("code") else None),
        "fp": report.get("fp"),
        "xff": report.get("xff") or (report.get("headers") or {}).get("X-Forwarded-For") or "",
        "egress": egress,
        "egress_proxy": report.get("egress_proxy") or egress.get("proxy") or "",
        "egress_scope": egress_scope,
        "egress_public_ip": egress.get("public_ip") or "",
        "captcha": {
            "code": code_msg.get("code"),
            "evil_level": code_msg.get("evil_level"),
            "msg": code_msg.get("msg"),
        },
        "ai_generated": result.get("ai_generated"),
        "data_type": result.get("data_type"),
        "img_type": result.get("img_type"),
        "model_type": result.get("model_type"),
        "model_type_en": result.get("model_type_en"),
        "availableUses": result.get("availableUses"),
        "uuid": result.get("uuid"),
        "feedback_token": result.get("feedback_token"),
        "msg": result.get("msg"),
        "msg_en": result.get("msg_en"),
        "payload_sent": report.get("payload_sent"),
        "media_send_mode": report.get("media_send_mode"),
        "feedback": report.get("feedback"),
        "attempt_count": report.get("attempt_count"),
        "input_file": report.get("input_file"),
        "failure_stage": failure_stage,
        "stop_loss_recommended": stop_loss_recommended,
        "agent_hint": agent_hint,
        "next_command": next_command,
        "upload": {
            "fileId": upload.get("fileId"),
            "cosURL": upload.get("cosURL"),
            "video_cos_url": upload.get("video_cos_url"),
            "totalChunks": upload.get("totalChunks"),
        } if upload else None,
        "report_json": report_json,
    }



def media_backoff_seconds(args: argparse.Namespace, report: dict[str, Any], attempt_index: int) -> float:
    result = report.get("result") or {}
    status = str(result.get("status") or "").strip().lower()
    msg = str(result.get("msg") or result.get("msg_en") or "").strip().lower()
    jitter = float(getattr(args, "captcha_backoff_jitter_sec", 0) or 0)
    if status == "handshake-failed" and msg == "invalid request":
        base = min(2.0, max(0.5, float(getattr(args, "captcha_backoff_sec", 0) or 0), 0.5))
        return min(5.0, base + (random.uniform(0, min(jitter, 0.5)) if jitter > 0 else 0.0))
    risk = captcha_risk_level(report)
    base = float(getattr(args, "captcha_backoff_sec", 0) or 0)
    if risk >= 100:
        base = max(base, 20.0)
    elif risk >= 50:
        base = max(base, 8.0)
    if base <= 0:
        return 0.0
    return min(600.0, base * max(1, attempt_index) + (random.uniform(0, jitter) if jitter > 0 else 0.0))
