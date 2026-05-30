"""Media batch job execution: single-item detection with retries."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from .config import DEFAULT_MEDIA_XFF, HTTP_BASE, PIC_WS_URL, VIDEO_CHUNK_SIZE
from .transport import (
    build_ws_headers,
    egress_meta,
    make_fp,
    make_fp_for_mode,
)
from .captcha import (
    captcha_ticket_pure,
    extract_first_captcha_code,
)
from .text_detect import (
    json_command_error,
    load_ticket_provider,
    write_json_file,
    TicketProviderError,
)
from .media_detect import (
    detect_media_with_ticket,
    issue_media_ticket,
    make_image_zip_payload,
    media_backoff_seconds,
    media_exit_code,
    media_should_retry,
    upload_video_file,
)
from .media_cdp import cdp_media_report
from .batch import (
    batch_media_browser_version_url_for_item,
    batch_media_cdp_context_proxy_for_item,
    batch_media_egress_proxy_for_item,
    batch_media_xff_for_item,
    compact_batch_media_result,
)


def run_media_report(args: argparse.Namespace, media_type: str) -> dict[str, Any]:
    setattr(args, "media_type", media_type)
    if getattr(args, "driver", "pure") == "cdp":
        return cdp_media_report(args, media_type)
    input_path = Path(args.image_file if media_type == "image" else args.video_file)
    if not input_path.exists():
        raise SystemExit(f"missing input file: {input_path}")
    image_bytes: bytes | None = None
    upload_meta: dict[str, Any] | None = None
    video_cos_url = ""
    if media_type == "image":
        image_bytes = input_path.read_bytes()
        if not image_bytes:
            raise SystemExit(f"empty image file: {input_path}")
    else:
        upload_meta = upload_video_file(
            input_path,
            fp=fp,
            xff=effective_xff,
            egress_proxy=egress_proxy,
            timeout=args.upload_timeout,
            chunk_size=args.chunk_size,
        )
        video_cos_url = upload_meta.get("video_cos_url") or ""
    manual_ticket = bool(args.ticket or args.randstr or args.ticket_json)
    max_attempts = 1 if manual_ticket else max(1, args.attempts)
    attempt_summaries: list[dict[str, Any]] = []
    selected: dict[str, Any] | None = None
    for i in range(1, max_attempts + 1):
        started = time.time()
        attempt_args = argparse.Namespace(**vars(args))
        if i > 1:
            batch_index = int(getattr(args, '_batch_index', 1) or 1) + int(getattr(args, '_route_attempt_offset', 0) or 0)
            batch_total = max(1, int(getattr(args, '_batch_total', 1) or 1))
            attempt_slot = batch_index + (i - 1) * batch_total
            setattr(attempt_args, '_preferred_xff', '')
            setattr(attempt_args, '_preferred_browser_version_url', '')
            attempt_args.xff = batch_media_xff_for_item(attempt_args, attempt_slot)
            attempt_args.egress_proxy = batch_media_egress_proxy_for_item(attempt_args, attempt_slot)
            attempt_args.cdp_browser_version_url = batch_media_browser_version_url_for_item(attempt_args, attempt_slot)
            attempt_args.cdp_context_proxy_server = batch_media_cdp_context_proxy_for_item(attempt_args, attempt_slot)
            if bool(getattr(attempt_args, 'refresh_fp_on_retry', False)):
                attempt_args.fp = ''
                setattr(attempt_args, '_prepared_fp', '')
        fp = getattr(attempt_args, '_prepared_fp', '') or make_fp_for_mode(getattr(attempt_args, "fp_mode", "fresh"), getattr(attempt_args, 'fp', ''))
        if not fp:
            raise SystemExit("missing fp; use --fp-mode fresh or --fp")
        effective_xff = getattr(attempt_args, 'xff', '') or (DEFAULT_MEDIA_XFF if getattr(attempt_args, 'fp_mode', 'fresh') == "fresh" else "")
        egress_proxy = str(getattr(attempt_args, "egress_proxy", "") or "")
        headers = build_ws_headers(xff=effective_xff, headers=attempt_args.header)
        detect_egress_proxy = egress_proxy if str(getattr(attempt_args, "egress_scope", "detect") or "detect") in {"detect", "all"} else ""
        try:
            ticket, randstr, ticket_meta = issue_media_ticket(attempt_args, fp=fp, iteration=i)
            report = detect_media_with_ticket(
                media_type=media_type,
                fp=fp,
                ticket=ticket,
                randstr=randstr,
                timeout=attempt_args.timeout,
                additional_headers=headers,
                egress_proxy=detect_egress_proxy,
                image_bytes=image_bytes,
                video_cos_url=video_cos_url,
                media_send_mode=getattr(attempt_args, "media_send_mode", "evil0-only"),
            )
            report["ticket_provider"] = ticket_meta
            report["xff"] = effective_xff
            report["requested_xff"] = getattr(attempt_args, 'xff', '')
            report["egress_proxy"] = egress_proxy
            report["egress_scope"] = str(getattr(attempt_args, "egress_scope", "detect") or "detect")
            ok = media_exit_code(report) == 0
            attempt_summaries.append({
                "i": i,
                "ok": ok,
                "elapsed_sec": round(time.time() - started, 4),
                "ticket_provider": ticket_meta,
                "result": report.get("result"),
                "payload_sent": report.get("payload_sent"),
                "captcha": extract_first_captcha_code(report),
                "logs": report.get("logs"),
                "fp": report.get("fp") or fp,
                "xff": report.get("xff") or effective_xff,
                "egress": report.get("egress"),
                "egress_proxy": egress_proxy,
                "egress_scope": str(getattr(attempt_args, "egress_scope", "detect") or "detect"),
            })
            selected = report
            if ok or not media_should_retry(report, retry_risk=bool(getattr(attempt_args, "retry_risk", False))):
                break
            if i < max_attempts:
                backoff_sec = media_backoff_seconds(attempt_args, report, i)
                if backoff_sec > 0:
                    attempt_summaries[-1]["backoff_sec"] = round(backoff_sec, 4)
                    time.sleep(backoff_sec)
        except Exception as exc:
            failed = {
                "fp": fp,
                "media_type": media_type,
                "protocol_mode": "pure",
                "headers": headers,
                "logs": [],
                "payload_sent": False,
                "egress": egress_meta(egress_proxy) if egress_proxy else {"enabled": False},
                "result": {"status": "failed", "msg": str(exc)},
                "xff": effective_xff,
                "egress_proxy": egress_proxy,
                "egress_scope": str(getattr(attempt_args, "egress_scope", "detect") or "detect"),
            }
            selected = failed
            attempt_summaries.append({
                "i": i,
                "ok": False,
                "elapsed_sec": round(time.time() - started, 4),
                "error": repr(exc),
                "result": failed.get("result"),
                "fp": fp,
                "xff": effective_xff,
            })
            if i >= max_attempts:
                break
    if selected is None:
        selected = {
            "fp": fp,
            "media_type": media_type,
            "protocol_mode": "pure",
            "headers": headers,
            "logs": [],
            "payload_sent": False,
            "egress": egress_meta(egress_proxy) if egress_proxy else {"enabled": False},
            "result": {"status": "failed", "msg": "no media attempts executed"},
        }
    selected["input_file"] = str(input_path)
    selected["input_size"] = input_path.stat().st_size
    selected["fp_mode"] = args.fp_mode
    selected["xff"] = selected.get("xff") or (selected.get("headers") or {}).get("X-Forwarded-For") or ""
    selected["requested_xff"] = selected.get("requested_xff") or args.xff
    selected["egress_proxy"] = selected.get("egress_proxy") or str(getattr(args, "egress_proxy", "") or "")
    selected["egress_scope"] = selected.get("egress_scope") or str(getattr(args, "egress_scope", "detect") or "detect")
    selected.setdefault("egress", egress_meta(str(selected.get("egress_proxy") or "")) if selected.get("egress_proxy") else {"enabled": False})
    selected["attempts"] = attempt_summaries
    selected["attempt_count"] = len(attempt_summaries)
    selected["upload"] = upload_meta
    selected["interface"] = {
        "ws_url": PIC_WS_URL,
        "video_upload_chunk": HTTP_BASE + "/user/upload_video_chunk",
        "video_merge_chunks": HTTP_BASE + "/user/merge_video_chunks",
    }
    return selected




def run_batch_media_detect_job(
    *,
    item_args: argparse.Namespace,
    image_path: Path,
    report_path: Path,
    i: int,
    started_at: float,
    ticket: str,
    randstr: str,
    ticket_meta: dict[str, Any],
    media_type: str = 'image',
) -> dict[str, Any]:
    try:
        image_bytes = image_path.read_bytes()
        if not image_bytes:
            raise RuntimeError(f"empty image file: {image_path}")
        max_attempts = max(1, int(getattr(item_args, 'attempts', 1) or 1))
        attempt_summaries: list[dict[str, Any]] = []
        selected: dict[str, Any] | None = None
        current_ticket = ticket
        current_randstr = randstr
        current_ticket_meta = ticket_meta
        for attempt_index in range(1, max_attempts + 1):
            attempt_args = argparse.Namespace(**vars(item_args))
            batch_index = int(getattr(item_args, '_batch_index', i) or i) + int(getattr(item_args, '_route_attempt_offset', 0) or 0)
            if attempt_index > 1:
                attempt_slot = batch_index + (attempt_index - 1) * max(1, int(getattr(item_args, '_batch_total', 1) or 1))
                setattr(attempt_args, '_preferred_xff', '')
                setattr(attempt_args, '_preferred_browser_version_url', '')
                attempt_args.xff = batch_media_xff_for_item(attempt_args, attempt_slot)
                attempt_args.egress_proxy = batch_media_egress_proxy_for_item(attempt_args, attempt_slot)
                attempt_args.cdp_browser_version_url = batch_media_browser_version_url_for_item(attempt_args, attempt_slot)
                attempt_args.cdp_context_proxy_server = batch_media_cdp_context_proxy_for_item(attempt_args, attempt_slot)
                if bool(getattr(attempt_args, 'refresh_fp_on_retry', False)):
                    attempt_args.fp = ''
                    setattr(attempt_args, '_prepared_fp', '')
                if getattr(attempt_args, 'driver', 'pure') == 'cdp':
                    attempt_args.fp = ''
                    setattr(attempt_args, '_prepared_fp', '')
            fp = getattr(attempt_args, '_prepared_fp', '') or make_fp_for_mode(getattr(attempt_args, 'fp_mode', 'fresh'), getattr(attempt_args, 'fp', ''))
            headers = build_ws_headers(xff=attempt_args.xff, headers=attempt_args.header)
            detect_egress_proxy = str(getattr(attempt_args, "egress_proxy", "") or "") if str(getattr(attempt_args, "egress_scope", "detect") or "detect") in {"detect", "all"} else ""
            if getattr(attempt_args, 'driver', 'pure') == 'cdp':
                report = cdp_media_report(attempt_args, media_type)
            else:
                report = detect_media_with_ticket(
                    media_type=media_type,
                    fp=fp,
                    ticket=current_ticket,
                    randstr=current_randstr,
                    timeout=attempt_args.timeout,
                    additional_headers=headers,
                    egress_proxy=detect_egress_proxy,
                    image_bytes=image_bytes,
                    media_send_mode=getattr(attempt_args, "media_send_mode", "evil0-only"),
                )
                report["ticket_provider"] = current_ticket_meta
                report["egress_proxy"] = str(getattr(attempt_args, "egress_proxy", "") or "")
                report["egress_scope"] = str(getattr(attempt_args, "egress_scope", "detect") or "detect")
            ok = media_exit_code(report) == 0
            attempt_summaries.append({
                "i": attempt_index,
                "ok": ok,
                "ticket_provider": current_ticket_meta if getattr(attempt_args, 'driver', 'pure') != 'cdp' else None,
                "result": report.get("result"),
                "payload_sent": report.get("payload_sent"),
                "captcha": extract_first_captcha_code(report),
                "logs": report.get("logs"),
                "fp": report.get("fp"),
                "xff": report.get("xff") or attempt_args.xff,
                "egress": report.get("egress"),
                "egress_proxy": str(getattr(attempt_args, "egress_proxy", "") or ""),
                "egress_scope": str(getattr(attempt_args, "egress_scope", "detect") or "detect"),
                "egress_public_ip": (report.get("egress") or {}).get("public_ip") if isinstance(report.get("egress"), dict) else "",
                "cdp_browser_version_url": str(getattr(attempt_args, "cdp_browser_version_url", "") or ""),
                "cdp_context_proxy_server": str(getattr(attempt_args, "cdp_context_proxy_server", "") or ""),
            })
            selected = report
            if ok:
                winning_xff = str(report.get("xff") or attempt_args.xff or "").strip()
                if winning_xff:
                    setattr(item_args, "_preferred_xff", winning_xff)
                winning_browser_url = str(getattr(attempt_args, "cdp_browser_version_url", "") or "").strip()
                if winning_browser_url:
                    setattr(item_args, "_preferred_browser_version_url", winning_browser_url)
            if ok or not media_should_retry(report, retry_risk=bool(getattr(item_args, "retry_risk", False))) or attempt_index >= max_attempts:
                break
            backoff_sec = media_backoff_seconds(item_args, report, attempt_index)
            if backoff_sec > 0:
                attempt_summaries[-1]["backoff_sec"] = round(backoff_sec, 4)
                time.sleep(backoff_sec)
            if getattr(item_args, 'driver', 'pure') != 'cdp':
                current_ticket, current_randstr, current_ticket_meta = issue_media_ticket(attempt_args, fp=fp, iteration=i * 1000 + attempt_index + 1)
        report = selected or {
            "fp": "",
            "media_type": media_type,
            "protocol_mode": "pure",
            "headers": {},
            "logs": [],
            "payload_sent": False,
            "result": {"status": "failed", "msg": "no media attempts executed"},
        }
        report["input_file"] = str(image_path)
        report["input_size"] = image_path.stat().st_size
        report["attempts"] = attempt_summaries
        report["attempt_count"] = len(attempt_summaries)
        write_json_file(report_path, report)
        compact = compact_batch_media_result(report, report_json=str(report_path))
        compact.update({
            'i': i,
            'elapsed_sec': round(time.time() - started_at, 4),
            'ticket_provider': report.get('ticket_provider') or current_ticket_meta,
            'result': report.get('result'),
            'payload_sent': report.get('payload_sent'),
            'captcha': extract_first_captcha_code(report),
            'egress': report.get('egress'),
            'egress_proxy': report.get('egress_proxy') or str(getattr(item_args, "egress_proxy", "") or ""),
            'egress_scope': report.get('egress_scope') or str(getattr(item_args, "egress_scope", "detect") or "detect"),
            'egress_public_ip': (report.get("egress") or {}).get("public_ip") if isinstance(report.get("egress"), dict) else "",
            'logs': report.get('logs'),
        })
        return compact
    except Exception as exc:
        return {
            'ok': False,
            'protocol_mode': getattr(item_args, 'driver', 'pure'),
            'media_type': media_type,
            'status': 'failed',
            'i': i,
            'input_file': str(image_path),
            'error': repr(exc),
            'elapsed_sec': round(time.time() - started_at, 4),
            'report_json': '',
        }
