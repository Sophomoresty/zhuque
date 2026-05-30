"""CLI video and media stress commands."""
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any

from .config import DEFAULT_MEDIA_ROTATE_XFF, DEFAULT_MEDIA_XFF
from .transport import build_ws_headers, json_dump, make_fp_for_mode, xff_for_iteration
from .text_detect import write_json_file
from .media_detect import media_check_result, media_error_report, media_handshake_only
from .media_batch_job import run_media_report
from .batch import apply_media_solve_risk_defaults, batch_media_egress_counts, batch_media_egress_proxy_for_item, parse_egress_proxy_pool


def cmd_check_video(args: argparse.Namespace) -> int:
    apply_media_solve_risk_defaults(args)
    try:
        report = run_media_report(args, 'video')
    except (Exception, SystemExit) as exc:
        report = media_error_report(args, 'video', exc)
    report_json = ''
    if args.out_dir:
        report_json = str(Path(args.out_dir) / 'video-report.json')
        write_json_file(Path(report_json), report)
    out = media_check_result(report, report_json=report_json)
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    return 0 if out.get('ok') else 2




def cmd_stress_media(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    success_count = 0
    rotate_xff = args.rotate_xff or (DEFAULT_MEDIA_ROTATE_XFF if args.fp_mode == "fresh" and not args.xff else "")
    egress_proxy_pool = parse_egress_proxy_pool(getattr(args, 'egress_proxy_pool', None) or [])
    if egress_proxy_pool:
        setattr(args, "_egress_proxy_pool", egress_proxy_pool)
    for i in range(1, args.count + 1):
        started = time.time()
        fp = make_fp_for_mode(args.fp_mode, args.fp)
        xff = xff_for_iteration(rotate_xff, i) if rotate_xff else (args.xff or (DEFAULT_MEDIA_XFF if args.fp_mode == "fresh" else ""))
        egress_proxy = batch_media_egress_proxy_for_item(args, i)
        headers = build_ws_headers(xff=xff, headers=args.header)
        entry: dict[str, Any] = {
            "i": i,
            "mode": "media-handshake",
            "started_at": started,
            "fp": fp,
            "fp_mode": args.fp_mode,
            "xff": xff,
            "egress_proxy": egress_proxy,
            "headers": headers,
        }
        try:
            probe = media_handshake_only(fp, additional_headers=headers, egress_proxy=egress_proxy, timeout=args.timeout)
            first = probe.get("first") or {}
            entry["probe"] = probe
            egress = probe.get("egress") if isinstance(probe.get("egress"), dict) else {}
            entry["egress"] = egress
            entry["egress_public_ip"] = egress.get("public_ip") or ""
            entry["availableUses"] = first.get("availableUses")
            entry["status"] = first.get("status")
            entry["msg"] = first.get("msg")
            ok = first.get("status") == "success" and int(first.get("availableUses", 0)) > 0
            entry["ok"] = bool(ok)
            if ok:
                success_count += 1
        except Exception as exc:
            entry["ok"] = False
            entry["error"] = repr(exc)
        entry["elapsed_sec"] = round(time.time() - started, 4)
        attempts.append(entry)
        if args.stop_on_fail and not entry.get("ok"):
            break
        if i < args.count and args.delay_sec > 0:
            time.sleep(float(args.delay_sec) + (random.uniform(0, float(args.jitter_sec)) if args.jitter_sec > 0 else 0.0))
    summary = {
        "ok": success_count == args.count and len(attempts) == args.count,
        "command": "stress-media",
        "data": {
            "protocol_mode": "pure",
            "mode": "media-handshake",
            "count_requested": args.count,
            "count_executed": len(attempts),
            "success_count": success_count,
            "failure_count": len(attempts) - success_count,
            "fp_mode": args.fp_mode,
            "xff": args.xff or (DEFAULT_MEDIA_XFF if args.fp_mode == "fresh" else ""),
            "requested_xff": args.xff,
            "rotate_xff": rotate_xff,
            "egress_proxy": str(getattr(args, "egress_proxy", "") or ""),
            "egress_proxy_pool": egress_proxy_pool,
            "egress_counts": batch_media_egress_counts(attempts),
            "headers": build_ws_headers(xff=args.xff, headers=args.header),
            "attempts_path": str(out_dir / "stress-media-attempts.json"),
        },
    }
    write_json_file(out_dir / "stress-media-attempts.json", attempts)
    write_json_file(out_dir / "stress-media-summary.json", summary)
    json_dump(summary)
    return 0 if summary["ok"] else 2
