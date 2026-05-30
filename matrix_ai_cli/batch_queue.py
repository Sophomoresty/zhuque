"""Batch queue management: finalization, XFF probing, error summaries."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import time
from pathlib import Path
from typing import Any

from .config import DEFAULT_MEDIA_BOUND, DEFAULT_MEDIA_XFF, DEFAULT_MEDIA_ROTATE_XFF
from .transport import (
    build_ws_headers,
    egress_meta,
    json_dump,
    make_fp,
    make_fp_for_mode,
    xff_for_iteration,
    rotate_xff_pool_for_pattern,
)
from .captcha import extract_first_captcha_code
from .text_detect import write_json_file
from .media_detect import (
    attach_check_images_top_level_aliases,
    media_exit_code,
    media_failure_stage,
    media_handshake_only,
    media_risk_event_from_compact,
    media_risk_guard_config,
)
from .batch import (
    batch_media_compact_failure_stage,
    batch_media_egress_counts,
    batch_media_preferred_xff_max_uses,
    batch_media_risk_summary,
    batch_media_risk_summary_from_events,
    compact_batch_media_result,
    parse_rotate_xff_candidates,
)


def batch_media_risk_resume_command(args: argparse.Namespace, *, out_dir: Path, remaining_manifest: str) -> str:
    base = [
        "matrix-ai-cli",
        "check-images",
        "--driver",
        str(getattr(args, "driver", "pure") or "pure"),
        "--out-dir",
        str(out_dir),
        "--images-file",
        remaining_manifest or "<remaining-images.txt>",
        "--allow-duplicate-images",
        "--fp-mode",
        str(getattr(args, "fp_mode", "fresh") or "fresh"),
        "--route-mode",
        str(getattr(args, "route_mode", "auto") or "auto"),
        "--concurrency",
        "1",
        "--ticket-phase",
        "serial",
        "--media-send-mode",
        str(getattr(args, "media_send_mode", "evil0-only") or "evil0-only"),
        "--risk-budget",
        str(max(0, int(getattr(args, "risk_budget", 0) or 0))),
    ]
    if bool(getattr(args, "solve_risk", False)):
        base.append("--solve-risk")
    if getattr(args, "driver", "pure") != "cdp":
        egress_pool = list(getattr(args, "_egress_proxy_pool", []) or getattr(args, "egress_proxy_pool", []) or [])
        egress_proxy = str(getattr(args, "egress_proxy", "") or "")
        if egress_pool:
            for proxy in egress_pool:
                base.extend(["--egress-proxy-pool", str(proxy)])
        elif egress_proxy:
            base.extend(["--egress-proxy", egress_proxy])
        base.extend(["--egress-scope", str(getattr(args, "egress_scope", "detect") or "detect")])
    if getattr(args, "driver", "pure") == "cdp":
        base.extend([
            "--cdp-ws-mode",
            str(getattr(args, "cdp_ws_mode", "proxy") or "proxy"),
            "--cdp-fp-source",
            str(getattr(args, "cdp_fp_source", "cli") or "cli"),
        ])
        if bool(getattr(args, "cdp_new_tab", True)):
            base.append("--cdp-new-tab")
            base.append("--cdp-close-tab" if bool(getattr(args, "cdp_close_tab", True)) else "--no-cdp-close-tab")
        else:
            base.extend([
                "--no-cdp-new-tab",
                "--no-cdp-close-tab",
                "--bound",
                str(getattr(args, "bound", DEFAULT_MEDIA_BOUND) or DEFAULT_MEDIA_BOUND),
            ])
        if bool(getattr(args, "cdp_auto_env", False)):
            base.append("--cdp-auto-env")
        else:
            base.append("--no-cdp-auto-env")
        if bool(getattr(args, "cdp_auto_feedback", False)):
            base.append("--cdp-auto-feedback")
    else:
        egress_pool = list(getattr(args, "_egress_proxy_pool", []) or getattr(args, "egress_proxy_pool", []) or [])
        egress_proxy = str(getattr(args, "egress_proxy", "") or "")
        if egress_pool:
            for proxy in egress_pool:
                base.extend(["--egress-proxy-pool", str(proxy)])
        elif egress_proxy:
            base.extend(["--egress-proxy", egress_proxy])
        base.extend(["--egress-scope", str(getattr(args, "egress_scope", "detect") or "detect")])
    return " ".join(shlex.quote(part) for part in base)




def batch_media_input_error_summary(args: argparse.Namespace, *, error: BaseException | str, route_mode: str, route_notes: list[str]) -> dict[str, Any]:
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    message = str(error)
    summary = {
        "ok": False,
        "command": "check-images",
        "error": message,
        "exit_code": 2,
        "data": {
            "protocol_mode": getattr(args, "driver", "pure"),
            "media_type": "image",
            "unique_input_count": 0,
            "repeat_each": max(1, int(getattr(args, "repeat_each", 1) or 1)),
            "count_requested": 0,
            "count_executed": 0,
            "success_count": 0,
            "failure_count": 0,
            "requested_concurrency": max(1, int(getattr(args, "concurrency", 1) or 1)),
            "concurrency": 1,
            "ticket_phase": getattr(args, "ticket_phase", "parallel"),
            "fp_mode": getattr(args, "fp_mode", "fresh"),
            "xff": getattr(args, "xff", ""),
            "requested_xff": getattr(args, "xff", ""),
            "rotate_xff": getattr(args, "rotate_xff", ""),
            "out_dir": str(out_dir),
            "results_jsonl": str(out_dir / "results.jsonl"),
            "reports_dir": str(out_dir / "reports"),
            "xff_probe": {"enabled": False},
            "risk_summary": {"evil_level_counts": {}, "status_counts": {}, "msg_counts": {}, "payload_sent_count": 0, "risk_stop_recommended": False, "risk_stop_reason": ""},
            "queue_health": {
                "used_xff_counts": {},
                "failed_xff_counts": {},
                "failure_stage_counts": {},
                "xff_pool": list(getattr(args, "_xff_pool", []) or []),
                "egress_proxy": str(getattr(args, "egress_proxy", "") or ""),
                "egress_proxy_pool": list(getattr(args, "_egress_proxy_pool", []) or []),
                "route_state": {
                    "mode": route_mode,
                    "notes": route_notes,
                    "strategy": "auto-preferred-then-pool",
                    "active": bool(list(getattr(args, "_xff_pool", []) or []) or getattr(args, "xff", "") or getattr(args, "rotate_xff", "")),
                    "fixed_xff": bool(getattr(args, "xff", "")),
                    "pool_size": len(list(getattr(args, "_xff_pool", []) or [])),
                    "egress_proxy_enabled": bool(str(getattr(args, "egress_proxy", "") or "") or list(getattr(args, "_egress_proxy_pool", []) or [])),
                    "egress_proxy_pool_size": len(list(getattr(args, "_egress_proxy_pool", []) or [])),
                    "preferred_xff": str(getattr(args, "_preferred_xff", "") or ""),
                    "preferred_xff_use_count": int(getattr(args, "_preferred_xff_use_count", 0) or 0),
                    "preferred_xff_max_uses": batch_media_preferred_xff_max_uses(args),
                    "rotated_preferred_xff": list(getattr(args, "_rotated_preferred_xff", []) or []),
                    "used_xff_counts": {},
                    "failed_xff_counts": {},
                    "failure_stage_counts": {},
                },
                "preferred_xff_max_uses": batch_media_preferred_xff_max_uses(args),
                "max_attempt_count": 0,
                "risk_guard": media_risk_guard_config(args),
                "risk_events": [],
                "risk_budget_exhausted": False,
                "risk_stop_index": 0,
                "cooldown_recommended_sec": 0,
                "remaining_manifest": "",
                "remaining_count": 0,
                "resume_command": "",
                "stop_loss_recommended": False,
                "failure_stage": "input-error",
                "agent_hint": "fix-input",
            },
            "results": [],
            "next_command": f"matrix-ai-cli check-images --driver pure --out-dir {shlex.quote(str(out_dir))} --images-file <images.txt> --fp-mode fresh --route-mode auto --concurrency 1 --ticket-phase serial",
        },
    }
    summary = attach_check_images_top_level_aliases(summary)
    write_json_file(out_dir / "summary.json", summary)
    json_dump(summary)
    return summary




def probe_rotate_xff_candidates(
    args: argparse.Namespace,
    *,
    base_image_paths: list[Path],
    out_dir: Path,
) -> dict[str, Any]:
    import sys as _sys
    from .media_batch_job import run_media_report as _default_run_media_report
    _cli = _sys.modules.get('matrix_ai_cli.cli')
    _run_media_report = getattr(_cli, 'run_media_report', None) or _default_run_media_report
    if not base_image_paths:
        return {"enabled": False, "reason": "no-input-images"}
    if getattr(args, "driver", "pure") == "cdp" and getattr(args, "cdp_ws_mode", "proxy") == "direct":
        return {"enabled": False, "reason": "cdp-direct-no-xff"}
    if getattr(args, "xff", ""):
        return {"enabled": False, "reason": "fixed-xff"}
    candidates = parse_rotate_xff_candidates(
        list(getattr(args, "xff_probe_pattern", []) or []) or [getattr(args, "rotate_xff", "")]
    )
    if not candidates:
        return {"enabled": False, "reason": "no-candidates"}
    max_patterns = max(0, int(getattr(args, "xff_probe_max_patterns", 0) or 0))
    if max_patterns > 0:
        candidates = candidates[:max_patterns]
    probe_attempts = max(1, int(getattr(args, "xff_probe_attempts", 1) or 1))
    probe_dir = out_dir / "xff-probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_image = base_image_paths[0]
    results: list[dict[str, Any]] = []
    risk_guard = media_risk_guard_config(args)
    risk_events: list[dict[str, Any]] = []
    risk_stopped = False
    risk_failure_stage = ""
    selected_pattern = ""
    selected_xff = ""
    selected_xff_pool: list[str] = []
    for idx, pattern in enumerate(candidates, start=1):
        probe_args = argparse.Namespace(**vars(args))
        probe_args.rotate_xff = ""
        probe_args.xff = xff_for_iteration(pattern, 1)
        probe_args.image_file = str(probe_image)
        probe_args.out_json = ""
        probe_args.out_dir = ""
        probe_args.attempts = probe_attempts
        probe_started = time.time()
        report_path = probe_dir / f"{idx:02d}.json"
        try:
            report = _run_media_report(probe_args, "image")
            write_json_file(report_path, report)
            compact = compact_batch_media_result(report, report_json=str(report_path))
            evil = (compact.get("captcha") or {}).get("evil_level")
            passed = bool(compact.get("ok")) and bool(compact.get("payload_sent")) and str(evil) == "0"
            entry = {
                "ok": passed,
                "candidate_index": idx,
                "rotate_xff": pattern,
                "probe_xff": probe_args.xff,
                "elapsed_sec": round(time.time() - probe_started, 4),
                "report_json": str(report_path),
                "result": compact,
            }
        except (Exception, SystemExit) as exc:
            entry = {
                "ok": False,
                "candidate_index": idx,
                "rotate_xff": pattern,
                "probe_xff": probe_args.xff,
                "elapsed_sec": round(time.time() - probe_started, 4),
                "report_json": "",
                "error": str(exc),
            }
        results.append(entry)
        if entry.get("ok"):
            if not selected_pattern:
                selected_pattern = pattern
                selected_xff = probe_args.xff
            selected_xff_pool.append(probe_args.xff)
        else:
            compact = entry.get("result") if isinstance(entry.get("result"), dict) else None
            if isinstance(compact, dict):
                risk_event = media_risk_event_from_compact(compact)
                if risk_guard.get("enabled") and risk_event:
                    risk_events.append(risk_event)
                    if len(risk_events) > int(risk_guard.get("risk_budget") or 0):
                        risk_stopped = True
                        risk_failure_stage = str(risk_event.get("failure_stage") or "captcha-risk")
                        break
    summary = {
        "enabled": True,
        "probe_image": str(probe_image),
        "probe_attempts": probe_attempts,
        "candidate_count": len(candidates),
        "selected_rotate_xff": selected_pattern,
        "selected_xff": selected_xff,
        "selected_xff_pool": selected_xff_pool,
        "ok": bool(selected_xff_pool) and not risk_stopped,
        "results": results,
        "probe_dir": str(probe_dir),
        "risk_guard": risk_guard,
        "risk_events": risk_events,
        "risk_budget_exhausted": risk_stopped,
        "stop_loss_recommended": risk_stopped,
        "failure_stage": risk_failure_stage,
        "cooldown_recommended_sec": risk_guard.get("cooldown_recommended_sec") if risk_stopped else 0,
    }
    write_json_file(probe_dir / "summary.json", summary)
    if selected_xff_pool and not risk_stopped:
        setattr(args, "_xff_pool", selected_xff_pool)
        args.rotate_xff = ""
    return summary




def check_images_finalize_summary(
    args: argparse.Namespace,
    *,
    out_dir: Path,
    reports_dir: Path,
    results_jsonl: Path,
    base_image_paths: list[Path],
    image_paths: list[Path],
    repeat_each: int,
    requested_concurrency: int,
    concurrency: int,
    cdp_pool_summary: dict[str, Any],
    xff_probe_summary: dict[str, Any],
    route_mode: str,
    route_notes: list[str],
    attempts: list[dict[str, Any]],
    success_count: int,
    risk_guard: dict[str, Any],
    risk_events: list[dict[str, Any]],
    risk_stopped: bool,
    risk_stop_index: int,
    risk_failure_stage: str,
    risk_window: dict[str, Any],
    remaining_manifest: str = "",
    remaining_count: int = 0,
    risk_recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    logical_success_indices = {int(item.get('i') or 0) for item in attempts if item.get('ok') and 1 <= int(item.get('i') or 0) <= len(image_paths)}
    logical_executed_indices = {int(item.get('i') or 0) for item in attempts if 1 <= int(item.get('i') or 0) <= len(image_paths)}
    logical_success_count = len(logical_success_indices)
    logical_executed_count = len(logical_executed_indices)
    logical_failure_count = max(0, logical_executed_count - logical_success_count)
    logical_ok = logical_success_count == len(image_paths) and logical_executed_count == len(image_paths)
    risk_summary = batch_media_risk_summary(attempts)
    if risk_events:
        risk_summary = {
            **risk_summary,
            "risk_guard_enabled": bool(risk_guard.get("enabled")),
            "risk_budget": int(risk_guard.get("risk_budget") or 0),
            "risk_events": risk_events,
            "risk_budget_exhausted": risk_stopped,
            "risk_stop_index": risk_stop_index,
            "cooldown_recommended_sec": risk_guard.get("cooldown_recommended_sec"),
            "remaining_count": remaining_count,
            "remaining_manifest": remaining_manifest,
        }
    used_xff_counts: dict[str, int] = {}
    failed_xff_counts: dict[str, int] = {}
    failure_stage_counts: dict[str, int] = {}
    max_attempt_count = 0
    for item in attempts:
        xff = str(item.get('xff') or '').strip()
        if xff:
            used_xff_counts[xff] = used_xff_counts.get(xff, 0) + 1
        try:
            max_attempt_count = max(max_attempt_count, int(item.get('attempt_count') or 0))
        except Exception:
            pass
        stage = batch_media_compact_failure_stage(item)
        if stage:
            failure_stage_counts[stage] = failure_stage_counts.get(stage, 0) + 1
            if xff:
                failed_xff_counts[xff] = failed_xff_counts.get(xff, 0) + 1
    egress_counts = batch_media_egress_counts(attempts)
    peak_active_workers = max(0, int(getattr(args, '_observed_peak_concurrency', 0) or 0))
    route_state = {
        'mode': route_mode,
        'notes': route_notes,
        'strategy': 'auto-preferred-then-pool+egress-proxy-pool',
        'active': bool(list(getattr(args, '_xff_pool', []) or []) or getattr(args, 'xff', '') or getattr(args, 'rotate_xff', '') or str(getattr(args, 'egress_proxy', '') or '') or list(getattr(args, '_egress_proxy_pool', []) or [])),
        'fixed_xff': bool(getattr(args, 'xff', '')),
        'pool_size': len(list(getattr(args, '_xff_pool', []) or [])),
        'egress_proxy_enabled': bool(str(getattr(args, 'egress_proxy', '') or '') or list(getattr(args, '_egress_proxy_pool', []) or [])),
        'egress_scope': str(getattr(args, 'egress_scope', 'detect') or 'detect'),
        'egress_proxy_pool_size': len(list(getattr(args, '_egress_proxy_pool', []) or [])),
        'egress_proxy': str(getattr(args, 'egress_proxy', '') or ''),
        'egress_proxy_pool': list(getattr(args, '_egress_proxy_pool', []) or []),
        'egress_counts': egress_counts,
        'preferred_xff': str(getattr(args, '_preferred_xff', '') or ''),
        'preferred_xff_use_count': int(getattr(args, '_preferred_xff_use_count', 0) or 0),
        'preferred_xff_max_uses': batch_media_preferred_xff_max_uses(args),
        'rotated_preferred_xff': list(getattr(args, '_rotated_preferred_xff', []) or []),
        'used_xff_counts': used_xff_counts,
        'failed_xff_counts': failed_xff_counts,
        'failure_stage_counts': failure_stage_counts,
    }
    if risk_recovery:
        route_state['risk_recovery'] = risk_recovery
    risk_resume_command = batch_media_risk_resume_command(args, out_dir=out_dir, remaining_manifest=remaining_manifest) if (risk_stopped and remaining_manifest) else ""
    risk_agent_hint = (
        f"cooldown-{int(risk_guard.get('cooldown_recommended_sec') or 0)}s-then-resume"
        if risk_stopped and remaining_manifest
        else "cooldown-and-retry-later"
        if risk_stopped
        else ('ok' if logical_ok else 'switch-route-or-slow-down')
    )
    active_xff_pool = list(getattr(args, '_xff_pool', []) or [])
    active_egress_pool = list(getattr(args, '_egress_proxy_pool', []) or [])
    summary_xff = args.xff or (active_xff_pool[0] if active_xff_pool else ((DEFAULT_MEDIA_XFF if args.fp_mode == "fresh" else "") if getattr(args, 'driver', 'pure') != 'cdp' or getattr(args, 'cdp_ws_mode', 'proxy') == 'proxy' else ''))
    summary_rotate_xff = '' if active_xff_pool else (args.rotate_xff or (DEFAULT_MEDIA_ROTATE_XFF if args.fp_mode == "fresh" and not args.xff else ""))
    summary = {
        'ok': logical_ok,
        'command': 'check-images',
        'data': {
            'protocol_mode': getattr(args, 'driver', 'pure'),
            'cdp_ws_mode': getattr(args, 'cdp_ws_mode', None) if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'cdp_fp_source': getattr(args, 'cdp_fp_source', None) if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'cdp_target_mode': getattr(args, 'cdp_target_mode', None) if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'cdp_auto_env': getattr(args, 'cdp_auto_env', None) if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'cdp_auto_feedback': getattr(args, 'cdp_auto_feedback', None) if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'cdp_pool': cdp_pool_summary if getattr(args, 'driver', 'pure') == 'cdp' else None,
            'media_type': 'image',
            'unique_input_count': len(base_image_paths),
            'repeat_each': repeat_each,
            'count_requested': len(image_paths),
            'count_executed': logical_executed_count,
            'attempt_row_count': len(attempts),
            'success_count': logical_success_count,
            'failure_count': logical_failure_count,
            'requested_concurrency': requested_concurrency,
            'concurrency': concurrency,
            'peak_active_workers': peak_active_workers,
            'observed_peak_concurrency': peak_active_workers,
            'ticket_phase': getattr(args, 'ticket_phase', 'parallel'),
            'captcha_xff_mode': getattr(args, 'captcha_xff_mode', 'none'),
            'tdc_profile_mode': getattr(args, 'tdc_profile_mode', 'fixed'),
            'ticket_delay_sec': getattr(args, 'ticket_delay_sec', None),
            'ticket_jitter_sec': getattr(args, 'ticket_jitter_sec', None),
            'ticket_window_size': getattr(args, 'ticket_window_size', None),
            'media_send_mode': getattr(args, 'media_send_mode', 'evil0-only'),
            'fp_mode': args.fp_mode,
            'xff': summary_xff,
            'requested_xff': args.xff,
            'rotate_xff': summary_rotate_xff,
            'egress_proxy': str(getattr(args, 'egress_proxy', '') or ''),
            'egress_scope': str(getattr(args, 'egress_scope', 'detect') or 'detect'),
            'egress_proxy_pool': active_egress_pool,
            'egress_counts': egress_counts,
            'out_dir': str(out_dir),
            'results_jsonl': str(results_jsonl),
            'reports_dir': str(reports_dir),
            'xff_probe': xff_probe_summary,
            'risk_summary': risk_summary,
            'queue_health': {
                'used_xff_counts': used_xff_counts,
                'failed_xff_counts': failed_xff_counts,
                'failure_stage_counts': failure_stage_counts,
                'xff_pool': list(getattr(args, '_xff_pool', []) or []),
                'egress_proxy': str(getattr(args, 'egress_proxy', '') or ''),
                'egress_scope': str(getattr(args, 'egress_scope', 'detect') or 'detect'),
                'egress_proxy_pool': active_egress_pool,
                'egress_counts': egress_counts,
                'cdp_bound_pool': list(getattr(args, '_cdp_bound_pool', []) or []),
                'route_state': route_state,
                'preferred_xff_max_uses': batch_media_preferred_xff_max_uses(args),
                'max_attempt_count': max_attempt_count,
                'peak_active_workers': peak_active_workers,
                'observed_peak_concurrency': peak_active_workers,
                'risk_guard': risk_guard,
                'risk_window': risk_window,
                'risk_recovery': risk_recovery or {},
                'risk_events': risk_events,
                'risk_budget_exhausted': risk_stopped,
                'risk_stop_index': risk_stop_index,
                'cooldown_recommended_sec': risk_guard.get('cooldown_recommended_sec') if risk_stopped else 0,
                'remaining_manifest': remaining_manifest,
                'remaining_count': remaining_count,
                'resume_command': risk_resume_command,
                'stop_loss_recommended': bool(risk_summary.get('risk_stop_recommended')),
                'failure_stage': risk_failure_stage or risk_summary.get('risk_stop_reason') or ('' if logical_ok else (next(iter(failure_stage_counts), 'detect-failed'))),
                'agent_hint': risk_agent_hint,
            },
            'results': attempts,
            'next_command': (
                risk_resume_command
                if risk_resume_command
                else (
                f"matrix-ai-cli check-images --driver cdp --cdp-ws-mode {getattr(args, 'cdp_ws_mode', 'proxy')} --cdp-fp-source {getattr(args, 'cdp_fp_source', 'cli')} --out-dir {shlex.quote(str(out_dir))} --images-file <images.txt> --fp-mode fresh --route-mode auto --concurrency 1"
                if getattr(args, 'driver', 'pure') == 'cdp'
                else f"matrix-ai-cli check-images --driver pure --out-dir {shlex.quote(str(out_dir))} --images-file <images.txt> --fp-mode fresh --route-mode auto --concurrency 1 --ticket-phase serial"
                )
            ),
        },
    }
    return attach_check_images_top_level_aliases(summary)
