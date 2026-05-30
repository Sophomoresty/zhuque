"""CLI drain queue command for high-count image batches."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import shlex
import sys
import time
from pathlib import Path
from typing import Any

from .transport import json_dump
from .text_detect import write_json_file
from .batch import apply_media_solve_risk_defaults, discover_image_inputs
from .batch_queue import batch_media_input_error_summary
from .cli_batch import cmd_check_images


def _append_flag(parts: list[str], flag: str, value: Any) -> None:
    if value is None:
        return
    text = str(value)
    if not text:
        return
    parts.extend([flag, text])


def _append_bool_flag(parts: list[str], flag: str, value: Any, *, default: bool | None = None) -> None:
    if value is None:
        return
    enabled = bool(value)
    if default is not None and enabled == default:
        return
    if enabled:
        parts.append(flag)
    else:
        name = flag[2:] if flag.startswith("--") else flag
        parts.append(f"--no-{name}")


def _build_resume_command(args: argparse.Namespace, images_file: str, *, drain_reset: bool = False) -> str:
    parts = [
        "matrix-ai-cli",
        "check-images-drain",
        "--out-dir",
        str(getattr(args, "out_dir", "") or ""),
        "--driver",
        str(getattr(args, "driver", "pure") or "pure"),
        "--fp-mode",
        str(getattr(args, "fp_mode", "fresh") or "fresh"),
        "--route-mode",
        str(getattr(args, "route_mode", "auto") or "auto"),
        "--media-send-mode",
        str(getattr(args, "media_send_mode", "on-code") or "on-code"),
        "--ticket-phase",
        str(getattr(args, "ticket_phase", "serial") or "serial"),
        "--ticket-window-size",
        str(getattr(args, "ticket_window_size", 0) or 0),
        "--concurrency",
        str(getattr(args, "concurrency", 1) or 1),
        "--drain-window-size",
        str(getattr(args, "drain_window_size", 0) or 0),
        "--drain-max-windows",
        str(getattr(args, "drain_max_windows", 1) or 1),
        "--drain-cooldown-sec",
        str(getattr(args, "drain_cooldown_sec", 0.0) or 0.0),
        "--allow-duplicate-images",
    ]
    if not bool(getattr(args, "auto_ticket", True)):
        parts.append("--no-auto-ticket")
    _append_flag(parts, "--fp", getattr(args, "fp", ""))
    _append_flag(parts, "--ticket", getattr(args, "ticket", ""))
    _append_flag(parts, "--randstr", getattr(args, "randstr", ""))
    _append_flag(parts, "--ticket-json", getattr(args, "ticket_json", ""))
    _append_flag(parts, "--ticket-command", getattr(args, "ticket_command", ""))
    if getattr(args, "ticket_phase", "serial") == "browser-pool":
        _append_flag(parts, "--browser-pool-bound", getattr(args, "browser_pool_bound", ""))
        _append_flag(parts, "--browser-pool-session-id", getattr(args, "browser_pool_session_id", ""))
        _append_flag(parts, "--browser-pool-max-uses", getattr(args, "browser_pool_max_uses", ""))
        _append_flag(parts, "--browser-pool-cooldown", getattr(args, "browser_pool_cooldown", ""))
    _append_flag(parts, "--images-file", images_file)
    for image_file in getattr(args, "image_file", []) or []:
        _append_flag(parts, "--image-file", image_file)
    for image_dir in getattr(args, "image_dir", []) or []:
        _append_flag(parts, "--image-dir", image_dir)
    _append_flag(parts, "--xff", getattr(args, "xff", ""))
    _append_flag(parts, "--rotate-xff", getattr(args, "rotate_xff", ""))
    for xff in getattr(args, "xff_pool", []) or []:
        _append_flag(parts, "--xff-pool", xff)
    _append_flag(parts, "--egress-proxy", getattr(args, "egress_proxy", ""))
    for proxy in getattr(args, "egress_proxy_pool", []) or []:
        _append_flag(parts, "--egress-proxy-pool", proxy)
    if getattr(args, "driver", "pure") == "cdp":
        for flag, attr in [
            ("--cdp-ws-mode", "cdp_ws_mode"),
            ("--cdp-fp-source", "cdp_fp_source"),
            ("--cdp-target-mode", "cdp_target_mode"),
            ("--cdp-browser-ws-endpoint", "cdp_browser_ws_endpoint"),
            ("--cdp-browser-version-url", "cdp_browser_version_url"),
            ("--cdp-browser-state-file", "cdp_browser_state_file"),
            ("--cdp-context-proxy-server", "cdp_context_proxy_server"),
            ("--cdp-tab-wait-sec", "cdp_tab_wait_sec"),
            ("--cdp-env-timeout", "cdp_env_timeout"),
            ("--cdp-refresh-threshold", "cdp_refresh_threshold"),
            ("--cdp-browser-pool-size", "cdp_browser_pool_size"),
            ("--cdp-bound-prefix", "cdp_bound_prefix"),
            ("--bound", "bound"),
            ("--session-id", "session_id"),
        ]:
            _append_flag(parts, flag, getattr(args, attr, ""))
        for value in getattr(args, "cdp_browser_version_url_pool", []) or []:
            _append_flag(parts, "--cdp-browser-version-url-pool", value)
        for value in getattr(args, "cdp_context_proxy_pool", []) or []:
            _append_flag(parts, "--cdp-context-proxy-pool", value)
        for value in getattr(args, "cdp_bound_pool", []) or []:
            _append_flag(parts, "--cdp-bound-pool", value)
        _append_bool_flag(parts, "--cdp-reset-browser-fp", getattr(args, "cdp_reset_browser_fp", None))
        _append_bool_flag(parts, "--cdp-new-tab", getattr(args, "cdp_new_tab", True), default=True)
        _append_bool_flag(parts, "--cdp-close-tab", getattr(args, "cdp_close_tab", True), default=True)
        _append_bool_flag(parts, "--cdp-auto-env", getattr(args, "cdp_auto_env", False), default=False)
        _append_bool_flag(parts, "--cdp-force-new-bound", getattr(args, "cdp_force_new_bound", False), default=False)
        _append_bool_flag(parts, "--cdp-reset-bound-fp", getattr(args, "cdp_reset_bound_fp", False), default=False)
        _append_bool_flag(parts, "--cdp-auto-refresh-fp", getattr(args, "cdp_auto_refresh_fp", False), default=False)
        _append_bool_flag(parts, "--cdp-auto-feedback", getattr(args, "cdp_auto_feedback", False), default=False)
    if getattr(args, "recursive", False):
        parts.append("--recursive")
    if getattr(args, "retry_risk", False):
        parts.append("--retry-risk")
    if getattr(args, "refresh_fp_on_retry", False):
        parts.append("--refresh-fp-on-retry")
    if getattr(args, "solve_risk", False):
        parts.append("--solve-risk")
    if getattr(args, "captcha_xff_mode", "none") != "none":
        parts.extend(["--captcha-xff-mode", str(getattr(args, "captcha_xff_mode"))])
    if getattr(args, "tdc_profile_mode", "fixed") != "fixed":
        parts.extend(["--tdc-profile-mode", str(getattr(args, "tdc_profile_mode"))])
    if getattr(args, "no_risk_guard", False):
        parts.append("--no-risk-guard")
    if drain_reset:
        parts.append("--drain-reset")
    return " ".join(shlex.quote(part) for part in parts if str(part))


def cmd_check_images_drain(args: argparse.Namespace) -> int:
    _cli = sys.modules.get("matrix_ai_cli.cli")
    if _cli is not None:
        import matrix_ai_cli.media_batch_job as _media_batch_job
        patched = getattr(_cli, "run_media_report", None)
        if patched is not None:
            _media_batch_job.run_media_report = patched
    apply_media_solve_risk_defaults(args)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dedupe_overridden = False
    if getattr(args, "images_file", "") and not bool(getattr(args, "allow_duplicate_images", False)):
        args.allow_duplicate_images = True
        dedupe_overridden = True
    try:
        image_paths = discover_image_inputs(args)
    except (OSError, SystemExit, ValueError) as exc:
        summary = batch_media_input_error_summary(args, error=exc, route_mode=str(getattr(args, "route_mode", "auto") or "auto"), route_notes=["drain-input-error"])
        write_json_file(out_dir / "drain-summary.json", summary)
        json_dump(summary)
        return 2
    requested_count = len(image_paths)
    completed_manifest = out_dir / "completed-indices.txt"
    completed: set[int] = set()
    if completed_manifest.exists() and not bool(getattr(args, "drain_reset", False)):
        for line in completed_manifest.read_text(encoding="utf-8").splitlines():
            with contextlib.suppress(Exception):
                completed.add(int(line.strip()))
    attempts: list[dict[str, Any]] = []
    remaining_manifest = out_dir / "drain-remaining-images.txt"
    max_windows = max(1, int(getattr(args, "drain_max_windows", 1) or 1))
    target_success = max(1, int(getattr(args, "drain_target_success", requested_count) or requested_count))
    cooldown_sec = max(0.0, float(getattr(args, "drain_cooldown_sec", 0.0) or 0.0))
    stop_reason = ""
    windows_run = 0
    peak_active_workers = 0
    route_attempt_offset = 0
    base_args = argparse.Namespace(**vars(args))
    base_args.allow_duplicate_images = True
    base_args.repeat_each = 1
    base_args.stop_on_fail = False
    base_args.risk_recover = False
    base_args.out_json = ""
    queue: list[tuple[int, Path]] = [(i, p) for i, p in enumerate(image_paths, start=1)]
    if completed:
        queue = [(i, p) for i, p in queue if i not in completed]
    for window_index in range(1, max_windows + 1):
        if not queue or len(completed) >= target_success:
            break
        window_size = max(1, int(getattr(args, "drain_window_size", 0) or getattr(args, "ticket_window_size", 0) or getattr(args, "concurrency", 1) or 1))
        selected = queue[:window_size]
        queue = queue[window_size:]
        manifest = out_dir / f"drain-window-{window_index:04d}.txt"
        manifest.write_text("\n".join(str(path) for _, path in selected) + "\n", encoding="utf-8")
        child_out = out_dir / f"window-{window_index:04d}"
        child_args = argparse.Namespace(**vars(base_args))
        child_args.images_file = str(manifest)
        child_args.image_file = []
        child_args.image_dir = []
        child_args.out_dir = str(child_out)
        child_args.allow_duplicate_images = True
        child_args.repeat_each = 1
        child_args.risk_recover = False
        child_args.stop_on_fail = False
        child_args.risk_budget = max(0, int(getattr(args, "risk_budget", 0) or 0))
        child_args.risk_window_size = 0
        child_args.safe_queue = False
        child_args.out_json = ""
        child_args.route_attempt_offset = route_attempt_offset
        child_stdout = io.StringIO()
        with contextlib.redirect_stdout(child_stdout):
            rc = cmd_check_images(child_args)
        child_stdout_path = out_dir / f"drain-window-{window_index:04d}-stdout.txt"
        child_stdout_path.write_text(child_stdout.getvalue(), encoding="utf-8")
        windows_run += 1
        route_attempt_offset += len(selected) * max(1, int(getattr(child_args, "attempts", 1) or 1))
        summary_path = child_out / "summary.json"
        child_summary: dict[str, Any] = {}
        if summary_path.exists():
            child_summary = json.loads(summary_path.read_text(encoding="utf-8"))
        child_data = child_summary.get("data") if isinstance(child_summary.get("data"), dict) else {}
        child_peak = max(0, int(child_data.get("peak_active_workers") or child_summary.get("peak_active_workers") or 0))
        peak_active_workers = max(peak_active_workers, child_peak)
        rows: list[dict[str, Any]] = []
        results_path = child_out / "results.jsonl"
        selected_successes: set[int] = set()
        if results_path.exists():
            for line in results_path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                local_i = int(item.get("i") or 0)
                if 1 <= local_i <= len(selected):
                    global_i = selected[local_i - 1][0]
                    item["window_i"] = local_i
                    item["i"] = global_i
                    item["drain_window"] = window_index
                    if item.get("report_json"):
                        item["window_report_json"] = item.get("report_json")
                    if item.get("ok"):
                        completed.add(global_i)
                        selected_successes.add(local_i)
                rows.append(item)
        selected_failures = [selected[i - 1] for i in range(1, len(selected) + 1) if i not in selected_successes]
        queue.extend(selected_failures)
        attempts.extend(rows)
        completed_manifest.write_text("\n".join(str(i) for i in sorted(completed)) + ("\n" if completed else ""), encoding="utf-8")
        remaining_manifest.write_text("\n".join(str(path) for _, path in queue) + ("\n" if queue else ""), encoding="utf-8")
        event = {
            "window": window_index,
            "rc": rc,
            "selected_count": len(selected),
            "window_ok": child_summary.get("ok"),
            "window_success_count": child_data.get("success_count"),
            "window_failure_count": child_data.get("failure_count"),
            "window_peak_active_workers": child_peak,
            "route_attempt_offset": int(getattr(child_args, "route_attempt_offset", 0) or 0),
            "completed_count": len(completed),
            "remaining_count": len(queue),
            "summary_json": str(summary_path),
            "stdout_path": str(child_stdout_path),
        }
        write_json_file(out_dir / f"drain-window-{window_index:04d}-event.json", event)
        if not queue or len(completed) >= target_success:
            stop_reason = "target-complete"
            break
        if rc == 143:
            stop_reason = "interrupted"
            break
        if cooldown_sec > 0 and window_index < max_windows:
            time.sleep(cooldown_sec)
    remaining = list(queue)
    if not stop_reason:
        stop_reason = "target-complete" if len(completed) >= target_success else "max-windows-exhausted"
    results_jsonl = out_dir / "drain-results.jsonl"
    with results_jsonl.open("w", encoding="utf-8") as fh:
        for item in attempts:
            fh.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
    success_count = len(completed)
    failure_count = requested_count - success_count
    resume_images_file = str(remaining_manifest) if remaining else str(getattr(args, "images_file", "") or "")
    resume_command = _build_resume_command(args, resume_images_file, drain_reset=bool(remaining))
    summary = {
        "ok": success_count >= target_success and success_count == requested_count,
        "command": "check-images-drain",
        "data": {
            "protocol_mode": getattr(args, "driver", "pure"),
            "media_type": "image",
            "count_requested": requested_count,
            "target_success": target_success,
            "success_count": success_count,
            "failure_count": failure_count,
            "count_executed": len(attempts),
            "attempt_row_count": len(attempts),
            "requested_concurrency": max(1, int(getattr(args, "concurrency", 1) or 1)),
            "concurrency": max(1, int(getattr(args, "concurrency", 1) or 1)),
            "peak_active_workers": peak_active_workers,
            "observed_peak_concurrency": peak_active_workers,
            "window_size": max(1, int(getattr(args, "drain_window_size", 0) or getattr(args, "ticket_window_size", 0) or getattr(args, "concurrency", 1) or 1)),
            "windows_run": windows_run,
            "max_windows": max_windows,
            "cooldown_sec": cooldown_sec,
            "media_send_mode": getattr(args, "media_send_mode", "evil0-only"),
            "dedupe_overridden": dedupe_overridden,
            "ticket_phase": getattr(args, "ticket_phase", "serial"),
            "ticket_window_size": getattr(args, "ticket_window_size", None),
            "route_attempt_offset": route_attempt_offset,
            "out_dir": str(out_dir),
            "results_jsonl": str(results_jsonl),
            "completed_manifest": str(completed_manifest),
            "remaining_manifest": str(remaining_manifest) if remaining else "",
            "remaining_count": len(remaining),
            "stop_reason": stop_reason,
            "queue_health": {
                "internal_queue": True,
                "window_size": max(1, int(getattr(args, "drain_window_size", 0) or getattr(args, "ticket_window_size", 0) or getattr(args, "concurrency", 1) or 1)),
                "windows_run": windows_run,
                "peak_active_workers": peak_active_workers,
                "observed_peak_concurrency": peak_active_workers,
                "completed_count": success_count,
                "remaining_count": len(remaining),
                "remaining_manifest": str(remaining_manifest) if remaining else "",
                "agent_hint": "ok" if success_count == requested_count else "rerun-same-command-to-resume",
                "resume_command": "" if success_count == requested_count else resume_command,
            },
            "results": attempts,
        },
    }
    summary.update({
        "ok": summary["ok"],
        "success_count": success_count,
        "failure_count": failure_count,
        "count_requested": requested_count,
        "count_executed": summary["data"]["count_executed"],
        "requested_concurrency": summary["data"]["requested_concurrency"],
        "concurrency": summary["data"]["concurrency"],
        "peak_active_workers": summary["data"]["peak_active_workers"],
        "observed_peak_concurrency": summary["data"]["observed_peak_concurrency"],
        "failure_stage": "" if summary["ok"] else stop_reason,
        "agent_hint": summary["data"]["queue_health"]["agent_hint"],
        "next_command": summary["data"]["queue_health"]["resume_command"],
    })
    write_json_file(out_dir / "drain-summary.json", summary)
    if getattr(args, "out_json", ""):
        write_json_file(Path(args.out_json), summary)
    json_dump(summary)
    return 0 if summary["ok"] else 2
