"""Batch media operations: multi-image queues, XFF rotation, risk guards."""
from __future__ import annotations

import argparse
import math
import os
import random
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    DEFAULT_MEDIA_ROTATE_XFF,
    DEFAULT_MEDIA_XFF,
    int_env,
)
from .transport import (
    make_fp,
    xff_for_iteration,
    rotate_xff_pool_for_pattern,
)
from .media_detect import (
    media_check_result,
)
from .browser_state import ensure_matrix_media_bound


def batch_media_make_resume_manifest(
    *,
    out_dir: Path,
    image_paths: list[Path],
    next_index: int,
) -> tuple[str, int]:
    if next_index > len(image_paths):
        return "", 0
    remaining = [str(path) for path in image_paths[next_index - 1:]]
    if not remaining:
        return "", 0
    path = out_dir / "remaining-images.txt"
    path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
    return str(path), len(remaining)



def discover_image_inputs(args: argparse.Namespace, *, dedupe: bool = True) -> list[Path]:
    exts = {".jpg", ".jpeg", ".png", ".webp"}
    effective_dedupe = dedupe and not bool(getattr(args, "allow_duplicate_images", False))
    seen: set[str] = set()
    out: list[Path] = []

    def add(path: Path) -> None:
        if path.suffix.lower() not in exts:
            return
        resolved = str(path.expanduser().resolve())
        if effective_dedupe and resolved in seen:
            return
        seen.add(resolved)
        out.append(Path(resolved))

    for item in getattr(args, "image_file", []) or []:
        add(Path(item))
    if getattr(args, "images_file", ""):
        for line in Path(args.images_file).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                add(Path(line))
    for directory in getattr(args, "image_dir", []) or []:
        root = Path(directory)
        if not root.exists():
            raise SystemExit(f"missing image directory: {root}")
        pattern = "**/*" if getattr(args, "recursive", False) else "*"
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                add(path)
    if not out:
        raise SystemExit("missing images; use --image-file, --image-dir, or --images-file")
    return out



def discover_remaining_image_inputs(path: str) -> list[Path]:
    args = argparse.Namespace(image_file=[], images_file=path, image_dir=[], recursive=False, allow_duplicate_images=True)
    return discover_image_inputs(args, dedupe=False)



def compact_batch_media_result(report: dict[str, Any], *, report_json: str) -> dict[str, Any]:
    out = media_check_result(report, report_json=report_json)
    out["input_size"] = report.get("input_size")
    return out



def batch_media_rotate_xff(args: argparse.Namespace) -> str:
    return args.rotate_xff or (DEFAULT_MEDIA_ROTATE_XFF if args.fp_mode == "fresh" and not args.xff else "")



def batch_media_preferred_xff(args: argparse.Namespace) -> str:
    preferred = str(getattr(args, "_preferred_xff", "") or "").strip()
    if not preferred:
        return ""
    max_uses = batch_media_preferred_xff_max_uses(args)
    use_count = max(0, int(getattr(args, "_preferred_xff_use_count", 0) or 0))
    return preferred if not max_uses or use_count < max_uses else ""



def batch_media_preferred_xff_max_uses(args: argparse.Namespace) -> int:
    raw = getattr(args, "preferred_xff_max_uses", -1)
    try:
        value = int(raw)
    except Exception:
        value = -1
    if value >= 0:
        return value
    if list(getattr(args, "_xff_pool", []) or []) and not getattr(args, "xff", ""):
        return max(1, int_env("MATRIX_AI_MEDIA_AUTO_PREFERRED_XFF_MAX_USES", 1))
    return 0



def batch_media_xff_for_item(args: argparse.Namespace, i: int) -> str:
    preferred = batch_media_preferred_xff(args)
    if preferred:
        return preferred
    pool = [str(x).strip() for x in (getattr(args, "_xff_pool", None) or []) if str(x).strip()]
    if pool:
        return pool[(max(1, i) - 1) % len(pool)]
    rotate_xff = batch_media_rotate_xff(args)
    return xff_for_iteration(rotate_xff, i) if rotate_xff else args.xff



def parse_egress_proxy_pool(values: list[str] | None) -> list[str]:
    return parse_rotate_xff_candidates(values)



def batch_media_egress_proxy_for_item(args: argparse.Namespace, i: int) -> str:
    pool = [str(x).strip() for x in (getattr(args, "_egress_proxy_pool", None) or []) if str(x).strip()]
    if pool:
        return pool[(max(1, i) - 1) % len(pool)]
    return str(getattr(args, "egress_proxy", "") or "").strip()



def batch_media_cdp_context_proxy_for_item(args: argparse.Namespace, i: int) -> str:
    pool = [str(x).strip() for x in (getattr(args, "_cdp_context_proxy_pool", None) or []) if str(x).strip()]
    if pool:
        return pool[(max(1, i) - 1) % len(pool)]
    return str(getattr(args, "cdp_context_proxy_server", "") or "").strip()



def batch_media_browser_version_url_for_item(args: argparse.Namespace, i: int) -> str:
    preferred = str(getattr(args, "_preferred_browser_version_url", "") or "").strip()
    if preferred:
        return preferred
    pool = [str(x).strip() for x in (getattr(args, "_browser_version_url_pool", None) or []) if str(x).strip()]
    if pool:
        return pool[(max(1, i) - 1) % len(pool)]
    return str(getattr(args, "cdp_browser_version_url", "") or "").strip()



def parse_cdp_bound_pool(values: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in values or []:
        for part in str(item).split(','):
            value = part.strip()
            if value and value not in seen:
                out.append(value)
                seen.add(value)
    return out



def apply_media_solve_risk_defaults(args: argparse.Namespace) -> None:
    if not bool(getattr(args, "solve_risk", False)):
        return
    args.driver = "cdp"
    args.cdp_ws_mode = "proxy"
    args.cdp_fp_source = "cli"
    if getattr(args, "cdp_target_mode", "extension-tab") not in {"extension-tab", "browser-context"}:
        args.cdp_target_mode = "extension-tab"
    args.cdp_new_tab = True
    args.cdp_close_tab = True
    args.cdp_auto_env = False
    args.cdp_auto_feedback = False
    args.cdp_auto_refresh_fp = False
    args.fp_mode = "fresh"
    args.fp = getattr(args, "fp", "") or ""
    if hasattr(args, "route_mode") and getattr(args, "route_mode", "auto") == "auto":
        args.route_mode = "auto"
    if hasattr(args, "xff_probe"):
        args.xff_probe = False
    if hasattr(args, "ticket_phase") and getattr(args, "ticket_phase", "parallel") == "parallel":
        args.ticket_phase = "parallel"
    if hasattr(args, "cdp_browser_pool_size"):
        args.cdp_browser_pool_size = max(0, int(getattr(args, "cdp_browser_pool_size", 0) or 0))
    if hasattr(args, "safe_queue") and bool(getattr(args, "safe_queue", False)):
        if int(getattr(args, "risk_window_size", 0) or 0) <= 0:
            args.risk_window_size = int_env("MATRIX_AI_SOLVE_RISK_WINDOW_SIZE", 3)
        if getattr(args, "risk_window_cooldown_sec", None) is None:
            args.risk_window_cooldown_sec = float(getattr(args, "risk_cooldown_sec", 300.0) or 300.0)



def batch_media_bound_for_item(args: argparse.Namespace, i: int) -> str:
    pool = [str(x).strip() for x in (getattr(args, "_cdp_bound_pool", None) or []) if str(x).strip()]
    if pool:
        return pool[(max(1, i) - 1) % len(pool)]
    return str(getattr(args, "bound", DEFAULT_BOUND) or DEFAULT_BOUND)



def ensure_cdp_media_bound_pool(args: argparse.Namespace, *, count: int) -> dict[str, Any]:
    apply_media_solve_risk_defaults(args)
    if getattr(args, "driver", "pure") != "cdp":
        return {"enabled": False, "reason": "driver-not-cdp"}
    if getattr(args, "cdp_target_mode", "extension-tab") != "extension-tab":
        return {"enabled": False, "reason": "target-not-extension-tab"}
    if bool(getattr(args, "cdp_new_tab", True)):
        return {"enabled": False, "reason": "new-tab-mode"}
    if getattr(args, "cdp_fp_source", "cli") != "browser":
        return {"enabled": False, "reason": "fp-source-not-browser"}
    explicit_pool = parse_cdp_bound_pool(getattr(args, "cdp_bound_pool", None) or [])
    requested = max(1, int(getattr(args, "concurrency", 1) or 1))
    pool_size = max(0, int(getattr(args, "cdp_browser_pool_size", 0) or 0))
    if not explicit_pool:
        if pool_size <= 0:
            pool_size = 1
        prefix = str(getattr(args, "cdp_bound_prefix", "") or getattr(args, "bound", DEFAULT_MEDIA_BOUND) or DEFAULT_MEDIA_BOUND)
        explicit_pool = [prefix] if pool_size == 1 else [f"{prefix}-{i}" for i in range(1, pool_size + 1)]
    if count <= 1 and pool_size <= 1 and explicit_pool:
        explicit_pool = explicit_pool[:1]
    setattr(args, "_cdp_bound_pool", explicit_pool)
    if explicit_pool and getattr(args, "bound", DEFAULT_BOUND) == DEFAULT_BOUND:
        args.bound = explicit_pool[0]
    if not bool(getattr(args, "cdp_auto_env", False)):
        return {
            "enabled": True,
            "prepared": False,
            "reason": "auto-env-disabled",
            "pool": explicit_pool,
            "pool_size": len(explicit_pool),
            "requested_concurrency": requested,
        }
    states: list[dict[str, Any]] = []
    force_new = bool(getattr(args, "cdp_force_new_bound", False))
    for bound in explicit_pool:
        states.append(ensure_matrix_media_bound(
            bound=bound,
            timeout=float(getattr(args, "cdp_env_timeout", 90.0) or 90.0),
            force_new=force_new,
            reset_fp=bool(getattr(args, "cdp_reset_bound_fp", False)),
            auto_refresh_fp=bool(getattr(args, "cdp_auto_refresh_fp", False)),
            refresh_threshold=int(getattr(args, "cdp_refresh_threshold", 1) or 1),
        ))
    if states:
        args.cdp_force_new_bound = False
    return {
        "enabled": True,
        "prepared": True,
        "pool": explicit_pool,
        "pool_size": len(explicit_pool),
        "requested_concurrency": requested,
        "states": states,
        "concurrency_capable": len(explicit_pool) >= requested,
    }



def batch_media_item_args(args: argparse.Namespace, image_path: Path, i: int) -> argparse.Namespace:
    item_args = argparse.Namespace(**vars(args))
    route_i = i + int(getattr(args, "_route_attempt_offset", getattr(args, "route_attempt_offset", 0)) or 0)
    item_args.image_file = str(image_path)
    item_args.xff = batch_media_xff_for_item(args, route_i)
    item_args.egress_proxy = batch_media_egress_proxy_for_item(args, route_i)
    item_args.egress_scope = str(getattr(args, "egress_scope", "detect") or "detect")
    item_args.cdp_browser_version_url = batch_media_browser_version_url_for_item(args, route_i)
    item_args.cdp_context_proxy_server = batch_media_cdp_context_proxy_for_item(args, route_i)
    item_args.bound = batch_media_bound_for_item(args, route_i)
    item_args.rotate_xff = batch_media_rotate_xff(args)
    item_args._batch_index = i
    item_args._route_slot = route_i
    item_args.out_json = ''
    return item_args



def batch_media_risk_window_config(args: argparse.Namespace) -> dict[str, Any]:
    safe_queue = bool(getattr(args, "safe_queue", False))
    size = max(0, int(getattr(args, "risk_window_size", 0) or 0))
    if safe_queue and size <= 0:
        size = int_env("MATRIX_AI_SOLVE_RISK_WINDOW_SIZE", 3)
    cooldown_raw = getattr(args, "risk_window_cooldown_sec", None)
    if cooldown_raw is None:
        cooldown = float(getattr(args, "risk_cooldown_sec", 300.0) or 300.0) if safe_queue else 0.0
    else:
        cooldown = max(0.0, float(cooldown_raw or 0.0))
    return {
        "enabled": size > 0,
        "safe_queue": safe_queue,
        "size": size,
        "cooldown_sec": cooldown,
    }



def batch_media_ticket_spacing(args: argparse.Namespace) -> tuple[float, float]:
    delay = getattr(args, 'ticket_delay_sec', None)
    jitter = getattr(args, 'ticket_jitter_sec', None)
    if delay is None:
        delay = getattr(args, 'delay_sec', 0)
    if jitter is None:
        jitter = getattr(args, 'jitter_sec', 0)
    return float(delay or 0), float(jitter or 0)



def batch_media_risk_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    evil_counts: dict[str, int] = {}
    payload_sent_count = 0
    status_counts: dict[str, int] = {}
    msg_counts: dict[str, int] = {}
    for item in results:
        captcha = item.get('captcha') or {}
        evil = captcha.get('evil_level')
        if evil is not None:
            evil_counts[str(evil)] = evil_counts.get(str(evil), 0) + 1
        if item.get('payload_sent'):
            payload_sent_count += 1
        status = str(item.get('status') or (item.get('result') or {}).get('status') or '').strip()
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
        msg = str(item.get('msg') or (item.get('result') or {}).get('msg') or (item.get('result') or {}).get('msg_en') or '').strip()
        if msg:
            msg_counts[msg[:160]] = msg_counts.get(msg[:160], 0) + 1
    risk_levels: list[int] = []
    for evil, count in evil_counts.items():
        try:
            evil_int = int(str(evil).strip())
        except Exception:
            continue
        if evil_int > 0:
            risk_levels.extend([evil_int] * count)
    risk_stop = bool(risk_levels)
    return {
        'evil_level_counts': evil_counts,
        'status_counts': status_counts,
        'msg_counts': msg_counts,
        'payload_sent_count': payload_sent_count,
        'risk_stop_recommended': risk_stop,
        'risk_stop_reason': f'captcha-evil-level-{max(risk_levels)}' if risk_stop else '',
    }



def batch_media_risk_summary_from_events(
    risk_events: list[dict[str, Any]],
    *,
    risk_guard: dict[str, Any],
    risk_stopped: bool,
    failure_stage: str,
) -> dict[str, Any]:
    evil_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    msg_counts: dict[str, int] = {}
    for event in risk_events:
        evil = str(event.get("evil_level") or "").strip()
        if evil:
            evil_counts[evil] = evil_counts.get(evil, 0) + 1
        status = str(event.get("status") or "").strip()
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
        msg = str(event.get("msg") or "").strip()
        if msg:
            msg_counts[msg[:160]] = msg_counts.get(msg[:160], 0) + 1
    return {
        "evil_level_counts": evil_counts,
        "status_counts": status_counts,
        "msg_counts": msg_counts,
        "payload_sent_count": 0,
        "risk_stop_recommended": bool(risk_stopped),
        "risk_stop_reason": failure_stage if risk_stopped else "",
        "risk_guard_enabled": bool(risk_guard.get("enabled")),
        "risk_budget": int(risk_guard.get("risk_budget") or 0),
        "risk_events": risk_events,
        "risk_budget_exhausted": bool(risk_stopped),
        "cooldown_recommended_sec": risk_guard.get("cooldown_recommended_sec") if risk_stopped else 0,
    }



def parse_rotate_xff_candidates(values: list[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        for part in str(raw).replace("\n", ",").split(","):
            item = part.strip()
            if not item or item in seen:
                continue
            seen.add(item)
            out.append(item)
    return out



def batch_media_default_xff_pool(args: argparse.Namespace, *, count: int) -> list[str]:
    if getattr(args, "driver", "pure") == "cdp" and getattr(args, "cdp_ws_mode", "proxy") != "proxy":
        return []
    if getattr(args, "xff", ""):
        return []
    if getattr(args, "fp_mode", "fresh") != "fresh":
        return []
    env_pool = parse_rotate_xff_candidates([os.environ.get("MATRIX_AI_MEDIA_XFF_POOL", "")])
    if env_pool:
        return env_pool[:max(1, count)]
    env_patterns = parse_rotate_xff_candidates([os.environ.get("MATRIX_AI_MEDIA_XFF_PATTERNS", "")])
    pattern_count = max(1, min(len(env_patterns), int_env("MATRIX_AI_MEDIA_XFF_PATTERN_COUNT", 8))) if env_patterns else int_env("MATRIX_AI_MEDIA_AUTO_XFF_PATTERN_COUNT", 8)
    per_pattern = int_env("MATRIX_AI_MEDIA_AUTO_XFF_PER_PATTERN", max(4, math.ceil(max(1, count) / max(1, pattern_count))))
    total_needed = max(max(1, count), pattern_count * max(1, per_pattern))
    if not env_patterns:
        base = random.randint(1, 239)
        env_patterns = [f"10.214.{(base + offset) % 240}.{{i}}" for offset in range(pattern_count)]
    out: list[str] = []
    seen: set[str] = set()
    for pattern in env_patterns[:pattern_count]:
        for xff in rotate_xff_pool_for_pattern(pattern, count=max(1, per_pattern), start=1):
            if xff and xff not in seen:
                seen.add(xff)
                out.append(xff)
            if len(out) >= total_needed:
                return out
    return out



def batch_media_should_auto_route(args: argparse.Namespace, *, count: int) -> bool:
    mode = str(getattr(args, "route_mode", "auto") or "auto")
    if mode == "off":
        return False
    if getattr(args, "driver", "pure") == "cdp" and getattr(args, "cdp_ws_mode", "proxy") != "proxy":
        return False
    if getattr(args, "xff", ""):
        return False
    if getattr(args, "rotate_xff", ""):
        return False
    if list(getattr(args, "_xff_pool", []) or []):
        return False
    return mode in {"on", "auto"} and getattr(args, "fp_mode", "fresh") == "fresh"



def batch_media_compact_failure_stage(item: dict[str, Any]) -> str:
    if item.get("ok"):
        return ""
    if item.get("failure_stage"):
        return str(item.get("failure_stage") or "")
    captcha = item.get("captcha") or {}
    evil = str(captcha.get("evil_level") or "")
    if evil and evil != "0":
        return f"captcha-evil-level-{evil}"
    msg = str(item.get("msg") or (item.get("result") or {}).get("msg") or (item.get("result") or {}).get("msg_en") or item.get("error") or "").strip().lower()
    status = str(item.get("status") or (item.get("result") or {}).get("status") or "").strip().lower()
    if (
        "missing media ticket" in msg
        or "missing input file" in msg
        or "empty image file" in msg
        or "empty video file" in msg
        or "unsupported" in msg
        or "missing fp" in msg
    ):
        return "input-error"
    if "invalid request" in msg:
        return "invalid-request"
    if "ticket" in msg or status == "ticket-rejected":
        return "ticket-rejected"
    if status:
        return status
    if item.get("error"):
        return "exception"
    return "detect-failed"



def batch_media_apply_result_route_feedback(args: argparse.Namespace, item_args: argparse.Namespace, compact: dict[str, Any]) -> None:
    xff = str(compact.get('xff') or getattr(item_args, 'xff', '') or '').strip()
    if xff:
        if not compact.get('xff'):
            compact['xff'] = xff
        used = dict(getattr(args, '_used_xff_counts', {}) or {})
        used[xff] = int(used.get(xff, 0) or 0) + 1
        setattr(args, '_used_xff_counts', used)
    if compact.get('ok'):
        if getattr(args, "rotate_xff", "") and not list(getattr(args, "_xff_pool", []) or []):
            return
        preferred_xff = xff
        if preferred_xff:
            current_preferred_xff = str(getattr(args, '_preferred_xff', '') or '').strip()
            preferred_xff_use_count = int(getattr(args, '_preferred_xff_use_count', 0) or 0)
            if preferred_xff == current_preferred_xff:
                preferred_xff_use_count += 1
            else:
                preferred_xff_use_count = 1
            preferred_xff_max_uses = batch_media_preferred_xff_max_uses(args)
            if preferred_xff_max_uses > 0 and preferred_xff_use_count >= preferred_xff_max_uses:
                setattr(args, '_preferred_xff', '')
                setattr(args, '_preferred_xff_use_count', 0)
                rotated = list(getattr(args, '_rotated_preferred_xff', []) or [])
                rotated.append(preferred_xff)
                setattr(args, '_rotated_preferred_xff', rotated[-50:])
            else:
                setattr(args, '_preferred_xff', preferred_xff)
                setattr(args, '_preferred_xff_use_count', preferred_xff_use_count)
        preferred_browser_url = str(compact.get('cdp_browser_version_url') or getattr(item_args, 'cdp_browser_version_url', '') or '').strip()
        if preferred_browser_url:
            setattr(args, '_preferred_browser_version_url', preferred_browser_url)
        return
    stage = batch_media_compact_failure_stage(compact)
    if xff:
        failed = dict(getattr(args, '_failed_xff_counts', {}) or {})
        failed[xff] = int(failed.get(xff, 0) or 0) + 1
        setattr(args, '_failed_xff_counts', failed)
        if str(getattr(args, '_preferred_xff', '') or '') == xff:
            setattr(args, '_preferred_xff', '')
            setattr(args, '_preferred_xff_use_count', 0)
    if stage:
        stages = dict(getattr(args, '_failure_stage_counts', {}) or {})
        stages[stage] = int(stages.get(stage, 0) or 0) + 1
        setattr(args, '_failure_stage_counts', stages)



def batch_media_egress_counts(attempts: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in attempts:
        key = str(item.get("egress_public_ip") or "").strip()
        if not key:
            egress = item.get("egress") if isinstance(item.get("egress"), dict) else {}
            key = str(egress.get("public_ip") or egress.get("proxy") or item.get("egress_proxy") or "").strip()
        if key:
            counts[key] = counts.get(key, 0) + 1
    return counts



def batch_media_slice_for_indices(image_paths: list[Path], indices: list[int]) -> list[Path]:
    return [image_paths[i - 1] for i in indices if 1 <= i <= len(image_paths)]



def batch_media_extend_xff_pool_for_retry(args: argparse.Namespace, *, needed_index: int) -> None:
    pool = list(getattr(args, "_xff_pool", []) or [])
    if not pool:
        return
    if needed_index <= len(pool):
        return
    extra = batch_media_default_xff_pool(args, count=needed_index)
    seen = set(pool)
    for xff in extra:
        if xff and xff not in seen:
            seen.add(xff)
            pool.append(xff)
        if len(pool) >= needed_index:
            break
    setattr(args, "_xff_pool", pool)
