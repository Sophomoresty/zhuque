"""CLI batch media commands: check-images, check-video, stress-media."""
from __future__ import annotations

import argparse
import contextlib
import json
import random
import shlex
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_MEDIA_XFF,
    int_env,
)
from .transport import (
    build_ws_headers,
    json_dump,
    make_fp_for_mode,
    parse_cdp_context_proxy_pool,
)
from .text_detect import (
    namespace_clone,
    write_json_file,
)
from .media_detect import (
    attach_check_images_top_level_aliases,
    issue_media_ticket,
    media_risk_event_from_compact,
    media_risk_guard_config,
)
from .media_batch_job import (
    run_batch_media_detect_job,
    run_media_report,
)
from .browser_pool_batch import run_browser_pool_windows
from .batch import (
    apply_media_solve_risk_defaults,
    batch_media_apply_result_route_feedback,
    batch_media_browser_version_url_for_item,
    batch_media_cdp_context_proxy_for_item,
    batch_media_compact_failure_stage,
    batch_media_default_xff_pool,
    batch_media_egress_proxy_for_item,
    batch_media_egress_counts,
    batch_media_extend_xff_pool_for_retry,
    batch_media_item_args,
    batch_media_make_resume_manifest,
    batch_media_risk_summary_from_events,
    batch_media_risk_window_config,
    batch_media_should_auto_route,
    batch_media_ticket_spacing,
    batch_media_xff_for_item,
    compact_batch_media_result,
    discover_image_inputs,
    discover_remaining_image_inputs,
    ensure_cdp_media_bound_pool,
    parse_egress_proxy_pool,
    parse_rotate_xff_candidates,
)
from .batch_queue import (
    batch_media_input_error_summary,
    check_images_finalize_summary,
    probe_rotate_xff_candidates,
)


def cmd_check_images(args: argparse.Namespace) -> int:
    import sys
    _cli = sys.modules.get('matrix_ai_cli.cli')
    _run_media_report = getattr(_cli, 'run_media_report', None) or run_media_report
    apply_media_solve_risk_defaults(args)
    browser_version_url_pool = [str(x).strip() for x in (getattr(args, 'cdp_browser_version_url_pool', None) or []) if str(x).strip()]
    if browser_version_url_pool:
        setattr(args, '_browser_version_url_pool', browser_version_url_pool)
    egress_proxy_pool = parse_egress_proxy_pool(getattr(args, 'egress_proxy_pool', None) or [])
    if egress_proxy_pool:
        setattr(args, '_egress_proxy_pool', egress_proxy_pool)
    xff_pool = parse_rotate_xff_candidates(getattr(args, 'xff_pool', None) or [])
    route_mode = str(getattr(args, 'route_mode', 'auto') or 'auto')
    route_notes: list[str] = []
    cdp_context_proxy_pool = parse_cdp_context_proxy_pool(getattr(args, 'cdp_context_proxy_pool', None) or [])
    if cdp_context_proxy_pool:
        setattr(args, '_cdp_context_proxy_pool', cdp_context_proxy_pool)
        route_notes.append('cdp-context-proxy-pool')
    if xff_pool:
        setattr(args, '_xff_pool', xff_pool)
        args.rotate_xff = ''
        route_notes.append('explicit-xff-pool')
    if egress_proxy_pool:
        route_notes.append('egress-proxy-pool')
    out_dir = Path(args.out_dir)
    reports_dir = out_dir / 'reports'
    out_dir.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)
    try:
        base_image_paths = discover_image_inputs(args)
    except (OSError, SystemExit, ValueError) as exc:
        summary = batch_media_input_error_summary(args, error=exc, route_mode=route_mode, route_notes=route_notes)
        if getattr(args, 'out_json', ''):
            write_json_file(Path(args.out_json), summary)
        return 2
    repeat_each = max(1, int(getattr(args, 'repeat_each', 1) or 1))
    image_paths = [path for path in base_image_paths for _ in range(repeat_each)]
    if route_mode == 'on' and not list(getattr(args, '_xff_pool', []) or []) and not getattr(args, 'xff', '') and not getattr(args, 'rotate_xff', '') and not batch_media_should_auto_route(args, count=len(image_paths)):
        summary = batch_media_input_error_summary(args, error='route-mode=on requires --xff, --xff-pool, --rotate-xff, or --fp-mode fresh auto pool', route_mode=route_mode, route_notes=route_notes)
        if getattr(args, 'out_json', ''):
            write_json_file(Path(args.out_json), summary)
        return 2
    elif batch_media_should_auto_route(args, count=len(image_paths)):
        auto_pool = batch_media_default_xff_pool(args, count=len(image_paths))
        if auto_pool:
            setattr(args, '_xff_pool', auto_pool)
            args.rotate_xff = ''
            route_notes.append('auto-xff-pool')
    cdp_pool_summary = ensure_cdp_media_bound_pool(args, count=len(image_paths))
    if cdp_pool_summary.get('enabled'):
        route_notes.append(f"cdp-real-browser-pool:{cdp_pool_summary.get('pool_size', 0)}")
        if cdp_pool_summary.get('prepared'):
            route_notes.append('cdp-auto-env')
        if getattr(args, 'cdp_auto_feedback', False):
            route_notes.append('cdp-auto-feedback')
    xff_probe_summary = {"enabled": False}
    if getattr(args, 'xff_probe', False):
        xff_probe_summary = probe_rotate_xff_candidates(args, base_image_paths=base_image_paths, out_dir=out_dir)
        if not xff_probe_summary.get('ok'):
            probe_risk_events = xff_probe_summary.get('risk_events', []) if isinstance(xff_probe_summary.get('risk_events', []), list) else []
            probe_risk_guard = xff_probe_summary.get('risk_guard') if isinstance(xff_probe_summary.get('risk_guard'), dict) else media_risk_guard_config(args)
            probe_failure_stage = xff_probe_summary.get('failure_stage') or 'xff-probe-failed'
            probe_stop_loss = bool(xff_probe_summary.get('stop_loss_recommended', True))
            probe_risk_summary = batch_media_risk_summary_from_events(
                probe_risk_events,
                risk_guard=probe_risk_guard,
                risk_stopped=probe_stop_loss,
                failure_stage=probe_failure_stage,
            )
            summary = {
                'ok': False,
                'command': 'check-images',
                'data': {
                    'protocol_mode': getattr(args, 'driver', 'pure'),
                    'media_type': 'image',
                    'unique_input_count': len(base_image_paths),
                    'repeat_each': repeat_each,
                    'count_requested': len(image_paths),
                    'count_executed': 0,
                    'success_count': 0,
                    'failure_count': 0,
                    'concurrency': max(1, int(getattr(args, 'concurrency', 1) or 1)),
                    'ticket_phase': getattr(args, 'ticket_phase', 'parallel'),
                    'fp_mode': args.fp_mode,
                    'xff': args.xff,
                    'requested_xff': args.xff,
                    'rotate_xff': args.rotate_xff or '',
                    'out_dir': str(out_dir),
                    'results_jsonl': str(out_dir / 'results.jsonl'),
                    'reports_dir': str(reports_dir),
                    'xff_probe': xff_probe_summary,
                    'risk_summary': probe_risk_summary,
                    'queue_health': {
                        'route_state': {
                            'mode': route_mode,
                            'notes': route_notes,
                            'pool_size': len(list(getattr(args, '_xff_pool', []) or [])),
                            'egress_scope': str(getattr(args, 'egress_scope', 'detect') or 'detect'),
                            'egress_proxy_enabled': bool(str(getattr(args, 'egress_proxy', '') or '') or list(getattr(args, '_egress_proxy_pool', []) or [])),
                            'egress_proxy_pool_size': len(list(getattr(args, '_egress_proxy_pool', []) or [])),
                        },
                        'risk_guard': probe_risk_guard,
                        'failure_stage': probe_failure_stage,
                        'stop_loss_recommended': probe_stop_loss,
                        'cooldown_recommended_sec': xff_probe_summary.get('cooldown_recommended_sec', 0),
                        'risk_events': probe_risk_events,
                        'risk_budget_exhausted': bool(xff_probe_summary.get('risk_budget_exhausted', False)),
                        'agent_hint': 'cooldown-and-retry-later' if probe_stop_loss else 'fix-route',
                    },
                    'results': [],
                    'next_command': f"matrix-ai-cli check-images --driver pure --out-dir {shlex.quote(str(out_dir))} --images-file <images.txt> --fp-mode fresh --xff-probe --xff-probe-pattern '10.216.16.{{i}}' --xff-probe-pattern '10.216.17.{{i}}' --concurrency 1 --ticket-phase serial",
                },
            }
            summary = attach_check_images_top_level_aliases(summary)
            write_json_file(out_dir / 'summary.json', summary)
            json_dump(summary)
            return 2
    results_jsonl = out_dir / 'results.jsonl'
    attempts: list[dict[str, Any]] = []
    success_count = 0
    risk_guard = media_risk_guard_config(args)
    risk_events: list[dict[str, Any]] = []
    risk_stopped = False
    risk_stop_index = 0
    risk_failure_stage = ""
    risk_recover_enabled = bool(getattr(args, "risk_recover", False))
    risk_recover_events = 0
    risk_recover_max_events = max(0, int(getattr(args, "risk_recover_max_events", 20) or 0))
    risk_recover_cooldown_sec = max(0.0, float(getattr(args, "risk_recover_cooldown_sec", None) if getattr(args, "risk_recover_cooldown_sec", None) is not None else getattr(args, "risk_cooldown_sec", 300.0) or 0.0))
    risk_recovery: dict[str, Any] = {
        "enabled": risk_recover_enabled,
        "max_events": risk_recover_max_events,
        "cooldown_sec": risk_recover_cooldown_sec,
        "events": [],
    }
    active_lock = threading.Lock()
    active_workers = 0
    peak_active_workers = 0

    def enter_worker() -> None:
        nonlocal active_workers, peak_active_workers
        with active_lock:
            active_workers += 1
            peak_active_workers = max(peak_active_workers, active_workers)

    def exit_worker() -> None:
        nonlocal active_workers
        with active_lock:
            active_workers -= 1

    def record_batch_compact(item_args: argparse.Namespace, compact: dict[str, Any]) -> bool:
        nonlocal success_count, risk_stopped, risk_stop_index, risk_failure_stage
        ok = bool(compact.get('ok'))
        if ok:
            success_count += 1
        batch_media_apply_result_route_feedback(args, item_args, compact)
        attempts.append(compact)
        risk_event = media_risk_event_from_compact(compact)
        if risk_guard.get("enabled") and risk_event:
            risk_events.append(risk_event)
            if len(risk_events) > int(risk_guard.get("risk_budget") or 0):
                if not (risk_recover_enabled and risk_recover_events < risk_recover_max_events):
                    risk_stopped = True
                index_raw = compact.get("i") or getattr(item_args, "_batch_index", None) or len(attempts)
                try:
                    risk_stop_index = max(1, min(len(image_paths), int(index_raw)))
                except Exception:
                    risk_stop_index = max(1, min(len(image_paths), len(attempts)))
                risk_failure_stage = str(risk_event.get("failure_stage") or "captcha-risk")
                compact["risk_guard_stopped"] = True
        return ok

    def should_recover_risk(compact: dict[str, Any]) -> bool:
        return bool(risk_recover_enabled and media_risk_event_from_compact(compact) and risk_recover_events < risk_recover_max_events)

    def recover_item_after_risk(item_args: argparse.Namespace, image_path: Path, i: int, jsonl: Any, *, base_report_path: Path) -> dict[str, Any] | None:
        nonlocal success_count, risk_recover_events, risk_stopped
        if not risk_recover_enabled:
            return None
        while risk_recover_events < risk_recover_max_events:
            risk_recover_events += 1
            retry_i = len(image_paths) + risk_recover_events
            batch_media_extend_xff_pool_for_retry(args, needed_index=retry_i)
            if risk_recover_cooldown_sec > 0:
                time.sleep(risk_recover_cooldown_sec)
            retry_args = namespace_clone(item_args)
            retry_args.xff = batch_media_xff_for_item(args, retry_i)
            retry_args.egress_proxy = batch_media_egress_proxy_for_item(args, retry_i)
            retry_args.cdp_browser_version_url = batch_media_browser_version_url_for_item(args, retry_i)
            retry_args.cdp_context_proxy_server = batch_media_cdp_context_proxy_for_item(args, retry_i)
            retry_args.fp = ''
            setattr(retry_args, '_prepared_fp', '')
            setattr(retry_args, '_batch_index', i)
            retry_report_path = reports_dir / f'{i:06d}-{image_path.stem}-recover-{risk_recover_events:02d}.json'
            started = time.time()
            compact_retry = run_batch_media_detect_job(
                item_args=retry_args,
                image_path=image_path,
                report_path=retry_report_path,
                i=i,
                started_at=started,
                ticket='',
                randstr='',
                ticket_meta={'source': 'risk-recover-inline'},
            ) if getattr(retry_args, 'driver', 'pure') == 'cdp' else None
            if compact_retry is None:
                try:
                    report = _run_media_report(retry_args, 'image')
                    write_json_file(retry_report_path, report)
                    compact_retry = compact_batch_media_result(report, report_json=str(retry_report_path))
                    compact_retry.update({
                        'i': i,
                        'elapsed_sec': round(time.time() - started, 4),
                    })
                except (Exception, SystemExit) as exc:
                    compact_retry = {
                        'ok': False,
                        'protocol_mode': getattr(retry_args, 'driver', 'pure'),
                        'media_type': 'image',
                        'status': 'failed',
                        'i': i,
                        'input_file': str(image_path),
                        'error': str(exc),
                        'elapsed_sec': round(time.time() - started, 4),
                        'report_json': '',
                    }
            compact_retry['risk_recover_attempt'] = risk_recover_events
            compact_retry['risk_recover_for_i'] = i
            if compact_retry.get('ok'):
                # Replace the failed base item logically while keeping the failed row as evidence.
                success_count += 1
                risk_stopped = False
                with contextlib.suppress(Exception):
                    write_json_file(base_report_path, json.loads(Path(str(compact_retry.get('report_json') or retry_report_path)).read_text(encoding='utf-8')))
                risk_recovery.setdefault('events', []).append({
                    'i': i,
                    'ok': True,
                    'recover_attempt': risk_recover_events,
                    'cooldown_sec': risk_recover_cooldown_sec,
                    'xff': compact_retry.get('xff'),
                    'report_json': compact_retry.get('report_json'),
                })
                attempts.append(compact_retry)
                jsonl.write(json.dumps(compact_retry, ensure_ascii=False, separators=(',', ':')) + '\n')
                jsonl.flush()
                return compact_retry
            risk_recovery.setdefault('events', []).append({
                'i': i,
                'ok': False,
                'recover_attempt': risk_recover_events,
                'cooldown_sec': risk_recover_cooldown_sec,
                'xff': compact_retry.get('xff'),
                'failure_stage': batch_media_compact_failure_stage(compact_retry),
                'report_json': compact_retry.get('report_json'),
            })
            attempts.append(compact_retry)
            jsonl.write(json.dumps(compact_retry, ensure_ascii=False, separators=(',', ':')) + '\n')
            jsonl.flush()
            if not media_risk_event_from_compact(compact_retry):
                return compact_retry
        risk_stopped = True
        return None

    requested_concurrency = max(1, int(getattr(args, 'concurrency', 1) or 1))
    concurrency = requested_concurrency
    cdp_proxy_risk_cap = max(0, int_env("MATRIX_AI_CDP_PROXY_RISK_MAX_CONCURRENCY", 3))
    cdp_pool_concurrency = bool(
        getattr(args, 'driver', 'pure') == 'cdp'
        and (
            (int(cdp_pool_summary.get('pool_size') or 0) >= requested_concurrency
             and getattr(args, 'cdp_ws_mode', '') == 'direct'
             and getattr(args, 'cdp_fp_source', '') == 'browser')
            or (getattr(args, 'cdp_ws_mode', '') == 'proxy'
                and getattr(args, 'cdp_fp_source', '') == 'cli'
                and bool(getattr(args, 'cdp_new_tab', True))
                and list(getattr(args, '_xff_pool', []) or []))
        )
    )
    pure_protocol_window_concurrency = bool(
        getattr(args, 'driver', 'pure') != 'cdp'
        and getattr(args, 'media_send_mode', 'evil0-only') == 'on-code'
    )
    risk_guard_serialized = bool(
        risk_guard.get("enabled")
        and requested_concurrency > 1
        and not cdp_pool_concurrency
        and not pure_protocol_window_concurrency
    )
    if risk_guard_serialized:
        concurrency = 1
        route_notes.append('risk-guard-serialized')
    elif risk_guard.get("enabled") and pure_protocol_window_concurrency and requested_concurrency > 1:
        route_notes.append('risk-guard-pure-window-drain')
    if (
        risk_guard.get("enabled")
        and cdp_pool_concurrency
        and cdp_proxy_risk_cap > 0
        and requested_concurrency > cdp_proxy_risk_cap
    ):
        concurrency = min(concurrency, cdp_proxy_risk_cap)
        route_notes.append(f'risk-guard-cdp-proxy-cap-{cdp_proxy_risk_cap}')
    if getattr(args, 'stop_on_fail', False) and requested_concurrency > 1 and not risk_guard_serialized:
        concurrency = 1
        route_notes.append('stop-on-fail-serialized')
    risk_window = batch_media_risk_window_config(args)
    if risk_window["enabled"]:
        if requested_concurrency > int(risk_window["size"]):
            concurrency = min(concurrency, int(risk_window["size"]))
            route_notes.append(f'risk-window-cap-{int(risk_window["size"])}')
        route_notes.append(f'risk-window-size-{int(risk_window["size"])}')
    if concurrency <= 1:
        with results_jsonl.open('w', encoding='utf-8') as jsonl:
            for i, image_path in enumerate(image_paths, start=1):
                item_args = batch_media_item_args(args, image_path, i)
                setattr(item_args, '_batch_total', len(image_paths))
                setattr(item_args, '_route_attempt_offset', int(getattr(args, 'route_attempt_offset', 0) or 0))
                if getattr(args, 'delay_sec', 0) and i > 1:
                    delay = float(args.delay_sec) + (random.uniform(0, float(args.jitter_sec)) if getattr(args, 'jitter_sec', 0) else 0.0)
                    time.sleep(delay)
                started = time.time()
                report_path = reports_dir / f'{i:06d}-{image_path.stem}.json'
                try:
                    if getattr(args, 'driver', 'pure') == 'cdp':
                        compact = run_batch_media_detect_job(
                            item_args=item_args,
                            image_path=image_path,
                            report_path=report_path,
                            i=i,
                            started_at=started,
                            ticket='',
                            randstr='',
                            ticket_meta={'source': 'serial-inline-cdp'},
                        )
                        ok = bool(compact.get('ok'))
                    else:
                        report = _run_media_report(item_args, 'image')
                        write_json_file(report_path, report)
                        compact = compact_batch_media_result(report, report_json=str(report_path))
                        compact.update({
                            'i': i,
                            'elapsed_sec': round(time.time() - started, 4),
                        })
                        ok = bool(compact.get('ok'))
                except (Exception, SystemExit) as exc:
                    compact = {
                        'ok': False,
                        'protocol_mode': getattr(args, 'driver', 'pure'),
                        'media_type': 'image',
                        'status': 'failed',
                        'i': i,
                        'input_file': str(image_path),
                        'error': str(exc),
                        'elapsed_sec': round(time.time() - started, 4),
                        'report_json': '',
                    }
                    ok = False
                ok = record_batch_compact(item_args, compact)
                jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(',', ':')) + '\n')
                jsonl.flush()
                if should_recover_risk(compact):
                    recovered = recover_item_after_risk(item_args, image_path, i, jsonl, base_report_path=report_path)
                    if recovered and recovered.get('ok'):
                        ok = True
                    else:
                        risk_stopped = True
                if risk_stopped or (args.stop_on_fail and not ok):
                    break
                if (
                    risk_window["enabled"]
                    and i < len(image_paths)
                    and int(risk_window["size"]) > 0
                    and i % int(risk_window["size"]) == 0
                    and float(risk_window["cooldown_sec"]) > 0
                ):
                    route_notes.append('risk-window-cooldown')
                    time.sleep(float(risk_window["cooldown_sec"]))
    else:
        with results_jsonl.open('w', encoding='utf-8') as jsonl, ThreadPoolExecutor(max_workers=concurrency) as pool:
            if getattr(args, 'driver', 'pure') != 'cdp' and getattr(args, 'ticket_phase', 'parallel') in {'serial', 'prefetch'}:
                ticket_delay, ticket_jitter = batch_media_ticket_spacing(args)
                ticket_window_size = max(1, int(getattr(args, 'ticket_window_size', 0) or (len(image_paths) if getattr(args, 'ticket_phase', 'parallel') == 'prefetch' else concurrency)))
                serial_stop = False

                def run_tracked_serial_job(job: dict[str, Any]) -> dict[str, Any]:
                    enter_worker()
                    try:
                        return run_batch_media_detect_job(
                            item_args=job['item_args'],
                            image_path=job['image_path'],
                            report_path=job['report_path'],
                            i=job['i'],
                            started_at=time.time(),
                            ticket=job['ticket'],
                            randstr=job['randstr'],
                            ticket_meta=job['ticket_meta'],
                        )
                    finally:
                        exit_worker()

                def flush_serial_ticket_jobs(jobs: list[dict[str, Any]]) -> bool:
                    futures = {
                        pool.submit(run_tracked_serial_job, job): job
                        for job in jobs
                    }
                    keep_going = True
                    for fut in futures:
                        job = futures[fut]
                        compact = fut.result()
                        ok = record_batch_compact(job['item_args'], compact)
                        jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(',', ':')) + '\n')
                        jsonl.flush()
                        if risk_stopped or (args.stop_on_fail and not ok):
                            keep_going = False
                    return keep_going

                jobs: list[dict[str, Any]] = []
                for i, image_path in enumerate(image_paths, start=1):
                    if serial_stop:
                        break
                    item_args = batch_media_item_args(args, image_path, i)
                    setattr(item_args, '_batch_total', len(image_paths))
                    setattr(item_args, '_route_attempt_offset', int(getattr(args, 'route_attempt_offset', 0) or 0))
                    fp = make_fp_for_mode(getattr(item_args, 'fp_mode', 'fresh'), getattr(item_args, 'fp', ''))
                    if not fp:
                        compact = {
                            'ok': False,
                            'protocol_mode': getattr(args, 'driver', 'pure'),
                            'media_type': 'image',
                            'status': 'failed',
                            'i': i,
                            'input_file': str(image_path),
                            'error': 'missing fp; use --fp-mode fresh or --fp',
                            'elapsed_sec': 0,
                            'report_json': '',
                        }
                        ok = record_batch_compact(item_args, compact)
                        jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(',', ':')) + '\n')
                        jsonl.flush()
                        if risk_stopped or (args.stop_on_fail and not ok):
                            break
                        continue
                    setattr(item_args, '_prepared_fp', fp)
                    if i > 1 and ticket_delay > 0:
                        time.sleep(ticket_delay + (random.uniform(0, ticket_jitter) if ticket_jitter > 0 else 0.0))
                    ticket_started = time.time()
                    try:
                        ticket, randstr, ticket_meta = issue_media_ticket(item_args, fp=fp, iteration=i)
                    except (Exception, SystemExit) as exc:
                        compact = {
                            'ok': False,
                            'protocol_mode': getattr(args, 'driver', 'pure'),
                            'media_type': 'image',
                            'status': 'failed',
                            'i': i,
                            'fp': fp,
                            'xff': item_args.xff,
                            'input_file': str(image_path),
                            'error': f'ticket-phase: {str(exc)}',
                            'elapsed_sec': round(time.time() - ticket_started, 4),
                            'report_json': '',
                        }
                        ok = record_batch_compact(item_args, compact)
                        jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(',', ':')) + '\n')
                        jsonl.flush()
                        if risk_stopped or (args.stop_on_fail and not ok):
                            break
                        continue
                    report_path = reports_dir / f'{i:06d}-{image_path.stem}.json'
                    jobs.append({
                        'i': i,
                        'image_path': image_path,
                        'item_args': item_args,
                        'report_path': report_path,
                        'ticket': ticket,
                        'randstr': randstr,
                        'ticket_meta': {
                            **ticket_meta,
                            'phase': 'prefetch-ticket' if getattr(args, 'ticket_phase', 'parallel') == 'prefetch' else 'serial-ticket-window',
                            'prepared_fp': fp,
                            'ticket_elapsed_sec': round(time.time() - ticket_started, 4),
                            'ticket_window_size': ticket_window_size,
                        },
                    })
                    if len(jobs) >= ticket_window_size:
                        serial_stop = not flush_serial_ticket_jobs(jobs)
                        jobs = []
                if jobs and not serial_stop:
                    flush_serial_ticket_jobs(jobs)
            elif getattr(args, 'driver', 'pure') != 'cdp' and getattr(args, 'ticket_phase', 'parallel') == 'browser-pool':
                run_browser_pool_windows(
                    args=args,
                    image_paths=image_paths,
                    reports_dir=reports_dir,
                    concurrency=concurrency,
                    jsonl=jsonl,
                    record_batch_compact=record_batch_compact,
                    enter_worker=enter_worker,
                    exit_worker=exit_worker,
                    should_stop=lambda: risk_stopped,
                    route_notes=route_notes,
                )
            else:
                pending: dict[Any, dict[str, Any]] = {}
                queued = 0
                completed = 0
                stop_queued = False
                window_completed = 0
                window_queued = 0
                while completed < len(image_paths):
                    while not stop_queued and queued < len(image_paths) and len(pending) < concurrency:
                        if risk_window["enabled"] and int(risk_window["size"]) > 0 and window_queued >= int(risk_window["size"]):
                            break
                        i = queued + 1
                        image_path = image_paths[queued]
                        queued += 1
                        window_queued += 1
                        started = time.time()
                        if getattr(args, 'delay_sec', 0) and i > 1:
                            delay = float(args.delay_sec) + (random.uniform(0, float(args.jitter_sec)) if getattr(args, 'jitter_sec', 0) else 0.0)
                            time.sleep(delay)
                        item_args = batch_media_item_args(args, image_path, i)
                        setattr(item_args, '_batch_total', len(image_paths))
                        setattr(item_args, '_route_attempt_offset', int(getattr(args, 'route_attempt_offset', 0) or 0))
                        report_path = reports_dir / f'{i:06d}-{image_path.stem}.json'

                        def worker(index: int = i, path: Path = image_path, started_at: float = started, report_path: Path = report_path, worker_args: argparse.Namespace = item_args) -> dict[str, Any]:
                            enter_worker()
                            try:
                                if getattr(worker_args, 'driver', 'pure') == 'cdp':
                                    return run_batch_media_detect_job(
                                        item_args=worker_args,
                                        image_path=path,
                                        report_path=report_path,
                                        i=index,
                                        started_at=started_at,
                                        ticket='',
                                        randstr='',
                                        ticket_meta={'source': 'parallel-inline-cdp'},
                                    )
                                report = _run_media_report(worker_args, 'image')
                                write_json_file(report_path, report)
                                compact = compact_batch_media_result(report, report_json=str(report_path))
                                compact.update({
                                    'i': index,
                                    'elapsed_sec': round(time.time() - started_at, 4),
                                })
                                return compact
                            except (Exception, SystemExit) as exc:
                                return {
                                    'ok': False,
                                    'protocol_mode': getattr(args, 'driver', 'pure'),
                                    'media_type': 'image',
                                    'status': 'failed',
                                    'i': index,
                                    'input_file': str(path),
                                    'error': str(exc),
                                    'elapsed_sec': round(time.time() - started_at, 4),
                                    'report_json': '',
                                }
                            finally:
                                exit_worker()

                        fut = pool.submit(worker)
                        pending[fut] = {'i': i, 'image_path': image_path, 'item_args': item_args}
                    if not pending:
                        break
                    done, _ = wait(set(pending.keys()), return_when=FIRST_COMPLETED)
                    for fut in done:
                        meta = pending.pop(fut)
                        compact = fut.result()
                        ok = record_batch_compact(meta['item_args'], compact)
                        jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(',', ':')) + '\n')
                        jsonl.flush()
                        if not ok:
                            stop_queued = stop_queued or bool(args.stop_on_fail)
                        if risk_stopped:
                            stop_queued = True
                        completed += 1
                        window_completed += 1
                    if stop_queued:
                        route_notes.append('risk-guard-drain-inflight')
                    if (
                        not stop_queued
                        and risk_window["enabled"]
                        and not pending
                        and queued < len(image_paths)
                        and int(risk_window["size"]) > 0
                        and window_completed >= int(risk_window["size"])
                    ):
                        if float(risk_window["cooldown_sec"]) > 0:
                            route_notes.append('risk-window-cooldown')
                            time.sleep(float(risk_window["cooldown_sec"]))
                        window_completed = 0
                        window_queued = 0
    remaining_manifest = ""
    remaining_count = 0
    if risk_stopped and risk_stop_index > 0:
        executed_indices: list[int] = []
        for item in attempts:
            try:
                executed_indices.append(int(item.get('i') or 0))
            except Exception:
                pass
        resume_next_index = (max(executed_indices) + 1) if executed_indices else (risk_stop_index + 1)
        remaining_manifest, remaining_count = batch_media_make_resume_manifest(
            out_dir=out_dir,
            image_paths=image_paths,
            next_index=resume_next_index,
        )
    setattr(args, '_observed_peak_concurrency', peak_active_workers if peak_active_workers else (1 if attempts else 0))
    summary = check_images_finalize_summary(
        args,
        out_dir=out_dir,
        reports_dir=reports_dir,
        results_jsonl=results_jsonl,
        base_image_paths=base_image_paths,
        image_paths=image_paths,
        repeat_each=repeat_each,
        requested_concurrency=requested_concurrency,
        concurrency=concurrency,
        cdp_pool_summary=cdp_pool_summary,
        xff_probe_summary=xff_probe_summary,
        route_mode=route_mode,
        route_notes=route_notes,
        attempts=attempts,
        success_count=success_count,
        risk_guard=risk_guard,
        risk_events=risk_events,
        risk_stopped=risk_stopped,
        risk_stop_index=risk_stop_index,
        risk_failure_stage=risk_failure_stage,
        risk_window=risk_window,
        remaining_manifest=remaining_manifest,
        remaining_count=remaining_count,
        risk_recovery=risk_recovery,
    )
    write_json_file(out_dir / 'summary.json', summary)
    if getattr(args, 'out_json', ''):
        write_json_file(Path(args.out_json), summary)
    json_dump(summary)
    return 0 if summary['ok'] else 2
