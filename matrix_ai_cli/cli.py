"""CLI entry point: argparse commands and main()."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from .config import (
    CAPTCHA_APPID,
    AGENT_BROWSER_CLI,
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    HTTP_BASE,
    JSON_PARSER_ARGV,
    PIC_WS_URL,
    VIDEO_CHUNK_SIZE,
    WS_URL,
)
from .transport import (
    agent_browser_close_tab,
    build_ws_headers,
    egress_meta,
    json_dump,
    load_text_arg,
    load_ticket_args,
    make_fp,
    make_fp_for_mode,
    recv_json,
    xff_for_iteration,
)
from .captcha import (
    captcha_prehandle,
    captcha_ticket_pure,
    captcha_ticket_terror,
    captcha_verify_probe,
    extract_first_captcha_code,
)
from .text_detect import (
    default_ticket_command,
    detect_with_ticket,
    extract_pdf_text,
    handshake_only,
    json_command_error,
    load_ticket_provider,
    namespace_clone,
    pick_fp,
    render_pdf,
    require_pure_ticket_inputs,
    resolve_ticket_and_fp,
    submit_feedback,
    text_detect_exit_code,
    text_route_xff,
    write_json_file,
    TicketProviderError,
)
from .text_routes import (
    attach_text_agent_contract,
    capture_standalone_ticket,
    captcha_probe,
    captcha_ticket_validated,
    run_pure_report,
    run_text_auto_report,
    run_text_browser_report,
    text_check_result,
)
from .browser_state import browser_txt_state
from .media_detect import (
    media_check_result,
    media_error_report,
    media_exit_code,
    issue_media_ticket,
)
from .media_cdp import cdp_media_report
from .media_batch_job import (
    run_batch_media_detect_job,
    run_media_report,
)
from .batch import (
    apply_media_solve_risk_defaults,
    batch_media_apply_result_route_feedback,
    batch_media_browser_version_url_for_item,
    batch_media_bound_for_item,
    batch_media_cdp_context_proxy_for_item,
    batch_media_compact_failure_stage,
    batch_media_default_xff_pool,
    batch_media_egress_proxy_for_item,
    batch_media_egress_counts,
    batch_media_extend_xff_pool_for_retry,
    batch_media_item_args,
    batch_media_make_resume_manifest,
    batch_media_risk_summary,
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
    batch_media_slice_for_indices,
)
from .batch_queue import (
    batch_media_input_error_summary,
    batch_media_risk_resume_command,
    check_images_finalize_summary,
    probe_rotate_xff_candidates,
)



class JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        command = ""
        argv = JSON_PARSER_ARGV or getattr(self, "_matrix_ai_argv", None) or sys.argv[1:]
        if argv and not argv[0].startswith("-"):
            command = argv[0]
        json_dump(json_command_error(command, message, exit_code=2, failure_stage="input-error"))
        raise SystemExit(2)

    def parse_args(self, args: list[str] | None = None, namespace: argparse.Namespace | None = None) -> argparse.Namespace:
        global JSON_PARSER_ARGV
        self._matrix_ai_argv = list(args) if args is not None else sys.argv[1:]
        previous = JSON_PARSER_ARGV
        JSON_PARSER_ARGV = list(self._matrix_ai_argv)
        try:
            return super().parse_args(args, namespace)
        finally:
            self._matrix_ai_argv = []
            JSON_PARSER_ARGV = previous

    def add_subparsers(self, **kwargs: Any) -> argparse._SubParsersAction:
        kwargs.setdefault("parser_class", JsonArgumentParser)
        return super().add_subparsers(**kwargs)



def cmd_doctor(args: argparse.Namespace) -> int:
    browser_state = None
    if not getattr(args, 'pure', False):
        try:
            browser_state = browser_txt_state(bound=DEFAULT_BOUND, timeout=10.0)
        except BaseException:
            browser_state = None
    json_dump({
        "ok": True,
        "command": "doctor",
        "python": sys.executable,
        "requests": True,
        "websockets": True,
        "weasyprint": True,
        "pypdf": True,
        "http_base": HTTP_BASE,
        "ws_url": WS_URL,
        "pic_ws_url": PIC_WS_URL,
        "agent_default_commands": [
            "check-text --text-file <path> --out-dir <dir>",
            "run-pure --fp-mode fresh --auto-ticket --result-only --text-file <path> --out-dir <dir>",
            "check-images --image-dir <dir> --out-dir <dir>",
            "check-images --driver pure --fp-mode fresh --route-mode auto --media-send-mode on-code --ticket-phase serial --ticket-window-size 5 --concurrency 5 --image-dir <dir> --out-dir <dir>",
            "check-images-drain --images-file <manifest> --out-dir <dir> --ticket-phase serial --ticket-window-size 5 --concurrency 5 --drain-window-size 5",
            "check-images --solve-risk --image-dir <dir> --out-dir <dir> --concurrency 1",
            "check-images --image-dir <dir> --out-dir <dir> --route-mode on --repeat-each 100 --ticket-phase serial --concurrency 1",
        ],
        "pure_protocol_commands": ["captcha-ticket --mode validated", "check-text --driver pure --fp-mode fresh --text-file <path> --out-dir <dir>", "check-image --image-file <path> --media-send-mode on-code", "check-images --image-dir <dir> --out-dir <dir> --media-send-mode on-code --ticket-phase serial --ticket-window-size 5 --concurrency 5", "check-images-drain --images-file <manifest> --out-dir <dir> --ticket-phase serial --ticket-window-size 5 --concurrency 5 --drain-window-size 5", "check-images --image-dir <dir> --concurrency 3 --ticket-phase serial --tdc-profile-mode random --delay-sec 6 --jitter-sec 2 --out-dir <dir>", "check-video --video-file <path> --media-send-mode on-code", "stress-media --fp-mode fresh --count 100 --out-dir <dir>", "run-pure --fp-mode fresh --xff <ip> --order fp-ticket-text --auto-ticket", "stress-pure --fp-mode fresh --rotate-xff <pattern> --order fp-ticket-text --auto-ticket", "feedback"],
        "ticket_provider_commands": ["captcha-ticket --mode validated", "captcha-ticket --mode tdc", "captcha-ticket --mode terror", "ticket --mode pure"],
        "ticket_provider_timeout_contract": {
            "env": "MATRIX_AI_TEXT_TICKET_PROVIDER_TIMEOUT",
            "default_cap_sec": 120,
            "absolute_cap_sec": 300,
        },
        "temp_report_contract": {
            "check_text_prefix": "matrix-ai-check-text-",
            "run_prefix": "matrix-ai-run-",
            "run_pure_prefix": "matrix-ai-run-pure-",
            "cleanup": "caller-managed after reading report_json",
        },
        "media_upload_endpoints": ["/user/upload_video_chunk", "/user/merge_video_chunks"],
        "browser_assisted_commands": ["run", "detect-text", "pick-fp", "check-image --solve-risk --image-file <path>", "check-images --solve-risk --image-dir <dir> --out-dir <dir>", "check-images --solve-risk --image-dir <dir> --concurrency 2 --cdp-browser-pool-size 2 --out-dir <dir>", "check-video --solve-risk --video-file <path>"],
        "check_text_route_contract": {
            "default_driver": "auto",
            "default_order": "browser,pure-auto,pure-no-xff",
            "summary": "stdout compact JSON plus optional <out-dir>/report.json",
            "failure_stage": "failure_stage",
            "route_state": "route_state",
            "agent_hint": "agent_hint",
            "next_command": "next_command",
            "stop_loss_recommended": "stop_loss_recommended",
        },
        "check_images_route_contract": {
            "default_route_mode": "auto",
            "auto_route": "fresh batch without fixed --xff builds an XFF pool and writes queue_health.route_state",
            "media_send_mode": "default evil0-only; use on-code for pure protocol batches that must submit media immediately after captcha code",
            "default_risk_guard": "enabled; serializes requested concurrency and stops before the next item after the first captcha evil_level>0 response",
            "safe_queue": "--safe-queue caps solve-risk bursts to risk_window_size and sleeps risk_window_cooldown_sec between windows; summary writes data.queue_health.risk_window",
            "solve_risk_route": "--solve-risk forces browser-executed CDP with local WS proxy, fresh CLI fp, fresh XFF routing, new disposable tab, and risk stop-loss; summary writes queue_health route/risk state",
            "resume_manifest": "<out-dir>/remaining-images.txt when risk guard stops a queue",
            "summary_path": "<out-dir>/summary.json",
            "jsonl_path": "<out-dir>/results.jsonl",
            "failure_stage": "data.queue_health.failure_stage",
            "stop_loss_recommended": "data.queue_health.stop_loss_recommended",
        },
        "resume_manifest": "<out-dir>/remaining-images.txt when risk guard stops a queue",
        "check_images_resume_manifest": "<out-dir>/remaining-images.txt when risk guard stops a queue",
        "agent_browser_cli": None if getattr(args, 'pure', False) else shutil.which(AGENT_BROWSER_CLI),
        "default_bound": None if getattr(args, 'pure', False) else DEFAULT_BOUND,
        "browser_state": browser_state,
    })
    return 0



def cmd_pick_fp(args: argparse.Namespace) -> int:
    headers = build_ws_headers(xff=getattr(args, 'xff', ''), headers=getattr(args, 'header', []))
    if headers and getattr(args, 'fp_mode', 'fixed') == 'fresh':
        fp = make_fp()
        probe = handshake_only(fp, additional_headers=headers)
        first = probe.get('first') or {}
        out = {
            'picked_fp': fp if first.get('status') == 'success' and int(first.get('availableUses', 0)) > 0 else None,
            'probe': probe,
            'available_uses': first.get('availableUses'),
            'headers': headers,
            'source': 'fresh-with-headers',
        }
        json_dump(out)
        return 0 if out.get('picked_fp') else 2
    json_dump(pick_fp(args.max_tries, bound=DEFAULT_BOUND))
    return 0



def cmd_detect_text(args: argparse.Namespace) -> int:
    if getattr(args, 'driver', ''):
        report, _text = run_text_auto_report(args, attempt_fn=run_text_route_attempt)
        json_dump(report)
        return text_detect_exit_code(report)
    text = load_text_arg(args.text, args.text_file)
    if args.fp_mode == 'pick':
        picked = pick_fp(args.max_tries)
        fp = picked['picked_fp']
        if not fp:
            json_dump(picked)
            return 2
    elif args.fp_mode == 'fresh':
        fp = make_fp()
    else:
        fp = args.fp
    args.xff = text_route_xff(args, fp)
    target = None
    try:
        capture = None
        if getattr(args, 'pure', False):
            fp, ticket, randstr = require_pure_ticket_inputs(fp=fp, ticket=args.ticket, randstr=args.randstr, ticket_json=args.ticket_json)
        else:
            fp, ticket, randstr, capture, target = resolve_ticket_and_fp(
                text=text,
                fp=fp,
                ticket=args.ticket,
                randstr=args.randstr,
                ticket_json=args.ticket_json,
                bound=args.bound,
                session_id=args.session_id,
                capture_timeout=args.capture_timeout,
                max_tries=args.max_tries,
            )
        headers = build_ws_headers(xff=getattr(args, 'xff', ''), headers=getattr(args, 'header', []))
        result = detect_with_ticket(text=text, fp=fp, ticket=ticket, randstr=randstr, timeout=args.timeout, order=getattr(args, 'order', 'fp-ticket-text'), additional_headers=headers, text_send_mode=getattr(args, 'text_send_mode', 'on-code'))
        if capture:
            result['capture'] = capture
        if target:
            result['browser_target'] = target
        json_dump(result)
        return text_detect_exit_code(result)
    finally:
        if target and target.get('temporary') and target.get('session_id'):
            try:
                agent_browser_close_tab(str(target['session_id']))
            except BaseException:
                pass



def cmd_render_pdf(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.report_json).read_text(encoding='utf-8'))
    text = Path(args.text_file).read_text(encoding='utf-8') if args.text_file else report.get('input_text', '')
    json_dump(render_pdf(report=report, text=text, out_pdf=Path(args.out_pdf)))
    return 0



def cmd_extract_pdf(args: argparse.Namespace) -> int:
    json_dump(extract_pdf_text(Path(args.pdf)))
    return 0



def cmd_run(args: argparse.Namespace) -> int:
    command = 'run'
    try:
        text = load_text_arg(args.text, args.text_file)
    except (OSError, SystemExit, ValueError) as exc:
        out = json_command_error(command, exc, exit_code=2)
        json_dump(out)
        return 2
    # Preserve text_file for child ticket providers. Exporting a full paper through
    # MATRIX_AI_TEXT can exceed the OS argv/env limit when the provider is spawned.
    args = namespace_clone(args, text=text)
    report, text = run_text_auto_report(namespace_clone(args, driver=(getattr(args, 'driver', '') or 'auto')), attempt_fn=run_text_route_attempt)
    report['input_text'] = text
    out_dir = Path(args.out_dir) if getattr(args, 'out_dir', '') else Path(tempfile.mkdtemp(prefix='matrix-ai-run-'))
    report_json = out_dir / 'report.json'
    report_json.parent.mkdir(parents=True, exist_ok=True)
    compact = attach_text_agent_contract(report, report_json=str(report_json))
    report_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    pdf_meta: dict[str, Any] = {}
    extract: dict[str, Any] = {}
    pdf_error = ''
    if not getattr(args, 'no_pdf', False):
        pdf_path = out_dir / 'report.pdf'
        try:
            pdf_meta = render_pdf(report=report, text=text, out_pdf=pdf_path)
            extract = extract_pdf_text(pdf_path)
        except Exception as exc:
            pdf_error = repr(exc)
    out = {
        **compact,
        'command': 'run',
        'data': {
            'protocol_mode': report.get('protocol_mode') or 'pure',
            'route_state': compact.get('route_state') or {},
            'failure_stage': compact.get('failure_stage') or '',
            'agent_hint': compact.get('agent_hint') or '',
            'next_command': compact.get('next_command') or '',
            'report_json': str(report_json),
            'detect': report,
        },
        'report_json': str(report_json),
        'detect': report,
        'pdf': pdf_meta,
        'extract': extract,
        'pdf_error': pdf_error,
    }
    json_dump(out)
    return 0 if compact.get('ok') else 2



def cmd_ticket(args: argparse.Namespace) -> int:
    if args.mode == 'standalone':
        out = capture_standalone_ticket(bound=args.bound, session_id=args.session_id, timeout=args.timeout)
    elif args.mode == 'pure':
        out = captcha_ticket_pure(timeout=args.timeout)
    else:
        text = load_text_arg(args.text, args.text_file)
        fp = args.fp or ''
        if not fp and args.fp_mode == 'pick':
            picked = pick_fp(args.max_tries)
            fp = picked.get('picked_fp') or ''
            if not fp:
                json_dump({'status':'failed','reason':'no usable fp','pick':picked})
                return 2
        fp, ticket, randstr, capture, target = resolve_ticket_and_fp(
            text=text,
            fp=fp,
            ticket=None,
            randstr=None,
            ticket_json=None,
            bound=args.bound,
            session_id=args.session_id,
            capture_timeout=args.timeout,
            max_tries=args.max_tries,
        )
        out = {'status':'captured','fp':fp,'payload':{'ticket':ticket,'randstr':randstr},'capture':capture,'browser_target':target}
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    payload = out.get('payload') or {}
    return 0 if payload.get('ticket') and payload.get('randstr') else 2



def cmd_captcha_probe(args: argparse.Namespace) -> int:
    out = captcha_probe(timeout=args.timeout)
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    return 0 if out.get('summary', {}).get('can_issue_ticket_without_browser') else 2


def cmd_captcha_ticket(args: argparse.Namespace) -> int:
    mode = getattr(args, 'mode', 'validated')
    if mode == 'tdc':
        out = captcha_ticket_pure(timeout=args.timeout, xff=(getattr(args, 'xff', '') or os.environ.get('MATRIX_AI_XFF') or ''))
    elif mode == 'validated':
        text_arg = getattr(args, 'text', None) or os.environ.get('MATRIX_AI_TEXT') or None
        text_file_arg = getattr(args, 'text_file', None) or os.environ.get('MATRIX_AI_TEXT_FILE') or None
        text = load_text_arg(text_arg, text_file_arg) if (text_arg or text_file_arg) else ("这是一次矩阵 AI 检测 CTF 纯协议闭环验证文本。" * 90)[:2160]
        out = captcha_ticket_validated(text=text, fp=(getattr(args, 'fp', '') or os.environ.get('MATRIX_AI_FP') or None), xff=(getattr(args, 'xff', '') or os.environ.get('MATRIX_AI_XFF') or ''), timeout=args.timeout, attempts=getattr(args, 'attempts', 20))
    elif mode == 'terror':
        out = captcha_ticket_terror()
    else:
        raise SystemExit(f'unsupported captcha ticket mode: {mode}')
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    payload = out.get('payload') or {}
    return 0 if payload.get('ticket') and payload.get('randstr') else 2



def cmd_feedback(args: argparse.Namespace) -> int:
    report = json.loads(Path(args.report_json).read_text(encoding='utf-8'))
    fp = args.fp or report.get('fp')
    if not fp:
        raise SystemExit('missing fp')
    out = submit_feedback(fp=fp, report=report, status=args.status, timeout=args.timeout)
    json_dump(out)
    resp = out.get('response') or {}
    return 0 if out.get('status_code') == 200 and resp.get('status') == 'success' else 2


def cmd_check_text(args: argparse.Namespace) -> int:
    command = 'check-text'
    try:
        text = load_text_arg(args.text, args.text_file)
    except (OSError, SystemExit, ValueError) as exc:
        out = json_command_error(command, exc, exit_code=2)
        if getattr(args, 'out_json', ''):
            write_json_file(Path(args.out_json), out)
        json_dump(out)
        return 2
    # Preserve text_file for child ticket providers.  Exporting a full paper through
    # MATRIX_AI_TEXT can exceed the OS argv/env limit when the provider is spawned.
    args = namespace_clone(args, text=text)
    report, _text = run_text_auto_report(args, attempt_fn=run_text_route_attempt)
    out_dir = Path(args.out_dir) if args.out_dir else Path(tempfile.mkdtemp(prefix='matrix-ai-check-text-'))
    out_dir.mkdir(parents=True, exist_ok=True)
    report_json = str(out_dir / 'report.json')
    out = attach_text_agent_contract(report, report_json=report_json)
    write_json_file(Path(report_json), report)
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    return 0 if out.get('ok') else 2




def cmd_check_image(args: argparse.Namespace) -> int:
    apply_media_solve_risk_defaults(args)
    try:
        report = run_media_report(args, 'image')
    except (Exception, SystemExit) as exc:
        report = media_error_report(args, 'image', exc)
    report_json = ''
    if args.out_dir:
        report_json = str(Path(args.out_dir) / 'image-report.json')
        write_json_file(Path(report_json), report)
    out = media_check_result(report, report_json=report_json)
    if args.out_json:
        write_json_file(Path(args.out_json), out)
    json_dump(out)
    return 0 if out.get('ok') else 2



def cmd_run_pure(args: argparse.Namespace) -> int:
    try:
        text = load_text_arg(args.text, args.text_file)
    except (OSError, SystemExit, ValueError) as exc:
        out = json_command_error('run-pure', exc, exit_code=2)
        json_dump(out)
        return 2
    # Preserve text_file for provider subprocesses; see cmd_check_text.
    args = namespace_clone(args, text=text)
    report, text = run_text_auto_report(namespace_clone(args, driver='pure'), attempt_fn=run_text_route_attempt)
    out_dir = Path(args.out_dir) if getattr(args, 'out_dir', '') else Path(tempfile.mkdtemp(prefix='matrix-ai-run-pure-'))
    report_json = out_dir / 'report.json'
    compact = attach_text_agent_contract(report, report_json=str(report_json))
    write_json_file(report_json, report)
    if getattr(args, 'result_only', False):
        out = compact
    else:
        out = {**compact, 'detect': report}
    pdf_error = ''
    if not (getattr(args, 'no_pdf', False) or getattr(args, 'result_only', False)):
        pdf_path = out_dir / 'report.pdf'
        try:
            pdf_meta = render_pdf(report=report, text=text, out_pdf=pdf_path)
            extract = extract_pdf_text(pdf_path)
        except Exception as exc:
            pdf_error = repr(exc)
            pdf_meta = {}
            extract = {}
        out.update({'pdf': pdf_meta, 'extract': extract})
    if pdf_error:
        out['pdf_error'] = pdf_error
    json_dump(out)
    return 0 if compact.get('ok') else 2



def cmd_stress_pure(args: argparse.Namespace) -> int:
    text = load_text_arg(args.text, args.text_file) if (args.text or args.text_file) else ''
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    success_count = 0
    ticket_command = args.ticket_command or (default_ticket_command(args.ticket_timeout) if args.auto_ticket else '')
    mode = 'full_detect' if (ticket_command or args.ticket_json) else ('captcha_probe' if args.captcha_probe else 'handshake_only')
    static_ticket = static_randstr = ''
    if args.ticket_json:
        static_ticket, static_randstr = load_ticket_args(None, None, args.ticket_json)
    for i in range(1, args.count + 1):
        started = time.time()
        fp = make_fp_for_mode(args.fp_mode, args.fp)
        xff = xff_for_iteration(args.rotate_xff, i) if args.rotate_xff else args.xff
        headers = build_ws_headers(xff=xff, headers=args.header)
        entry: dict[str, Any] = {'i': i, 'mode': mode, 'started_at': started, 'fp': fp, 'fp_mode': args.fp_mode, 'headers': headers}
        try:
            if ticket_command or args.ticket_json:
                if ticket_command:
                    ticket, randstr, provided_fp, provider_meta, provider_report = load_ticket_provider(
                        ticket_command,
                        iteration=i,
                        fp=fp,
                        text=text,
                        text_file=args.text_file,
                        xff=xff,
                    )
                    fp = provided_fp or fp
                    entry['fp'] = fp
                    entry['provider'] = provider_meta
                    if provider_report and text_detect_exit_code(provider_report) == 0:
                        report = provider_report
                    else:
                        report = detect_with_ticket(
                            text=text,
                            fp=fp,
                            ticket=ticket,
                            randstr=randstr,
                            timeout=args.timeout,
                            order=args.order,
                            additional_headers=headers,
                            text_send_mode=args.text_send_mode,
                        )
                else:
                    ticket, randstr = static_ticket, static_randstr
                    entry['provider'] = {'source': 'ticket-json', 'path': args.ticket_json, 'one_time_reuse_expected': i > 1}
                    report = detect_with_ticket(
                        text=text,
                        fp=fp,
                        ticket=ticket,
                        randstr=randstr,
                        timeout=args.timeout,
                        order=args.order,
                        additional_headers=headers,
                        text_send_mode=args.text_send_mode,
                    )
                entry['result'] = report.get('result')
                entry['logs'] = report.get('logs')
                ok = text_detect_exit_code(report) == 0
            elif args.captcha_probe:
                probe = captcha_probe(timeout=args.timeout)
                entry['captcha_summary'] = probe.get('summary')
                ok = bool((probe.get('summary') or {}).get('can_issue_ticket_without_browser'))
            else:
                if not fp:
                    raise RuntimeError('missing fp; use --fp or --fp-mode fresh')
                probe = handshake_only(fp, additional_headers=headers)
                entry['probe'] = probe
                first = probe.get('first') or {}
                ok = first.get('status') == 'success' and int(first.get('availableUses', 0)) > 0
            entry['ok'] = bool(ok)
            if ok:
                success_count += 1
        except Exception as exc:
            entry['ok'] = False
            entry['error'] = str(exc)
        entry['elapsed_sec'] = round(time.time() - started, 4)
        attempts.append(entry)
        if args.stop_on_fail and not entry['ok']:
            break
    summary = {
        'protocol_mode': 'pure',
        'mode': mode,
        'count_requested': args.count,
        'count_executed': len(attempts),
        'success_count': success_count,
        'failure_count': len(attempts) - success_count,
        'full_detect_requires_fresh_ticket_per_iteration': bool(ticket_command),
        'captcha_probe_requires_no_browser': bool(args.captcha_probe),
        'fp_mode': args.fp_mode,
        'xff': args.xff,
        'rotate_xff': args.rotate_xff,
        'headers': build_ws_headers(xff=args.xff, headers=args.header),
        'ok': success_count == args.count,
        'attempts_path': str(out_dir / 'stress-attempts.json'),
    }
    write_json_file(out_dir / 'stress-attempts.json', attempts)
    write_json_file(out_dir / 'stress-summary.json', summary)
    json_dump(summary)
    return 0 if summary['ok'] else 2



def main() -> int:
    from .cli_parser import build_parser
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == '__main__':
    raise SystemExit(main())

# Re-exports for backward compatibility with tests
from .cli_parser import build_parser  # noqa: E402, F401
from .cli_batch import cmd_check_images, discover_image_inputs, discover_remaining_image_inputs  # noqa: E402, F401
from .text_detect import text_has_manual_one_time_ticket, text_should_send_after_captcha  # noqa: E402, F401
from .text_routes import run_text_route_attempt, text_route_order, text_route_xff  # noqa: E402, F401
from .batch_queue import probe_rotate_xff_candidates  # noqa: E402, F401
