"""Text detection route logic: auto-routing, browser fallback, validation."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

from .config import (
    CAPTCHA_APPID,
    CAPTCHA_ENTRY_URL,
    DEFAULT_BOUND,
    WS_URL,
)
from .transport import (
    agent_browser_execute_js,
    build_ws_headers,
    egress_meta,
    json_dump,
    load_text_arg,
    make_fp,
    make_fp_for_mode,
    xff_for_iteration,
)
from .captcha import (
    captcha_prehandle,
    captcha_ticket_pure,
    captcha_verify_static_tdc,
    extract_first_captcha_code,
    make_tdc_ft,
    tdc_template_summary,
)
from .text_detect import (
    default_ticket_command,
    detect_with_ticket,
    json_command_error,
    load_ticket_provider,
    namespace_clone,
    pick_fp,
    require_pure_ticket_inputs,
    resolve_ticket_and_fp,
    text_detect_exit_code,
    text_failure_stage,
    text_has_explicit_route,
    text_has_manual_one_time_ticket,
    text_route_order,
    text_route_xff,
    text_ticket_provider_timeout,
    write_json_file,
    TicketProviderError,
)
from .transport import agent_browser_close_tab
from .browser_state import capture_ticket_auto, ensure_browser_target, ensure_usable_browser_fp


def captcha_ticket_validated(
    *,
    text: str,
    fp: str | None = None,
    xff: str = "",
    timeout: float = 20.0,
    attempts: int = 20,
    wait_ms_values: list[int] | None = None,
) -> dict[str, Any]:
    """Issue pure-protocol captcha tickets and keep only one proven by Matrix as evil_level=0."""
    wait_ms_values = wait_ms_values or [0, 500, 1500, 2200]
    evidence: list[dict[str, Any]] = []
    for attempt in range(1, attempts + 1):
        wait_ms = wait_ms_values[(attempt - 1) % len(wait_ms_values)]
        seq = [{'ft': make_tdc_ft()}, {'isNewEntry': 1}]
        pre = captcha_prehandle(timeout=timeout)
        verify = captcha_verify_static_tdc(pre, timeout=timeout, wait_ms=wait_ms, seq=seq, require_dynamic_tdc=True)
        verify_resp = (verify or {}).get('response') or {}
        payload = {'ticket': verify_resp.get('ticket') or '', 'randstr': verify_resp.get('randstr') or ''}
        entry: dict[str, Any] = {
            'attempt': attempt,
            'wait_ms': wait_ms,
            'seq': seq,
            'verify_ok': bool((verify or {}).get('ok')),
            'verify_errorCode': verify_resp.get('errorCode'),
            'randstr': payload.get('randstr'),
            'request_summary': (verify or {}).get('request_summary'),
            'dynamic_tdc': (verify or {}).get('dynamic_tdc'),
        }
        if not payload.get('ticket') or not payload.get('randstr'):
            evidence.append(entry)
            continue
        test_fp = fp or make_fp()
        validation_xff = xff
        if xff and not fp:
            parts = xff.split('.')
            if len(parts) == 4 and all(part.isdigit() for part in parts):
                validation_xff = '.'.join(parts[:3] + [str((int(parts[3]) + attempt - 1) % 240 + 1)])
        elif not xff:
            validation_xff = f'10.214.{attempt // 240}.{attempt % 240 + 1}'
        headers = build_ws_headers(xff=validation_xff, headers=[])
        entry['validation_xff'] = validation_xff
        try:
            report = detect_with_ticket(
                text=text,
                fp=test_fp,
                ticket=payload['ticket'],
                randstr=payload['randstr'],
                timeout=timeout,
                order='fp-ticket-text',
                additional_headers=headers,
                text_send_mode='evil0-only',
            )
            code_msg = extract_first_captcha_code(report)
            entry.update({
                'matrix_code': code_msg.get('code'),
                'matrix_evil_level': code_msg.get('evil_level'),
                'matrix_msg': code_msg.get('msg'),
                'matrix_status': (report.get('result') or {}).get('status'),
                'matrix_success': (report.get('result') or {}).get('status') == 'success',
            })
            if code_msg.get('code') == '1' and code_msg.get('evil_level') == '0':
                evidence.append(entry)
                return {
                    'status': 'captured',
                    'protocol_mode': 'pure',
                    'provider': 'tencent-captcha-jsdom-tdc-pow-validated',
                    'appid': CAPTCHA_APPID,
                    'fp': test_fp,
                    'payload': payload,
                    'validation': entry,
                    'report': report,
                    'attempts': evidence,
                }
        except Exception as exc:
            entry['validation_error'] = repr(exc)
        evidence.append(entry)
    return {
        'status': 'failed',
        'protocol_mode': 'pure',
        'provider': 'tencent-captcha-jsdom-tdc-pow-validated',
        'appid': CAPTCHA_APPID,
        'payload': {},
        'attempts': evidence,
    }




def captcha_probe(*, timeout: float = 20.0) -> dict[str, Any]:
    pre = captcha_prehandle(timeout=timeout)
    verify = captcha_verify_static_tdc(pre, timeout=timeout, require_dynamic_tdc=True) if (pre.get('response') or {}).get('sess') else None
    pre_resp = pre.get('response') or {}
    verify_resp = (verify or {}).get('response') or {}
    return {
        'protocol_mode': 'pure',
        'appid': CAPTCHA_APPID,
        'prehandle': pre,
        'verify_probe': verify,
        'summary': {
            'prehandle_state': pre_resp.get('state'),
            'prehandle_direct_ticket': bool(pre_resp.get('ticket')),
            'prehandle_has_challenge': bool(pre_resp.get('sess') and pre_resp.get('src_1')),
            'challenge_src_1': pre_resp.get('src_1'),
            'subcapclass': pre_resp.get('subcapclass'),
            'tdc_required': bool(((pre_resp.get('data') or {}).get('comm_captcha_cfg') or {}).get('tdc_path')),
            'pow_required': bool(((pre_resp.get('data') or {}).get('comm_captcha_cfg') or {}).get('pow_cfg')),
            'verify_ticket': bool(verify_resp.get('ticket')),
            'verify_errorCode': verify_resp.get('errorCode'),
            'static_tdc_template': tdc_template_summary(),
            'can_issue_ticket_without_browser': bool(pre_resp.get('ticket')) or bool(verify_resp.get('ticket')),
        },
    }




def capture_standalone_ticket(*, bound: str = "", session_id: str = "", timeout: float = 30.0) -> dict[str, Any]:
    target = ensure_browser_target(bound=bound, session_id=session_id, timeout=min(max(timeout, 10.0), 60.0))
    active_bound = target.get('bound') or ''
    active_session_id = target.get('session_id') or ''
    script = f"""
(async () => {{
  function load(src) {{
    return new Promise((resolve, reject) => {{
      const s = document.createElement('script');
      s.src = src;
      s.onload = resolve;
      s.onerror = reject;
      document.head.appendChild(s);
    }});
  }}
  if (typeof TencentCaptcha === 'undefined') await load('https://captcha.gtimg.com/TCaptcha.js');
  return await new Promise((resolve) => {{
    let finished = false;
    const done = (obj) => {{ if (!finished) {{ finished = true; resolve(obj); }} }};
    try {{
      const cap = new TencentCaptcha({json.dumps(CAPTCHA_APPID)}, (res) => {{
        if (res && res.ret === 0 && res.ticket && res.randstr) {{
          done({{status:'captured', payload:{{ticket:res.ticket, randstr:res.randstr}}, raw:res, at:Date.now()}});
        }} else {{
          done({{status:'failed', raw:res, at:Date.now()}});
        }}
      }}, {{userLanguage:'zh-cn'}});
      cap.show();
      setTimeout(() => done({{status:'timeout', iframes:[...document.querySelectorAll('iframe')].map(f=>f.src), at:Date.now()}}), {int(timeout * 1000)});
    }} catch (e) {{
      done({{status:'error', error:String(e && e.stack || e), at:Date.now()}});
    }}
  }});
}})()
"""
    result = agent_browser_execute_js(bound=active_bound, session_id=active_session_id, script=script, timeout=timeout + 10)
    if not isinstance(result, dict):
        raise SystemExit(f'standalone captcha returned non-object: {result!r}')
    result['browser_target'] = target
    return result




def run_pure_report(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    import sys as _sys
    _cli = _sys.modules.get('matrix_ai_cli.cli')
    _load_ticket_provider = getattr(_cli, 'load_ticket_provider', None) or load_ticket_provider
    _detect_with_ticket = getattr(_cli, 'detect_with_ticket', None) or detect_with_ticket
    text_file_arg = getattr(args, 'text_file', None)
    text = load_text_arg(args.text, text_file_arg)
    fp = make_fp_for_mode(getattr(args, 'fp_mode', 'fixed'), args.fp)
    args.xff = text_route_xff(args, fp)
    provider_meta = None
    has_manual_ticket = bool(getattr(args, 'ticket', None) or getattr(args, 'randstr', None) or getattr(args, 'ticket_json', None))
    ticket_attempts = max(1, int(getattr(args, 'ticket_attempts', 2) or 2))
    ticket_command = args.ticket_command or (default_ticket_command(args.ticket_timeout, ticket_attempts) if args.auto_ticket and not has_manual_ticket else '')
    try:
        if ticket_command:
            ticket, randstr, provided_fp, provider_meta, provider_report = _load_ticket_provider(
                ticket_command,
                iteration=1,
                fp=fp,
                text=text,
                text_file=text_file_arg,
                xff=args.xff,
                provider_retries=max(1, int(getattr(args, 'ticket_provider_retries', 1) or 1)),
                provider_timeout=text_ticket_provider_timeout(args),
            )
            fp = provided_fp or fp
            if provider_report and text_detect_exit_code(provider_report) == 0:
                report = provider_report
            else:
                headers = build_ws_headers(xff=args.xff, headers=args.header)
                report = _detect_with_ticket(
                    text=text,
                    fp=fp,
                    ticket=ticket,
                    randstr=randstr,
                    timeout=args.timeout,
                    order=args.order,
                    additional_headers=headers,
                    text_send_mode=getattr(args, 'text_send_mode', 'on-code'),
                )
        else:
            fp, ticket, randstr = require_pure_ticket_inputs(fp=fp, ticket=args.ticket, randstr=args.randstr, ticket_json=args.ticket_json)
            headers = build_ws_headers(xff=args.xff, headers=args.header)
            report = _detect_with_ticket(
                text=text,
                fp=fp,
                ticket=ticket,
                randstr=randstr,
                timeout=args.timeout,
                order=args.order,
                additional_headers=headers,
                text_send_mode=getattr(args, 'text_send_mode', 'on-code'),
            )
    except Exception as exc:
        if provider_meta:
            report = {
                'fp': fp,
                'result': {'status': 'failed', 'msg': repr(exc)},
                'error': repr(exc),
                'provider': provider_meta,
            }
        else:
            raise
    report['input_text'] = text
    report['protocol_mode'] = 'pure'
    report['fp_mode'] = args.fp_mode
    report['xff'] = args.xff
    if provider_meta:
        report['provider'] = provider_meta
    return report, text




def run_text_browser_report(args: argparse.Namespace) -> tuple[dict[str, Any], str]:
    text = load_text_arg(args.text, args.text_file)
    fp_mode = getattr(args, 'browser_fp_mode', '') or getattr(args, 'fp_mode', 'pick')
    bound = getattr(args, 'bound', DEFAULT_BOUND)
    session_id = getattr(args, 'session_id', '')
    if fp_mode == 'fresh':
        fp = make_fp()
        pick_meta = None
    elif fp_mode == 'pick':
        picked = pick_fp(getattr(args, 'max_tries', 20), bound=bound, session_id=session_id)
        fp = picked.get('picked_fp') or ''
        pick_meta = picked
    else:
        fp = getattr(args, 'fp', '') or ''
        pick_meta = None
    args.xff = text_route_xff(args, fp)
    target = None
    try:
        fp, ticket, randstr, capture, target = resolve_ticket_and_fp(
            text=text,
            fp=fp,
            ticket=getattr(args, 'ticket', None),
            randstr=getattr(args, 'randstr', None),
            ticket_json=getattr(args, 'ticket_json', None),
            bound=bound,
            session_id=session_id,
            capture_timeout=getattr(args, 'capture_timeout', getattr(args, 'timeout', 60.0)),
            max_tries=getattr(args, 'max_tries', 20),
        )
        headers = build_ws_headers(xff=getattr(args, 'xff', ''), headers=getattr(args, 'header', []))
        report = detect_with_ticket(
            text=text,
            fp=fp,
            ticket=ticket,
            randstr=randstr,
            timeout=getattr(args, 'timeout', 20.0),
            order=getattr(args, 'order', 'fp-ticket-text'),
            additional_headers=headers,
            text_send_mode=getattr(args, 'text_send_mode', 'on-code'),
        )
        if capture:
            report['capture'] = capture
        if target:
            report['browser_target'] = target
        if pick_meta is not None:
            report['pick'] = pick_meta
        report['input_text'] = text
        report['protocol_mode'] = 'browser'
        report['route_driver'] = 'browser'
        report['fp_mode'] = fp_mode
        report['xff'] = getattr(args, 'xff', '')
        return report, text
    finally:
        if target and target.get('temporary') and target.get('session_id'):
            try:
                agent_browser_close_tab(str(target['session_id']))
            except BaseException:
                pass




def run_text_route_attempt(args: argparse.Namespace, route: str) -> tuple[dict[str, Any], str]:
    if route == 'browser':
        browser_args = namespace_clone(
            args,
            pure=False,
            fp_mode=getattr(args, 'browser_fp_mode', '') or 'pick',
            route_driver='browser',
        )
        return run_text_browser_report(browser_args)
    if route == 'pure-no-xff':
        pure_args = namespace_clone(
            args,
            fp_mode='fixed' if getattr(args, 'fp', '') else 'fresh',
            xff='',
            rotate_xff='',
            xff_pool=[],
            route_mode='off',
            auto_ticket=True if getattr(args, 'driver', 'auto') == 'auto' and not text_has_manual_one_time_ticket(args) else getattr(args, 'auto_ticket', True),
            route_driver=route,
        )
        return run_pure_report(pure_args)
    pure_args = namespace_clone(
        args,
        fp_mode='fixed' if getattr(args, 'fp', '') else ('fresh' if getattr(args, 'driver', 'auto') == 'auto' else getattr(args, 'fp_mode', 'fresh')),
        auto_ticket=True if getattr(args, 'driver', 'auto') == 'auto' and not text_has_manual_one_time_ticket(args) else getattr(args, 'auto_ticket', True),
        route_driver=route,
    )
    return run_pure_report(pure_args)




def run_text_auto_report(args: argparse.Namespace, *, attempt_fn=None) -> tuple[dict[str, Any], str]:
    if attempt_fn is None:
        attempt_fn = run_text_route_attempt
    driver = str(getattr(args, 'driver', 'pure') or 'pure')
    if getattr(args, 'pure', False):
        driver = 'pure'
    routes = text_route_order(args, driver=driver)
    attempts: list[dict[str, Any]] = []
    latest_provider: dict[str, Any] | None = None
    latest_error = ''
    last_text = load_text_arg(getattr(args, 'text', None), getattr(args, 'text_file', None))
    stop_on_first_failure = bool(getattr(args, 'stop_on_first_failure', False))
    manual_ticket = text_has_manual_one_time_ticket(args)
    for idx, route in enumerate(routes, start=1):
        if idx > 1 and manual_ticket:
            attempts.append({
                'route': route,
                'ok': False,
                'skipped': True,
                'failure_stage': 'manual-one-time-ticket-not-reused',
            })
            continue
        started = time.time()
        try:
            report, text = attempt_fn(args, route)
            last_text = text
            stage = text_failure_stage(report)
            ok = not stage
            attempt = {
                'route': route,
                'ok': ok,
                'failure_stage': stage,
                'elapsed_sec': round(time.time() - started, 4),
                'fp': report.get('fp'),
                'xff': report.get('xff') or (report.get('headers') or {}).get('X-Forwarded-For') or '',
                'status': (report.get('result') or {}).get('status') or report.get('status'),
                'captcha': extract_first_captcha_code(report),
                'protocol_mode': report.get('protocol_mode') or ('browser' if route == 'browser' else 'pure'),
            }
            provider_tries = (report.get('provider') or {}).get('provider_tries') if isinstance(report.get('provider'), dict) else None
            if isinstance(provider_tries, list):
                attempt['provider_tries'] = provider_tries
                latest_provider = report.get('provider')
            if report.get('error'):
                latest_error = str(report.get('error') or '')
            attempts.append(attempt)
            if ok:
                report['text_route'] = {
                    'mode': getattr(args, 'route_mode', 'auto'),
                    'driver': driver,
                    'selected': route,
                    'attempts': attempts,
                    'manual_ticket': manual_ticket,
                    'agent_hint': 'ok',
                }
                return report, text
            if stop_on_first_failure:
                break
        except SystemExit as exc:
            attempt = {
                'route': route,
                'ok': False,
                'failure_stage': text_failure_stage(None, error=str(exc)),
                'elapsed_sec': round(time.time() - started, 4),
                'error': str(exc),
            }
            attempts.append(attempt)
            if stop_on_first_failure:
                break
        except Exception as exc:
            attempt = {
                'route': route,
                'ok': False,
                'failure_stage': text_failure_stage(None, error=repr(exc)),
                'elapsed_sec': round(time.time() - started, 4),
                'error': repr(exc),
            }
            if isinstance(exc, TicketProviderError):
                attempt['provider_tries'] = exc.tries
            attempts.append(attempt)
            if stop_on_first_failure:
                break
    final_report = {
        'protocol_mode': driver,
        'route_driver': driver,
        'fp_mode': getattr(args, 'fp_mode', ''),
        'xff': getattr(args, 'xff', ''),
        'input_text': last_text,
        'result': {'status': 'failed', 'msg': 'all text routes failed'},
        'text_route': {
            'mode': getattr(args, 'route_mode', 'auto'),
            'driver': driver,
            'selected': '',
            'attempts': attempts,
            'manual_ticket': manual_ticket,
            'agent_hint': 'switch-route-or-use-browser',
        },
    }
    if isinstance(latest_provider, dict):
        final_report['provider'] = latest_provider
    if latest_error:
        final_report['error'] = latest_error
    return final_report, last_text




def text_check_result(report: dict[str, Any], *, report_json: str = "") -> dict[str, Any]:
    result = report.get('result') or {}
    code_msg = extract_first_captcha_code(report)
    route = report.get('text_route') or {}
    failure_stage = text_failure_stage(report)
    next_command = ''
    if failure_stage:
        if route.get('manual_ticket'):
            next_command = 'matrix-ai-cli check-text --driver auto --fp-mode fresh --auto-ticket --text-file <path> --out-dir <dir>'
        else:
            next_command = 'matrix-ai-cli check-text --driver auto --fp-mode fresh --text-file <path> --out-dir <dir>'
    return {
        'ok': text_detect_exit_code(report) == 0,
        'protocol_mode': report.get('protocol_mode') or 'pure',
        'status': result.get('status'),
        'fp': report.get('fp'),
        'xff': report.get('xff') or (report.get('headers') or {}).get('X-Forwarded-For') or '',
        'captcha': {
            'code': code_msg.get('code'),
            'evil_level': code_msg.get('evil_level'),
            'msg': code_msg.get('msg'),
        },
        'confidence': result.get('confidence'),
        'labels_ratio': result.get('labels_ratio'),
        'content_type': result.get('content_type'),
        'availableUses': result.get('availableUses'),
        'segment_labels': result.get('segment_labels') or [],
        'feedback_token': result.get('feedback_token'),
        'report_json': report_json,
        'route_state': route,
        'failure_stage': failure_stage,
        'stop_loss_recommended': failure_stage.startswith('captcha-evil-level-'),
        'agent_hint': 'ok' if not failure_stage else ((route.get('agent_hint') or 'switch-route-or-use-browser')),
        'next_command': next_command,
    }




def attach_text_agent_contract(report: dict[str, Any], *, report_json: str = "") -> dict[str, Any]:
    compact = text_check_result(report, report_json=report_json)
    contract = {
        'ok': compact.get('ok'),
        'route_state': compact.get('route_state') or {},
        'failure_stage': compact.get('failure_stage') or '',
        'agent_hint': compact.get('agent_hint') or '',
        'next_command': compact.get('next_command') or '',
        'stop_loss_recommended': compact.get('stop_loss_recommended'),
        'report_json': report_json,
    }
    report['agent_contract'] = contract
    report['ok'] = compact.get('ok')
    report['route_state'] = contract['route_state']
    report['failure_stage'] = contract['failure_stage']
    report['agent_hint'] = contract['agent_hint']
    report['next_command'] = contract['next_command']
    report['stop_loss_recommended'] = contract['stop_loss_recommended']
    report['report_json'] = report_json
    return compact
