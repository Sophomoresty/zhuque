"""Text detection: WS protocol, browser ticket capture, PDF rendering."""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import requests
import websockets
import websockets.sync.client
from jinja2 import Template

try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from weasyprint import HTML
except ImportError:
    HTML = None

from .config import (
    CAPTCHA_APPID,
    CAPTCHA_ENTRY_URL,
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    DEFAULT_UA,
    HTTP_BASE,
    JSON_PARSER_ARGV,
    MATRIX_PIC_URL,
    MATRIX_TXT_URL,
    WS_URL,
)
from .transport import (
    agent_browser_action,
    agent_browser_close_tab,
    agent_browser_eval,
    agent_browser_execute_js,
    agent_browser_open_new_tab,
    build_ws_headers,
    discover_candidate_fps,
    egress_meta,
    ensure_browser_bridge,
    load_text_arg,
    load_ticket_args,
    make_fp,
    make_fp_for_mode,
    parse_last_json,
    recv_json,
    wait_browser_session_ready,
    ws_connect_kwargs,
    xff_for_iteration,
)
from .captcha import (
    captcha_prehandle,
    captcha_ticket_pure,
    captcha_verify_static_tdc,
    extract_first_captcha_code,
    make_tdc_ft,
    solve_md5_pow,
)


HTML_TEMPLATE = Template("""
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: 'Noto Sans CJK SC', 'Noto Sans CJK', sans-serif; margin: 24px; color: #222; }
    h1 { font-size: 24px; margin-bottom: 8px; }
    h2 { font-size: 18px; margin-top: 24px; }
    .meta { color: #555; font-size: 12px; line-height: 1.6; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border: 1px solid #ccc; padding: 8px; vertical-align: top; font-size: 12px; }
    .text-block { white-space: pre-wrap; line-height: 1.6; font-size: 13px; }
  </style>
</head>
<body>
  <h1>AI检测报告</h1>
  <div class="meta">
    <div>生成时间: {{ generated_at }}</div>
    <div>FP: {{ fp }}</div>
    <div>剩余次数: {{ available_uses }}</div>
    <div>置信度: {{ confidence }}</div>
    <div>内容类型: {{ content_type }}</div>
  </div>
  <h2>统计</h2>
  <table>
    <tr><th>labels_ratio</th><td>{{ labels_ratio_json }}</td></tr>
    <tr><th>feedback_token</th><td>{{ feedback_token }}</td></tr>
  </table>
  <h2>原文</h2>
  <div class="text-block">{{ text }}</div>
  <h2>分段分析</h2>
  <table>
    <thead><tr><th>#</th><th>label</th><th>conf</th><th>position</th><th>text</th></tr></thead>
    <tbody>
      {% for seg in segments %}
      <tr>
        <td>{{ seg.order }}</td>
        <td>{{ seg.label }}</td>
        <td>{{ seg.conf }}</td>
        <td>{{ seg.position }}</td>
        <td class="text-block">{{ seg.text }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</body>
</html>
""")



def handshake_only(fp: str, *, additional_headers: dict[str, str] | None = None) -> dict[str, Any]:
    with websockets.sync.client.connect(WS_URL, **ws_connect_kwargs(additional_headers)) as ws:
        ws.send(json.dumps({"fp": fp}))
        first = recv_json(ws)
        return {"fp": fp, "headers": additional_headers or {}, "first": first}



def text_should_send_after_captcha(msg: dict[str, Any], text_send_mode: str) -> bool:
    if msg.get("code") != "1":
        return False
    evil = str(msg.get("evil_level") or "").strip()
    if evil and evil != "0":
        return False
    return text_send_mode == "on-code" or evil == "0"



def captcha_evil_level(msg: dict[str, Any]) -> int:
    try:
        return int(str(msg.get("evil_level") or "0").strip())
    except Exception:
        return 0



def pick_fp(
    max_tries: int = 20,
    *,
    preferred_fps: list[str] | None = None,
    bound: str = "",
    session_id: str = "",
) -> dict[str, Any]:
    candidates = discover_candidate_fps(preferred_fps=preferred_fps, bound=bound, session_id=session_id)
    attempts = []
    best: dict[str, Any] | None = None
    for candidate in candidates[:max_tries]:
        fp = candidate['fp']
        probe = handshake_only(fp)
        attempts.append({'candidate': candidate, 'probe': probe})
        first = probe.get('first', {})
        uses = int(first.get('availableUses', 0)) if first.get('status') == 'success' else 0
        if uses > 0:
            if best is None or uses > best['available_uses']:
                best = {
                    'picked_fp': fp,
                    'probe': probe,
                    'candidate': candidate,
                    'available_uses': uses,
                }
    if best:
        return {**best, 'attempts': attempts, 'candidates': candidates}
    return {'picked_fp': None, 'attempts': attempts, 'candidates': candidates}



def detect_with_ticket(
    text: str,
    fp: str,
    ticket: str,
    randstr: str,
    timeout: float = 20.0,
    *,
    order: str = "fp-ticket-text",
    additional_headers: dict[str, str] | None = None,
    text_send_mode: str = "on-code",
) -> dict[str, Any]:
    logs: list[dict[str, Any]] = []
    if order not in {"fp-ticket-text", "ticket-text", "ticket-fp-text", "fp-text-ticket", "fp-ticket-text-immediate"}:
        raise SystemExit(f"unsupported protocol order: {order}")
    if order in {"fp-ticket-text", "ticket-fp-text", "fp-text-ticket", "fp-ticket-text-immediate"} and not fp:
        raise SystemExit(f"missing fp for protocol order: {order}")
    with websockets.sync.client.connect(WS_URL, **ws_connect_kwargs(additional_headers)) as ws:
        if order in {"fp-ticket-text", "fp-text-ticket", "fp-ticket-text-immediate"}:
            ws.send(json.dumps({"fp": fp}, separators=(",", ":")))
            logs.append({"send": {"fp": fp}})
            first = recv_json(ws)
            logs.append({"recv": first})
            # Browser behavior: server returns 'failed Invalid request' for first frame on
            # fresh fp, but continues to accept ticket. Only abort on explicit limit/quota.
            if first.get("status") != "success" and first.get("status") in ("limited",) and first.get("msg") != "Invalid request":
                return {"fp": fp, "protocol_order": order, "headers": additional_headers or {}, "logs": logs, "result": first}
        ws.send(json.dumps({"ticket": ticket, "randstr": randstr}, separators=(",", ":")))
        logs.append({"send": {"ticket": "<ticket>", "randstr": randstr}})
        if order == "ticket-fp-text":
            ws.send(json.dumps({"fp": fp}, separators=(",", ":")))
            logs.append({"send": {"fp": fp}})
        sent_text = False
        deadline = time.time() + timeout
        final = None
        while time.time() < deadline:
            msg = recv_json(ws)
            logs.append({"recv": msg})
            if captcha_evil_level(msg) > 0:
                final = msg
                break
            if not sent_text and text_should_send_after_captcha(msg, text_send_mode):
                ws.send(json.dumps({"text": text}, ensure_ascii=False, separators=(",", ":")))
                logs.append({"send": {"text_len": len(text), "after_evil_level": msg.get("evil_level")}})
                sent_text = True
                continue
            if msg.get("status") == "success" and "confidence" in msg:
                final = msg
                break
            if msg.get("status") in ("failed", "limited") or msg.get("msg") == "Invalid request":
                final = msg
                break
        return {"fp": fp, "protocol_order": order, "headers": additional_headers or {}, "logs": logs, "result": final}




def submit_feedback(fp: str, report: dict[str, Any], *, status: bool = True, timeout: float = 20.0) -> dict[str, Any]:
    result = report.get('result') or report
    feedback_token = result.get('feedback_token') or result.get('feedbackToken') or ''
    cos_url = result.get('cos_url') or result.get('cos') or report.get('cos') or ''
    if not cos_url:
        # Historical successful reports store cos only inside segment labels or omit it; keep a
        # server-visible request error as evidence instead of fabricating a value.
        cos_url = ''
    body = {
        'uid': fp,
        'cos_url': cos_url,
        'feedback_token': feedback_token,
        'user_label': 1 if status else 0,
        'data': {
            'reason': '',
            'source_link': '',
            'masterpiece': '',
            'model': '',
            'prompt': '',
        },
    }
    r = requests.post(
        HTTP_BASE + '/feedback',
        headers={'Content-Type': 'application/json', 'FP': fp, 'User-Agent': DEFAULT_UA},
        json=body,
        timeout=timeout,
    )
    try:
        data = r.json()
    except Exception:
        data = {'text': r.text[:1000]}
    return {'status_code': r.status_code, 'response': data, 'request': body}


def render_pdf(report: dict[str, Any], text: str, out_pdf: Path) -> dict[str, Any]:
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    html = HTML_TEMPLATE.render(
        generated_at=time.strftime("%Y-%m-%d %H:%M:%S"),
        fp=report.get("fp"),
        available_uses=report.get("result", {}).get("availableUses"),
        confidence=report.get("result", {}).get("confidence"),
        content_type=report.get("result", {}).get("content_type"),
        labels_ratio_json=json.dumps(report.get("result", {}).get("labels_ratio", {}), ensure_ascii=False),
        feedback_token=report.get("result", {}).get("feedback_token", ""),
        text=text,
        segments=report.get("result", {}).get("segment_labels", []),
    )
    HTML(string=html).write_pdf(str(out_pdf))
    return {"pdf": str(out_pdf), "size": out_pdf.stat().st_size}



def extract_pdf_text(pdf_path: Path) -> dict[str, Any]:
    reader = PdfReader(str(pdf_path))
    parts = []
    for page in reader.pages:
        parts.append(page.extract_text() or "")
    text = "\n".join(parts)
    return {"pdf": str(pdf_path), "text": text, "text_len": len(text), "pages": len(reader.pages)}



def text_detect_exit_code(report: dict[str, Any]) -> int:
    result = report.get('result') or {}
    return 0 if result.get('status') == 'success' and 'confidence' in result else 2




def text_route_xff(args: argparse.Namespace, fp: str) -> str:
    from .batch import parse_rotate_xff_candidates
    route_mode = str(getattr(args, 'route_mode', 'auto') or 'auto')
    explicit = str(getattr(args, 'xff', '') or '').strip()
    if explicit or route_mode == 'off':
        return explicit
    pool = parse_rotate_xff_candidates(getattr(args, 'xff_pool', None) or [])
    if pool:
        return pool[0]
    rotate = str(getattr(args, 'rotate_xff', '') or '').strip()
    if rotate:
        return xff_for_iteration(rotate, 1)
    if getattr(args, 'fp_mode', 'fresh') != 'fresh':
        if route_mode == 'on':
            raise ValueError('route-mode=on requires --xff, --xff-pool, --rotate-xff, or --fp-mode fresh')
        return explicit
    salt = os.environ.get('MATRIX_AI_TEXT_XFF_SALT') or 'matrix-ai-cli-text-xff'
    derived = hashlib.sha256(f"{fp}:{salt}".encode()).digest()
    return f"10.214.{derived[0] % 240}.{derived[1] % 240 + 1}"



def namespace_clone(args: argparse.Namespace, **updates: Any) -> argparse.Namespace:
    data = dict(vars(args))
    data.update(updates)
    return argparse.Namespace(**data)



def text_has_explicit_route(args: argparse.Namespace) -> bool:
    from .batch import parse_rotate_xff_candidates
    return bool(
        str(getattr(args, 'xff', '') or '').strip()
        or str(getattr(args, 'rotate_xff', '') or '').strip()
        or parse_rotate_xff_candidates(getattr(args, 'xff_pool', None) or [])
    )



def text_has_manual_one_time_ticket(args: argparse.Namespace) -> bool:
    return bool(
        (getattr(args, 'ticket', None) or getattr(args, 'randstr', None) or getattr(args, 'ticket_json', None))
        and not getattr(args, 'ticket_command', '')
    )



def text_failure_stage(report: dict[str, Any] | None, *, error: str = '') -> str:
    if error:
        error_l = error.lower()
        if 'ticket provider failed' in error_l:
            return 'ticket-provider-failed'
        if 'auto capture ticket failed' in error_l or 'captcha' in error_l:
            return 'captcha-capture-failed'
        if 'missing ticket/randstr' in error_l or 'valid --ticket-json' in error_l:
            return 'input-error'
        if 'missing fp' in error_l:
            return 'missing-fp'
        return 'exception'
    if not report:
        return 'detect-failed'
    if text_detect_exit_code(report) == 0:
        return ''
    captcha = extract_first_captcha_code(report)
    evil = str(captcha.get('evil_level') or '').strip()
    try:
        evil_int = int(evil or 0)
    except Exception:
        evil_int = 0
    if evil_int > 0:
        return f'captcha-evil-level-{evil_int}'
    result = report.get('result') or {}
    status = str(result.get('status') or '').strip().lower()
    msg = str(result.get('msg') or result.get('msg_en') or captcha.get('msg') or '').strip().lower()
    if 'invalid request' in msg:
        return 'invalid-request'
    if 'ticket' in msg:
        return 'ticket-rejected'
    if status:
        return status
    if not report.get('fp'):
        return 'missing-fp'
    return 'detect-failed'



def text_route_order(args: argparse.Namespace, *, driver: str) -> list[str]:
    if driver == 'browser':
        return ['browser']
    raw = (
        str(getattr(args, 'route_order', '') or '').strip()
        or os.environ.get('MATRIX_AI_TEXT_ROUTE_ORDER', '').strip()
        or 'auto'
    )
    if raw == 'auto':
        raw = 'pure-auto,pure-no-xff' if driver == 'pure' else 'browser,pure-auto,pure-no-xff'
    aliases = {
        'pure': 'pure-auto',
        'pure-xff': 'pure-auto',
        'no-xff': 'pure-no-xff',
        'browser-assisted': 'browser',
    }
    out: list[str] = []
    seen: set[str] = set()
    for part in raw.replace(';', ',').split(','):
        item = aliases.get(part.strip(), part.strip())
        if item not in {'pure-auto', 'pure-no-xff', 'browser'}:
            continue
        if driver == 'pure' and item == 'browser':
            continue
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out or (['pure-auto', 'pure-no-xff'] if driver == 'pure' else ['pure-auto', 'browser', 'pure-no-xff'])



def resolve_ticket_and_fp(
    *,
    text: str,
    fp: str,
    ticket: str | None,
    randstr: str | None,
    ticket_json: str | None,
    bound: str,
    session_id: str,
    capture_timeout: float,
    max_tries: int,
) -> tuple[str, str, str, dict[str, Any] | None, dict[str, Any] | None]:
    from .browser_state import (
        browser_txt_state,
        capture_ticket_auto,
        ensure_browser_target,
        ensure_usable_browser_fp,
    )

    if ticket or randstr or ticket_json:
        ticket, randstr = load_ticket_args(ticket, randstr, ticket_json)
        if not fp:
            raise SystemExit('missing fp when using manual ticket/randstr inputs')
        return fp, ticket, randstr, None, None
    errors: list[str] = []
    for attempt_index in range(2):
        target = ensure_browser_target(
            bound=bound,
            session_id=session_id,
            timeout=min(max(capture_timeout, 30.0), 60.0),
            force_new=bool(attempt_index and not session_id),
        )
        active_bound = target.get('bound') or ''
        active_session_id = target.get('session_id') or ''
        try:
            if not fp:
                state = target.get('state') or browser_txt_state(bound=active_bound, session_id=active_session_id, timeout=10.0)
                ensured = ensure_usable_browser_fp(
                    bound=active_bound,
                    session_id=active_session_id,
                    current_fp=state.get('fp'),
                    timeout=min(max(capture_timeout, 30.0), 60.0),
                    max_tries=max_tries,
                )
                fp = ensured.get('fp') or ''
            else:
                probe = handshake_only(fp)
                first = probe.get('first') or {}
                if first.get('status') != 'success' or int(first.get('availableUses', 0)) <= 0:
                    ensured = ensure_usable_browser_fp(
                        bound=active_bound,
                        session_id=active_session_id,
                        current_fp=fp,
                        timeout=min(max(capture_timeout, 30.0), 60.0),
                        max_tries=max_tries,
                    )
                    fp = ensured.get('fp') or ''
            capture = capture_ticket_auto(
                text=text,
                bound=active_bound,
                session_id=active_session_id,
                fp=fp or None,
                timeout=capture_timeout,
            )
            payload = capture.get('payload') or {}
            ticket = payload.get('ticket')
            randstr = payload.get('randstr')
            fp = capture.get('fp') or fp
            if not fp or not ticket or not randstr:
                raise SystemExit(f'auto capture returned incomplete payload: {capture}')
            if errors:
                target['recovery_errors'] = errors
            return fp, ticket, randstr, capture, target
        except SystemExit as exc:
            errors.append(str(exc))
            if target.get('temporary') and target.get('session_id'):
                with contextlib.suppress(BaseException):
                    agent_browser_close_tab(str(target['session_id']))
            if session_id or attempt_index:
                raise
            fp = ''
    raise SystemExit(f'auto browser ticket recovery failed: {errors}')





def require_pure_ticket_inputs(*, fp: str, ticket: str | None, randstr: str | None, ticket_json: str | None) -> tuple[str, str, str]:
    ticket, randstr = load_ticket_args(ticket, randstr, ticket_json)
    return fp, ticket, randstr



def default_ticket_command(timeout: float, attempts: int = 2) -> str:
    return f"matrix-ai-cli captcha-ticket --mode validated --timeout {timeout} --attempts {max(1, int(attempts or 1))}"



def text_ticket_provider_timeout(args: argparse.Namespace) -> float:
    explicit = float(getattr(args, 'ticket_provider_timeout', 0.0) or 0.0)
    if explicit > 0:
        return min(300.0, explicit)
    env_timeout = str(os.environ.get('MATRIX_AI_TEXT_TICKET_PROVIDER_TIMEOUT') or '').strip()
    if env_timeout:
        return min(300.0, max(1.0, float(env_timeout)))
    ticket_timeout = float(getattr(args, 'ticket_timeout', 20.0) or 20.0)
    ticket_attempts = max(1, int(getattr(args, 'ticket_attempts', 2) or 2))
    return min(120.0, max(30.0, ticket_timeout * ticket_attempts + 15.0))



def run_shell_command_capture(command: str, *, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    argv = shlex.split(command)
    if not argv:
        raise RuntimeError("empty ticket provider command")
    proc = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        with contextlib.suppress(ProcessLookupError, OSError):
            os.killpg(proc.pid, signal.SIGTERM)
        with contextlib.suppress(ProcessLookupError, OSError):
            proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(ProcessLookupError, OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            with contextlib.suppress(ProcessLookupError, OSError):
                proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                stdout = exc.stdout if isinstance(exc.stdout, str) else ''
                stderr = exc.stderr if isinstance(exc.stderr, str) else ''
                with contextlib.suppress(subprocess.TimeoutExpired, ProcessLookupError, OSError):
                    if not hasattr(proc, 'wait'):
                        raise ProcessLookupError()
                    proc.wait(timeout=1)
        raise subprocess.TimeoutExpired(command, timeout, output=stdout, stderr=stderr) from exc
    return subprocess.CompletedProcess(command, proc.returncode, stdout, stderr)



def json_command_error(command: str, error: BaseException | str, *, exit_code: int = 2, failure_stage: str | None = None) -> dict[str, Any]:
    message = str(error) or f"command failed with exit code {exit_code}"
    if not failure_stage:
        message_l = message.lower().replace('_', '-')
        message_words = message_l.split()
        input_markers = ('missing', 'requires', 'unsupported', 'invalid')
        failure_stage = 'input-error' if any((marker in message_words) or message_l.startswith(marker) for marker in input_markers) else 'exception'
    return {
        'ok': False,
        'command': command,
        'error': message,
        'exit_code': exit_code,
        'route_state': {},
        'failure_stage': failure_stage,
        'stop_loss_recommended': False,
        'agent_hint': 'fix-input' if failure_stage == 'input-error' else 'inspect-error',
        'next_command': f"matrix-ai-cli {command} --help" if command else "matrix-ai-cli --help",
        'report_json': '',
    }



class TicketProviderError(RuntimeError):
    def __init__(self, message: str, *, tries: list[dict[str, Any]]):
        super().__init__(message)
        self.tries = tries



def load_ticket_provider(
    command: str,
    *,
    iteration: int,
    fp: str,
    text: str | None = None,
    text_file: str | None = None,
    xff: str = "",
    provider_retries: int = 1,
    provider_timeout: float = 0.0,
) -> tuple[str, str, str | None, dict[str, Any], dict[str, Any]]:
    env = os.environ.copy()
    env['MATRIX_AI_ITERATION'] = str(iteration)
    env['MATRIX_AI_FP'] = fp
    if text_file:
        # Prefer passing the file path for long papers; exporting the full text can exceed OS env limits.
        env['MATRIX_AI_TEXT_FILE'] = text_file
    elif text:
        if len(text.encode('utf-8')) > 32768:
            raise TicketProviderError(
                "ticket provider text too large for environment; use --text-file",
                tries=[{
                    'command': command,
                    'provider_try': 0,
                    'returncode': None,
                    'error': 'text-too-large-for-env',
                    'text_bytes': len(text.encode('utf-8')),
                }],
            )
        env['MATRIX_AI_TEXT'] = text
    if xff:
        env['MATRIX_AI_XFF'] = xff
    effective_timeout = min(300.0, max(1.0, float(provider_timeout or os.environ.get('MATRIX_AI_TEXT_TICKET_PROVIDER_TIMEOUT') or 75.0)))
    tries: list[dict[str, Any]] = []
    for provider_try in range(1, max(1, provider_retries) + 1):
        env['MATRIX_AI_PROVIDER_TRY'] = str(provider_try)
        try:
            proc = run_shell_command_capture(command, env=env, timeout=effective_timeout)
            meta = {
                'command': command,
                'provider_try': provider_try,
                'returncode': proc.returncode,
                'stdout_tail': proc.stdout[-1000:],
                'stderr_tail': proc.stderr[-1000:],
                'timeout_sec': effective_timeout,
            }
        except subprocess.TimeoutExpired as exc:
            meta = {
                'command': command,
                'provider_try': provider_try,
                'returncode': None,
                'stdout_tail': (exc.stdout or '')[-1000:] if isinstance(exc.stdout, str) else '',
                'stderr_tail': (exc.stderr or '')[-1000:] if isinstance(exc.stderr, str) else '',
                'error': f'timeout after {exc.timeout}s',
                'timeout_sec': effective_timeout,
            }
            tries.append(meta)
            continue
        if proc.returncode != 0:
            tries.append(meta)
            continue
        try:
            obj = parse_last_json(proc.stdout)
        except Exception as exc:
            meta['error'] = f'parse-provider-json: {exc}'
            tries.append(meta)
            continue
        if not isinstance(obj, dict):
            meta['error'] = f'parse-provider-json: expected object, got {type(obj).__name__}'
            tries.append(meta)
            continue
        payload = obj.get('payload') or obj.get('js_return', {}).get('payload') or obj
        if not isinstance(payload, dict):
            meta['error'] = f'parse-provider-json: expected payload object, got {type(payload).__name__}'
            tries.append(meta)
            continue
        ticket = payload.get('ticket')
        randstr = payload.get('randstr')
        provided_fp = payload.get('fp') or obj.get('fp')
        provider_report = obj.get('report') or obj.get('detect') or {}
        meta['provider'] = obj.get('provider')
        meta['status'] = obj.get('status')
        meta['validation'] = obj.get('validation')
        current_try = {k: v for k, v in meta.items() if k not in {'tries', 'provider_tries'}}
        provider_tries = [*tries, current_try]
        meta['provider_tries'] = provider_tries
        if ticket and randstr:
            return ticket, randstr, provided_fp, meta, provider_report
        meta['error'] = 'ticket provider returned no ticket/randstr'
        tries.append(meta)
    last = tries[-1] if tries else {}
    raise TicketProviderError(
        f"ticket provider failed after {max(1, provider_retries)} tries rc={last.get('returncode')} error={last.get('error') or ''}",
        tries=tries,
    )



def write_json_file(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding='utf-8')


def captcha_risk_level(report: dict[str, Any]) -> int:
    code_msg = extract_first_captcha_code(report)
    try:
        return int(code_msg.get("evil_level") or 0)
    except Exception:
        return 0
