"""Captcha solving: prehandle, TDC, verify, ticket issuance."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import string
import subprocess
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests
try:
    from curl_cffi import requests as curl_requests
except Exception:  # pragma: no cover
    curl_requests = None

from .config import (
    CAPTCHA_API_BASE,
    CAPTCHA_APPID,
    CAPTCHA_CURL_IMPERSONATE,
    CAPTCHA_ENTRY_URL,
    CAPTCHA_IFRAME_REFERER,
    CAPTCHA_UA,
    TERROR_TICKET_APPID,
    TERROR_TICKET_ERROR_CODE,
)
try:
    from .tdc_templates import TENCENTCAPTCHA_STATIC_TDC_TEMPLATE
except ImportError:  # pragma: no cover
    from tdc_templates import TENCENTCAPTCHA_STATIC_TDC_TEMPLATE

from .transport import request_proxies


def solve_md5_pow(prefix: str, target: str, *, limit: int = 20_000_000) -> dict[str, Any]:
    started = time.time()
    if not prefix or not target:
        return {'ok': False, 'answer': None, 'elapsed_sec': 0.0, 'reason': 'missing-prefix-or-target'}
    for i in range(limit):
        if hashlib.md5((prefix + str(i)).encode()).hexdigest() == target:
            return {'ok': True, 'answer': str(i), 'elapsed_sec': round(time.time() - started, 6), 'limit': limit}
    return {'ok': False, 'answer': None, 'elapsed_sec': round(time.time() - started, 6), 'limit': limit, 'reason': 'not-found'}




def make_terror_ticket(*, now: float | None = None) -> dict[str, Any]:
    ts = int(now or time.time())
    rand = '@' + hashlib.md5(f'{ts}:{os.getpid()}:{time.time_ns()}'.encode()).hexdigest()[:6]
    ticket = f'terror_{TERROR_TICKET_ERROR_CODE}_{TERROR_TICKET_APPID}_{ts}'
    return {
        'ticket': ticket,
        'randstr': rand,
        'appid': TERROR_TICKET_APPID,
        'error_code': TERROR_TICKET_ERROR_CODE,
        'timestamp': ts,
        'source': 'frontend-loadErrorCallback-compatible',
    }



def captcha_ticket_terror() -> dict[str, Any]:
    payload = make_terror_ticket()
    return {
        'status': 'captured',
        'protocol_mode': 'pure',
        'provider': 'matrix-frontend-terror-ticket',
        'payload': {'ticket': payload['ticket'], 'randstr': payload['randstr']},
        'ticket_summary': {k: v for k, v in payload.items() if k not in {'ticket', 'randstr'}},
    }


def captcha_http_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
    egress_proxy: str = "",
):
    proxies = request_proxies(egress_proxy)
    if curl_requests is not None:
        try:
            return curl_requests.get(
                url,
                params=params,
                headers=headers,
                impersonate=CAPTCHA_CURL_IMPERSONATE,
                proxies=proxies,
                timeout=timeout,
            )
        except Exception:
            pass
    session = requests.Session()
    if egress_proxy:
        session.trust_env = False
    return session.get(url, params=params, headers=headers, proxies=proxies, timeout=timeout)


def captcha_prehandle(
    *,
    timeout: float = 20.0,
    ua: str = CAPTCHA_UA,
    entry_url: str = CAPTCHA_ENTRY_URL,
    xff: str = "",
    egress_proxy: str = "",
) -> dict[str, Any]:
    ua_b64 = base64.b64encode(ua.encode()).decode()
    params = {
        'aid': CAPTCHA_APPID,
        'protocol': 'https',
        'accver': '1',
        'showtype': 'popup',
        'ua': ua_b64,
        'noheader': '1',
        'fb': '1',
        'aged': '0',
        'enableAged': '0',
        'enableDarkMode': '0',
        'grayscale': '1',
        'dyeid': '0',
        'clientype': '2',
        'cap_cd': '',
        'uid': '',
        'lang': 'zh-cn',
        'entry_url': entry_url,
        'elder_captcha': '0',
        'js': '',
        'login_appid': '',
        'support_media': 'jpeg,png,gif,mp4,webm',
        'wb': '2',
        'version': '1.1.0',
        'userLanguage': 'zh-cn',
        'subsid': '1',
        'sess': '',
        'agent_id': '',
        'agent_auth_sign': '',
        'callback': '_matrix_ai_cli_cb',
    }
    headers = {
        'User-Agent': ua,
        'Referer': 'https://matrix.tencent.com/',
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Sec-Fetch-Dest': 'script',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Storage-Access': 'active',
        'sec-ch-ua': '"Not/A)Brand";v="99", "Chromium";v="148"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    if xff:
        headers['X-Forwarded-For'] = xff
    r = captcha_http_get(
        CAPTCHA_API_BASE + '/cap_union_prehandle',
        params=params,
        headers=headers,
        timeout=timeout,
        egress_proxy=egress_proxy,
    )
    text = r.text
    parsed: dict[str, Any]
    m = re.match(r'^\s*[^()]+\((.*)\)\s*;?\s*$', text, re.S)
    try:
        parsed = json.loads(m.group(1) if m else text)
    except Exception as exc:
        parsed = {'_parse_error': str(exc), 'raw': text[:1000]}
    return {
        'ok': r.ok,
        'status_code': r.status_code,
        'url': r.url,
        'request': {'params': params, 'ua': ua, 'entry_url': entry_url, 'xff': xff, 'egress_proxy': egress_proxy},
        'response': parsed,
        'text_prefix': text[:1200],
    }



def captcha_verify_probe(prehandle: dict[str, Any], *, timeout: float = 20.0, ua: str = CAPTCHA_UA) -> dict[str, Any]:
    ph = prehandle.get('response') or prehandle
    sess = ph.get('sess') or ''
    cfg = ((ph.get('data') or {}).get('comm_captcha_cfg') or {})
    pow_cfg = cfg.get('pow_cfg') or {}
    pow_result = solve_md5_pow(pow_cfg.get('prefix', ''), pow_cfg.get('md5', ''))
    collect = '------'
    ans = []
    body = {
        'collect': collect,
        'tlg': str(len(collect)),
        'eks': '',
        'sess': sess,
        'ans': json.dumps(ans, separators=(',', ':')),
    }
    if pow_result.get('ok'):
        body['pow_answer'] = str(pow_cfg.get('prefix', '')) + str(pow_result.get('answer'))
        body['pow_calc_time'] = str(max(1, int(float(pow_result.get('elapsed_sec') or 0) * 1000)))
    r = requests.post(
        CAPTCHA_API_BASE + '/cap_union_new_verify',
        data=body,
        headers={
            'User-Agent': ua,
            'Referer': CAPTCHA_IFRAME_REFERER,
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'sec-ch-ua': '"Not/A)Brand";v="99", "Chromium";v="148"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        },
        timeout=timeout,
    )
    try:
        parsed = r.json()
    except Exception:
        parsed = {'raw': r.text[:1000]}
    return {
        'ok': bool(parsed.get('ticket') and parsed.get('randstr')),
        'status_code': r.status_code,
        'request': body,
        'response': parsed,
        'pow': pow_result,
        'text_prefix': r.text[:1200],
    }



def tdc_template_summary() -> dict[str, Any]:
    tpl = TENCENTCAPTCHA_STATIC_TDC_TEMPLATE
    return {
        'name': tpl.get('name'),
        'source_evidence': tpl.get('source_evidence'),
        'collect_len': len(tpl.get('collect') or ''),
        'collect_sha256': tpl.get('collect_sha256') or hashlib.sha256((tpl.get('collect') or '').encode()).hexdigest(),
        'eks_len': len(tpl.get('eks') or ''),
        'eks_sha256': tpl.get('eks_sha256') or hashlib.sha256((tpl.get('eks') or '').encode()).hexdigest(),
        'ans': tpl.get('ans') or '',
    }



def extract_tdc_seed_from_js(js_text: str) -> str:
    m = re.search(r'window\.TDC_NAME\s*=\s*"([^"]+)".*?window\.\1\s*=\s*\'([^\']+)\'', js_text, re.S)
    return m.group(2) if m else ""



def make_tdc_ft() -> str:
    alphabet = string.ascii_letters + string.digits + "_-"
    return "qf_" + "".join(random.choice(alphabet) for _ in range(6))



def make_tdc_profile(seed: str | int | None = None) -> dict[str, Any]:
    rng = random.Random(str(seed if seed is not None else time.time_ns()))
    width = rng.choice([1366, 1440, 1536, 1600, 1680, 1920, 2560])
    height = rng.choice([768, 900, 945, 960, 1080, 1200, 1440])
    inner_w = max(1024, width - rng.choice([0, 8, 16, 24]))
    inner_h = max(720, height - rng.choice([72, 88, 96, 120, 135]))
    return {
        'innerWidth': inner_w,
        'innerHeight': inner_h,
        'outerWidth': width + rng.choice([0, 8, 16]),
        'outerHeight': height + rng.choice([0, 8, 16, 32]),
        'hardwareConcurrency': rng.choice([4, 6, 8, 12, 16]),
        'deviceMemory': rng.choice([4, 8, 16]),
        'devicePixelRatio': rng.choice([1, 1.25, 1.5, 2]),
        'eventEvery': rng.choice([80, 96, 110, 120, 137, 160, 190]),
        'eventX': rng.randint(280, max(281, inner_w - 120)),
        'eventY': rng.randint(180, max(181, inner_h - 120)),
        'screen': {
            'width': width,
            'height': height,
            'availWidth': width,
            'availHeight': max(600, height - rng.choice([40, 48, 72])),
            'colorDepth': 24,
            'pixelDepth': 24,
        },
    }



def ensure_jsdom_node_path() -> str:
    """Return a NODE_PATH containing jsdom when available, installing to user cache if needed."""
    candidates = [
        Path.home() / ".local" / "share" / "matrix-ai-cli" / "node_modules",
        Path("/tmp/matrix-jsdom/node_modules"),
    ]
    for base in candidates:
        if (base / "jsdom").exists():
            return str(base)
    cache = candidates[0].parent
    cache.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["npm", "install", "--silent", "--prefix", str(cache), "jsdom@24"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except Exception:
        pass
    if (candidates[0] / "jsdom").exists():
        return str(candidates[0])
    return ""



def compute_tdc_with_node(
    tdc_js: str,
    *,
    timeout: float = 12.0,
    wait_ms: int = 0,
    seq: list[dict[str, Any]] | None = None,
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    runner = Path(__file__).with_name('tdc_node_runner.js')
    if not runner.exists():
        return {'ok': False, 'error': f'missing runner: {runner}'}
    with tempfile.NamedTemporaryFile('w', suffix='.js', delete=False, encoding='utf-8') as fh:
        fh.write(tdc_js)
        js_path = fh.name
    env = os.environ.copy()
    node_path = ensure_jsdom_node_path()
    if node_path:
        env['NODE_PATH'] = node_path + (os.pathsep + env['NODE_PATH'] if env.get('NODE_PATH') else '')
    env_cfg = {
        'waitMs': wait_ms,
        'seq': seq if seq is not None else [{'ft': make_tdc_ft()}, {'isNewEntry': 1}],
        'innerWidth': 1920,
        'innerHeight': 945,
        'outerWidth': 1936,
        'outerHeight': 1048,
        'hardwareConcurrency': 16,
        'devicePixelRatio': 1,
        'plugins': 'full',
        'url': 'https://captcha.gtimg.com/static/template/drag_ele.86303081.html',
        'referrer': 'https://matrix.tencent.com/',
        'eventEvery': 120,
    }
    if profile:
        env_cfg.update(profile)
    env['TDC_ENV_CFG'] = json.dumps(env_cfg, separators=(',', ':'))
    try:
        proc = subprocess.run(
            ['node', str(runner), js_path],
            capture_output=True,
            text=True,
            timeout=max(timeout, wait_ms / 1000.0 + 8.0),
            env=env,
        )
    except Exception as exc:
        Path(js_path).unlink(missing_ok=True)
        return {'ok': False, 'error': str(exc)}
    finally:
        try:
            Path(js_path).unlink(missing_ok=True)
        except Exception:
            pass
    try:
        line = proc.stdout.strip().splitlines()[-1]
        obj = json.loads(line)
    except Exception as exc:
        return {'ok': False, 'error': f'node-output-parse: {exc}', 'stdout_tail': proc.stdout[-1000:], 'stderr_tail': proc.stderr[-1000:], 'returncode': proc.returncode}
    if obj.get('err') or obj.get('error'):
        return {'ok': False, 'error': obj.get('err') or obj.get('error'), 'stdout_tail': proc.stdout[-1000:], 'stderr_tail': proc.stderr[-1000:], 'returncode': proc.returncode}
    info = obj.get('info') or {}
    data = obj.get('data') or ''
    collect = urllib.parse.unquote(data)
    return {
        'ok': bool(info.get('info') and data),
        'returncode': proc.returncode,
        'stderr_tail': proc.stderr[-500:],
        'collect': collect,
        'collect_encoded': data,
        'eks': info.get('info') or '',
        'tokenid': info.get('tokenid'),
        'data_len_encoded': len(data),
        'data_len_decoded': len(collect),
        'tdc_runtime': obj.get('runtime'),
        'tdc_wait_ms': wait_ms,
        'tdc_seq': env_cfg['seq'],
        'tdc_profile': {k: env_cfg.get(k) for k in ['innerWidth', 'innerHeight', 'outerWidth', 'outerHeight', 'hardwareConcurrency', 'deviceMemory', 'devicePixelRatio', 'eventEvery', 'eventX', 'eventY', 'screen'] if k in env_cfg},
    }



def get_dynamic_tdc_payload(
    prehandle: dict[str, Any],
    *,
    timeout: float = 20.0,
    ua: str = CAPTCHA_UA,
    wait_ms: int = 0,
    seq: list[dict[str, Any]] | None = None,
    xff: str = "",
    egress_proxy: str = "",
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    ph = prehandle.get('response') or prehandle
    cfg = ((ph.get('data') or {}).get('comm_captcha_cfg') or {})
    tdc_path = cfg.get('tdc_path') or ''
    if not tdc_path:
        return {'ok': False, 'error': 'missing-tdc-path'}
    headers = {
        'User-Agent': ua,
        'Referer': CAPTCHA_IFRAME_REFERER,
        'Accept': '*/*',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Sec-Fetch-Dest': 'script',
        'Sec-Fetch-Mode': 'no-cors',
        'Sec-Fetch-Site': 'cross-site',
        'Sec-Fetch-Storage-Access': 'active',
        'sec-ch-ua': '"Not/A)Brand";v="99", "Chromium";v="148"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    if xff:
        headers['X-Forwarded-For'] = xff
    r = captcha_http_get(
        CAPTCHA_API_BASE + tdc_path,
        headers=headers,
        timeout=timeout,
        egress_proxy=egress_proxy,
    )
    seed_eks = extract_tdc_seed_from_js(r.text)
    computed = compute_tdc_with_node(r.text, timeout=min(max(timeout, 8.0), 24.0), wait_ms=wait_ms, seq=seq, profile=profile)
    if not computed.get('eks') and seed_eks:
        computed['eks'] = seed_eks
    computed.update({
        'tdc_url': r.url,
        'tdc_status_code': r.status_code,
        'tdc_js_len': len(r.text),
        'tdc_xff': xff,
        'tdc_egress_proxy': egress_proxy,
        'seed_eks_len': len(seed_eks),
        'seed_eks_sha256': hashlib.sha256(seed_eks.encode()).hexdigest() if seed_eks else '',
    })
    return computed




def captcha_verify_http_post(
    body: dict[str, str],
    *,
    ua: str = CAPTCHA_UA,
    timeout: float = 20.0,
    xff: str = "",
    egress_proxy: str = "",
):
    headers = {
        'User-Agent': ua,
        'Referer': CAPTCHA_IFRAME_REFERER,
        'Origin': 'https://captcha.gtimg.com',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'cross-site',
        'sec-ch-ua': '"Not/A)Brand";v="99", "Chromium";v="148"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
    }
    if xff:
        headers['X-Forwarded-For'] = xff
    if curl_requests is not None:
        try:
            return curl_requests.post(
                CAPTCHA_API_BASE + '/cap_union_new_verify',
                data=body,
                headers=headers,
                impersonate=CAPTCHA_CURL_IMPERSONATE,
                proxies=request_proxies(egress_proxy),
                timeout=timeout,
            )
        except Exception:
            pass
    session = requests.Session()
    if egress_proxy:
        session.trust_env = False
    return session.post(
        CAPTCHA_API_BASE + '/cap_union_new_verify',
        data=body,
        headers=headers,
        proxies=request_proxies(egress_proxy),
        timeout=timeout,
    )


def captcha_verify_static_tdc(
    prehandle: dict[str, Any],
    *,
    timeout: float = 20.0,
    ua: str = CAPTCHA_UA,
    include_request_body: bool = False,
    wait_ms: int = 0,
    seq: list[dict[str, Any]] | None = None,
    xff: str = "",
    egress_proxy: str = "",
    profile: dict[str, Any] | None = None,
    require_dynamic_tdc: bool = True,
) -> dict[str, Any]:
    ph = prehandle.get('response') or prehandle
    sess = ph.get('sess') or ''
    cfg = ((ph.get('data') or {}).get('comm_captcha_cfg') or {})
    pow_cfg = cfg.get('pow_cfg') or {}
    pow_result = solve_md5_pow(pow_cfg.get('prefix', ''), pow_cfg.get('md5', ''))
    tpl = TENCENTCAPTCHA_STATIC_TDC_TEMPLATE
    dynamic_tdc = get_dynamic_tdc_payload(prehandle, timeout=timeout, ua=ua, wait_ms=wait_ms, seq=seq, xff=xff, egress_proxy=egress_proxy, profile=profile)
    dynamic_ok = bool(dynamic_tdc.get('ok') and dynamic_tdc.get('collect') and dynamic_tdc.get('eks'))
    if require_dynamic_tdc and not dynamic_ok:
        request_summary = {
            'sess_len': len(sess),
            'collect_len': 0,
            'collect_sha256': '',
            'eks_len': 0,
            'eks_sha256': '',
            'ans': tpl.get('ans') or '[{"elem_id":0,"type":"DynAnswerType_TIME","data":""}]',
            'pow_answer_len': 0,
            'pow_calc_time': None,
            'xff': xff,
            'egress_proxy': egress_proxy,
            'dynamic_tdc_required': True,
        }
        return {
            'ok': False,
            'status_code': None,
            'request_summary': request_summary,
            'response': {'errorCode': 'DYNAMIC_TDC_FAILED', 'errMessage': dynamic_tdc.get('error') or 'dynamic tdc unavailable'},
            'pow': pow_result,
            'tdc_template': tdc_template_summary(),
            'dynamic_tdc': {k: v for k, v in dynamic_tdc.items() if k not in {'collect', 'collect_encoded', 'eks'}},
            'text_prefix': '',
            'rejected_before_verify': True,
        }
    collect = dynamic_tdc.get('collect') or tpl.get('collect') or ''
    eks = dynamic_tdc.get('eks') or tpl.get('eks') or ''
    ans = tpl.get('ans') or '[{"elem_id":0,"type":"DynAnswerType_TIME","data":""}]'
    body = {
        'collect': collect,
        'tlg': str(len(collect)),
        'eks': eks,
        'sess': sess,
        'ans': ans,
    }
    if pow_result.get('ok'):
        body['pow_answer'] = str(pow_cfg.get('prefix', '')) + str(pow_result.get('answer'))
        body['pow_calc_time'] = str(max(1, int(float(pow_result.get('elapsed_sec') or 0) * 1000)))
    r = captcha_verify_http_post(body, ua=ua, timeout=timeout, xff=xff, egress_proxy=egress_proxy)
    try:
        parsed = r.json()
    except Exception:
        parsed = {'raw': r.text[:1000]}
    request_summary = {
        'sess_len': len(sess),
        'collect_len': len(collect),
        'collect_sha256': hashlib.sha256(collect.encode()).hexdigest(),
        'eks_len': len(eks),
        'eks_sha256': hashlib.sha256(eks.encode()).hexdigest(),
        'ans': ans,
        'pow_answer_len': len(body.get('pow_answer', '')),
        'pow_calc_time': body.get('pow_calc_time'),
        'xff': xff,
        'egress_proxy': egress_proxy,
    }
    out = {
        'ok': bool(parsed.get('ticket') and parsed.get('randstr')),
        'status_code': r.status_code,
        'request_summary': request_summary,
        'response': parsed,
        'pow': pow_result,
        'tdc_template': tdc_template_summary(),
        'dynamic_tdc': {k: v for k, v in dynamic_tdc.items() if k not in {'collect', 'collect_encoded', 'eks'}},
        'text_prefix': r.text[:1200],
    }
    if include_request_body:
        out['request'] = body
    return out



def captcha_ticket_pure(
    *,
    timeout: float = 20.0,
    wait_ms: int = 0,
    seq: list[dict[str, Any]] | None = None,
    entry_url: str = CAPTCHA_ENTRY_URL,
    xff: str = "",
    egress_proxy: str = "",
    profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pre = captcha_prehandle(timeout=timeout, entry_url=entry_url, xff=xff, egress_proxy=egress_proxy)
    verify = captcha_verify_static_tdc(pre, timeout=timeout, wait_ms=wait_ms, seq=seq, xff=xff, egress_proxy=egress_proxy, profile=profile, require_dynamic_tdc=True) if (pre.get('response') or {}).get('sess') else None
    pre_resp = pre.get('response') or {}
    verify_resp = (verify or {}).get('response') or {}
    payload = {}
    if verify_resp.get('ticket') and verify_resp.get('randstr'):
        payload = {'ticket': verify_resp.get('ticket'), 'randstr': verify_resp.get('randstr')}
    return {
        'status': 'captured' if payload else 'failed',
        'protocol_mode': 'pure',
        'provider': 'tencent-captcha-static-tdc-pow',
        'appid': CAPTCHA_APPID,
        'entry_url': entry_url,
        'xff': xff,
        'egress_proxy': egress_proxy,
        'tdc_profile': profile or {},
        'payload': payload,
        'prehandle_summary': {
            'state': pre_resp.get('state'),
            'sid': pre_resp.get('sid'),
            'sess_len': len(pre_resp.get('sess') or ''),
            'src_1': pre_resp.get('src_1'),
            'subcapclass': pre_resp.get('subcapclass'),
            'tdc_required': bool(((pre_resp.get('data') or {}).get('comm_captcha_cfg') or {}).get('tdc_path')),
            'pow_required': bool(((pre_resp.get('data') or {}).get('comm_captcha_cfg') or {}).get('pow_cfg')),
            'xff': ((pre.get('request') or {}).get('xff') or ''),
            'egress_proxy': ((pre.get('request') or {}).get('egress_proxy') or ''),
        },
        'verify_summary': {
            'ok': bool((verify or {}).get('ok')),
            'status_code': (verify or {}).get('status_code'),
            'wait_ms': wait_ms,
            'seq': seq,
            'errorCode': verify_resp.get('errorCode'),
            'errMessage': verify_resp.get('errMessage'),
            'request_summary': (verify or {}).get('request_summary'),
            'pow': (verify or {}).get('pow'),
            'tdc_template': (verify or {}).get('tdc_template'),
            'dynamic_tdc': (verify or {}).get('dynamic_tdc'),
        },
    }



def extract_first_captcha_code(report: dict[str, Any]) -> dict[str, Any]:
    result = report.get('result') or {}
    if isinstance(result, dict) and result.get('code'):
        return result
    for item in report.get('logs') or []:
        msg = item.get('recv') or {}
        if msg.get('code'):
            return msg
    for item in report.get('proxy_events') or []:
        preview = item.get('preview') or ''
        if '"code"' in preview and '"evil_level"' in preview:
            try:
                parsed = json.loads(preview)
                if parsed.get('code'):
                    return parsed
            except Exception:
                pass
    return {}





