"""Browser state management: bound sessions, fp refresh, ticket capture."""
from __future__ import annotations

import contextlib
import json
import time
from typing import Any

from .config import (
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    MATRIX_PIC_URL,
    MATRIX_TXT_URL,
)
from .transport import (
    agent_browser_action,
    agent_browser_close_tab,
    agent_browser_eval,
    agent_browser_execute_js,
    agent_browser_open_new_tab,
    ensure_browser_bridge,
    make_fp,
    wait_browser_session_ready,
)


def cdp_media_state_js(*, click_media_tab: bool = True) -> str:
    return """
(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  function slimData(d) {
    if (!d) return null;
    const o = {};
    for (const k of ['status','code','evil_level','msg','msg_en','availableUses','ai_generated','img_type','uuid','remaining','mllm_message','data_type','model_type','model_type_en','feedback_token']) {
      if (d[k] !== undefined) o[k] = d[k];
    }
    return o;
  }
  function findPic() {
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const v = el && el.__vue__;
      if (v && v.aiGenPicRemainingCount !== undefined && typeof v.submit === 'function' && typeof v.sendData === 'function') return v;
    }
    return null;
  }
  function findLeft() {
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const v = el && el.__vue__;
      if (v && v.form && Object.prototype.hasOwnProperty.call(v.form, 'base64') && typeof v.onSubmit === 'function') return v;
    }
    return null;
  }
  function clickMediaTab() {
    const nodes = Array.from(document.querySelectorAll('button,li,a,span,div'));
    const classHint = (el) => String(el.className || '');
    const textHint = (el) => String(el.innerText || el.textContent || '').trim();
    const rank = (el) => {
      const text = textHint(el);
      const cls = classHint(el);
      if (el.tagName === 'BUTTON' && text === '图片/视频') return 0;
      if (el.tagName === 'BUTTON' && text.includes('图片/视频')) return 1;
      if (/ai-button/.test(cls) && text.includes('图片/视频')) return 2;
      if (el.tagName === 'SPAN' && text === '图片/视频') return 3;
      if (text === 'AI生成检测-图像') return 4;
      if ((/图片检测|图像检测/.test(text) || text.includes('图像/视频')) && !/文本/.test(text)) return 5;
      return 99;
    };
    const candidates = nodes.filter((el) => rank(el) < 99).sort((a, b) => rank(a) - rank(b));
    for (const el of candidates) {
      const text = String(el.innerText || el.textContent || '').trim();
      try {
        el.click();
        return {clicked:true, tag:el.tagName, className:String(el.className || ''), text:text.slice(0,80), rank:rank(el)};
      } catch (e) {
        return {clicked:false, error:String(e && e.stack || e), tag:el.tagName, text:text.slice(0,80), rank:rank(el)};
      }
    }
    return {clicked:false, error:'media-tab-not-found'};
  }
  let mediaTab = null;
  if (__CLICK_MEDIA_TAB__) mediaTab = clickMediaTab();
  let pic = null;
  let left = null;
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    pic = findPic();
    left = findLeft();
    if (pic && left) break;
    await sleep(250);
  }
  const fp = localStorage.getItem('fp');
  return {
    ok: !!(pic && left && fp),
    href: location.href,
    title: document.title,
    ready: document.readyState,
    fp,
    picFound: !!pic,
    leftFound: !!left,
    remaining: pic ? pic.aiGenPicRemainingCount : null,
    wsReady: pic && pic.websock ? pic.websock.readyState : null,
    data: pic ? slimData(pic.data) : null,
    mediaTab,
    vueCount: Array.from(document.querySelectorAll('*')).filter(e => e.__vue__).length,
  };
})()
""".replace("__CLICK_MEDIA_TAB__", "true" if click_media_tab else "false")




def matrix_media_bound_state(*, bound: str = "", session_id: str = "", timeout: float = 20.0, click_media_tab: bool = True) -> dict[str, Any]:
    try:
        value = agent_browser_execute_js(
            bound=bound or DEFAULT_MEDIA_BOUND,
            session_id=session_id,
            script=cdp_media_state_js(click_media_tab=click_media_tab),
            timeout=max(10.0, timeout),
        )
        return value if isinstance(value, dict) else {"ok": False, "error": f"unexpected state result: {type(value).__name__}", "raw": value}
    except (Exception, SystemExit) as exc:
        return {"ok": False, "error": str(exc)}




def matrix_media_reset_browser_fp(*, bound: str = "", session_id: str = "", timeout: float = 20.0) -> dict[str, Any]:
    script = """
(() => {
  const before = localStorage.getItem('fp');
  localStorage.removeItem('fp');
  try { sessionStorage.removeItem('fp'); } catch (_) {}
  setTimeout(() => location.reload(), 50);
  return {reset:true,before,href:location.href};
})()
"""
    value = agent_browser_execute_js(
        bound=bound or DEFAULT_MEDIA_BOUND,
        session_id=session_id,
        script=script,
        timeout=max(10.0, timeout),
    )
    return value if isinstance(value, dict) else {"reset": True, "raw": value}




def matrix_media_reopen_bound(*, bound: str, timeout: float = 90.0) -> dict[str, Any]:
    sid = agent_browser_open_new_tab(MATRIX_PIC_URL, timeout=max(30.0, min(max(timeout, 10.0), 120.0)))
    return {"session_id": sid, "bound": bound, "url": MATRIX_PIC_URL, "binding": "session-id"}




def ensure_matrix_media_bound(
    *,
    bound: str = "",
    session_id: str = "",
    timeout: float = 90.0,
    force_new: bool = False,
    reset_fp: bool = False,
    auto_refresh_fp: bool = False,
    refresh_threshold: int = 1,
) -> dict[str, Any]:
    bound = bound or DEFAULT_MEDIA_BOUND
    started = time.time()
    ensure_browser_bridge(timeout=max(60.0, min(max(timeout, 10.0), 120.0)))
    last: dict[str, Any] = {}
    if not force_new:
        last = matrix_media_bound_state(bound=bound, session_id=session_id, timeout=min(20.0, max(10.0, timeout)), click_media_tab=True)
        remaining = last.get("remaining")
        try:
            remaining_int = int(remaining) if remaining is not None else None
        except Exception:
            remaining_int = None
        should_refresh = bool(auto_refresh_fp and last.get("ok") and remaining_int is not None and remaining_int <= max(0, int(refresh_threshold)))
        if reset_fp or should_refresh:
            reset_meta = matrix_media_reopen_bound(bound=bound, timeout=timeout) if should_refresh and not reset_fp and not session_id else matrix_media_reset_browser_fp(bound=bound, session_id=session_id, timeout=20.0)
            source_label = "new-tab-auto-refresh" if reset_meta.get("session_id") and not reset_fp else ("fp-reset" if reset_fp else "fp-auto-refresh")
            deadline = time.time() + max(20.0, timeout)
            refreshed: dict[str, Any] = {}
            while time.time() < deadline:
                refresh_session_id = str(reset_meta.get("session_id") or session_id or "")
                refreshed = matrix_media_bound_state(bound=bound, session_id=refresh_session_id, timeout=15.0, click_media_tab=True)
                if refreshed.get("ok") and (reset_meta.get("session_id") or not reset_meta.get("before") or refreshed.get("fp") != reset_meta.get("before")):
                    return {
                        "ok": True,
                        "bound": bound,
                        "session_id": refresh_session_id,
                        "source": source_label,
                        "elapsed_sec": round(time.time() - started, 4),
                        "reset": reset_meta,
                        "previous_state": last,
                        "state": refreshed,
                    }
                time.sleep(0.75)
            if last.get("ok"):
                with contextlib.suppress(Exception):
                    before = str(reset_meta.get("before") or "")
                    if before:
                        before_json = json.dumps(before)
                        restore_script = "(()=>{localStorage.setItem('fp',__FP__); setTimeout(()=>location.reload(),50); return {restored:true,fp:__FP__};})()".replace("__FP__", before_json)
                        agent_browser_execute_js(bound=bound, session_id=session_id, script=restore_script, timeout=15.0)
                        time.sleep(1.0)
                return {
                    "ok": True,
                    "bound": bound,
                    "session_id": session_id,
                    "source": "existing-bound-or-session-refresh-failed-restored",
                    "elapsed_sec": round(time.time() - started, 4),
                    "reset": reset_meta,
                    "refresh_error": "new fp not ready before timeout",
                    "state": last,
                }
            last = {"ok": False, "error": "fp refresh failed", "reset": reset_meta, "last": refreshed}
        if last.get("ok"):
            return {
                "ok": True,
                "bound": bound,
                "session_id": session_id,
                "source": "existing-bound-or-session",
                "elapsed_sec": round(time.time() - started, 4),
                "state": last,
            }
    opened_session = session_id or agent_browser_open_new_tab(MATRIX_PIC_URL, timeout=max(30.0, min(max(timeout, 10.0), 120.0)))
    deadline = time.time() + max(15.0, timeout)
    while time.time() < deadline:
        last = matrix_media_bound_state(bound=bound, session_id=session_id or opened_session, timeout=15.0, click_media_tab=True)
        if last.get("ok"):
            return {
                "ok": True,
                "bound": bound,
                "session_id": session_id or opened_session,
                "source": "new-tab" if not session_id else "session",
                "elapsed_sec": round(time.time() - started, 4),
                "state": last,
            }
        time.sleep(0.75)
    raise SystemExit(f"cdp media env not ready: bound={bound} session_id={session_id or opened_session} last={last}")




def browser_txt_state(*, bound: str = "", session_id: str = "", timeout: float = 10.0) -> dict[str, Any]:
    expr = r"""(() => {
  const findTxt = () => {
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const v = el && el.__vue__;
      if (v && typeof v.submit === 'function' && v.captcha && typeof v.callback === 'function') return v;
    }
    return null;
  };
  const txt = findTxt();
  return {
    href: location.href,
    title: document.title,
    fp: localStorage.getItem('fp'),
    txtFound: !!txt,
    remaining: txt ? txt.aiGenTxtRemainingCount : null,
    wsConnected: txt ? txt.wsConnected : null,
    processing: txt ? txt.processing : null,
    data: txt ? txt.data : null
  };
})()"""
    result = agent_browser_eval(bound=bound, session_id=session_id, expr=expr, timeout=timeout)
    if not isinstance(result, dict):
        raise SystemExit(f'failed to read browser state: {result}')
    return result




def refresh_browser_fp(*, bound: str = "", session_id: str = "", timeout: float = 30.0) -> dict[str, Any]:
    from .text_detect import handshake_only

    agent_browser_execute_js(
        bound=bound,
        session_id=session_id,
        script="""
(() => {
  try { localStorage.removeItem('fp'); } catch (_e) {}
  try { localStorage.removeItem('aiGenAccessToken'); } catch (_e) {}
  try { setTimeout(() => location.reload(), 50); } catch (_e) {}
  return { status: 'cleared-fp', href: location.href };
})()
""",
        timeout=min(timeout, 10.0),
    )
    deadline = time.time() + timeout
    last_state: dict[str, Any] | None = None
    while time.time() < deadline:
        state = browser_txt_state(bound=bound, session_id=session_id, timeout=10.0)
        last_state = state
        fp = state.get('fp')
        if fp:
            probe = handshake_only(fp)
            first = probe.get('first') or {}
            if first.get('status') == 'success' and int(first.get('availableUses', 0)) > 0:
                state['probe'] = probe
                return state
        time.sleep(1.0)
    raise SystemExit(f'refresh_browser_fp failed: {last_state}')




def ensure_usable_browser_fp(
    *,
    bound: str = "",
    session_id: str = "",
    current_fp: str | None,
    timeout: float = 30.0,
    max_tries: int = 20,
) -> dict[str, Any]:
    from .text_detect import handshake_only, pick_fp

    fp = current_fp or ''
    current_probe = None
    if fp:
        probe = handshake_only(fp)
        current_probe = probe
        first = probe.get('first') or {}
        current_uses = int(first.get('availableUses', 0)) if first.get('status') == 'success' else 0
    else:
        current_uses = 0
    picked = pick_fp(max_tries=max_tries, preferred_fps=[fp] if fp else [], bound=bound, session_id=session_id)
    if picked.get('picked_fp'):
        picked_uses = int((picked.get('probe') or {}).get('first', {}).get('availableUses', 0))
        if current_probe and current_uses >= picked_uses and current_uses > 0:
            return {'fp': fp, 'probe': current_probe, 'source': 'current-browser-fp'}
        return {
            'fp': picked['picked_fp'],
            'probe': picked.get('probe'),
            'source': 'candidate-pool',
            'candidate': picked.get('candidate'),
        }
    refreshed = refresh_browser_fp(bound=bound, session_id=session_id, timeout=timeout)
    refreshed_fp = refreshed.get('fp') or ''
    if refreshed_fp:
        probe = handshake_only(refreshed_fp)
        first = probe.get('first') or {}
        if first.get('status') == 'success' and int(first.get('availableUses', 0)) > 0:
            return {'fp': refreshed_fp, 'browser': refreshed, 'probe': probe, 'source': 'refreshed-browser-fp'}
    raise SystemExit(f'failed to find usable fp: current={current_fp}, refreshed={refreshed_fp}')




def capture_ticket_auto(*, text: str, bound: str = "", session_id: str = "", fp: str | None, timeout: float = 60.0) -> dict[str, Any]:
    if fp:
        prepare_browser_fp(bound=bound, session_id=session_id, fp=fp, timeout=min(timeout, 15.0))
    script = f"""
(() => {{
  const findTxt = () => {{
    for (const el of Array.from(document.querySelectorAll('*'))) {{
      const v = el && el.__vue__;
      if (v && typeof v.submit === 'function' && v.captcha && typeof v.callback === 'function') return v;
    }}
    return null;
  }};
  const txt = findTxt();
  if (!txt) return {{ error: 'txt-component-not-found' }};
  const text = {json.dumps(text)};
  const state = {{
    status: 'installed',
    installedAt: Date.now(),
    fp: localStorage.getItem('fp'),
    href: location.href,
    title: document.title,
    remaining: txt.aiGenTxtRemainingCount,
    textLen: text.length,
    logs: []
  }};
  const restore = [];
  window.__matrixCliCapture = state;

  if (txt.websock && typeof txt.websock.send === 'function') {{
    const oldSend = txt.websock.send.bind(txt.websock);
    restore.push(() => {{ try {{ txt.websock.send = oldSend; }} catch (_e) {{}} }});
    txt.websock.send = function(data) {{
      let parsed = null;
      try {{ parsed = typeof data === 'string' ? JSON.parse(data) : null; }} catch (_e) {{}}
      state.logs.push({{ kind: 'websock.send', data: parsed || String(data).slice(0, 200), ts: Date.now() }});
      if (parsed && parsed.ticket && parsed.randstr) {{
        state.status = 'captured';
        state.payload = {{ ticket: parsed.ticket, randstr: parsed.randstr }};
        state.capturedAt = Date.now();
        state.remaining = txt.aiGenTxtRemainingCount;
        try {{ txt.processing = false; }} catch (_e) {{}}
        return;
      }}
      return oldSend(data);
    }};
  }}

  if (txt.captcha && txt.captcha.options && typeof txt.captcha.options.callback === 'function') {{
    const oldOptCb = txt.captcha.options.callback;
    restore.push(() => {{ try {{ txt.captcha.options.callback = oldOptCb; }} catch (_e) {{}} }});
    txt.captcha.options.callback = function(payload) {{
      state.logs.push({{ kind: 'captcha.options.callback', payload, ts: Date.now() }});
      if (payload && payload.ticket && payload.randstr) {{
        state.status = 'captured';
        state.payload = {{ ticket: payload.ticket, randstr: payload.randstr }};
        state.capturedAt = Date.now();
        state.remaining = txt.aiGenTxtRemainingCount;
        try {{ txt.processing = false; }} catch (_e) {{}}
        return undefined;
      }}
      return oldOptCb.apply(this, arguments);
    }};
  }}

  if (txt.captcha && txt.captcha.initOpts && typeof txt.captcha.initOpts.callback === 'function') {{
    const oldInitCb = txt.captcha.initOpts.callback;
    restore.push(() => {{ try {{ txt.captcha.initOpts.callback = oldInitCb; }} catch (_e) {{}} }});
    txt.captcha.initOpts.callback = function(payload) {{
      state.logs.push({{ kind: 'captcha.initOpts.callback', payload, ts: Date.now() }});
      if (payload && payload.ticket && payload.randstr) {{
        state.status = 'captured';
        state.payload = {{ ticket: payload.ticket, randstr: payload.randstr }};
        state.capturedAt = Date.now();
        state.remaining = txt.aiGenTxtRemainingCount;
        try {{ txt.processing = false; }} catch (_e) {{}}
        return undefined;
      }}
      return oldInitCb.apply(this, arguments);
    }};
  }}

  state.restore = () => {{
    for (const fn of restore.splice(0)) {{
      try {{ fn(); }} catch (_e) {{}}
    }}
    const txt2 = findTxt();
    if (txt2) {{
      try {{ txt2.processing = false; }} catch (_e) {{}}
    }}
    state.restoredAt = Date.now();
    return true;
  }};

  txt.text = text;
  txt.submit();
  state.status = 'submitted';
  state.afterSubmitRemaining = txt.aiGenTxtRemainingCount;
  state.processing = txt.processing;
  return {{
    status: 'installed',
    fp: state.fp,
    remaining: state.remaining,
    textLen: text.length,
    note: 'poll window.__matrixCliCapture for result'
  }};
}})()
"""
    install = agent_browser_execute_js(bound=bound, session_id=session_id, script=script, timeout=min(timeout, 20.0))
    if isinstance(install, dict) and install.get('error'):
        raise SystemExit(f'capture hook install failed: {install}')
    deadline = time.time() + timeout
    last_state: dict[str, Any] | None = None
    while time.time() < deadline:
        state = agent_browser_eval(bound=bound, session_id=session_id, expr='(()=>window.__matrixCliCapture || null)()', timeout=10.0)
        if isinstance(state, dict):
            last_state = state
            if state.get('status') == 'captured' and isinstance(state.get('payload'), dict):
                agent_browser_eval(
                    bound=bound,
                    session_id=session_id,
                    expr='(()=>window.__matrixCliCapture && window.__matrixCliCapture.restore ? window.__matrixCliCapture.restore() : null)()',
                    timeout=10.0,
                )
                return state
            if state.get('status') == 'failed':
                break
            if state.get('status') == 'submitted':
                page_state = browser_txt_state(bound=bound, session_id=session_id, timeout=10.0)
                page_data = page_state.get('data')
                if isinstance(page_data, dict) and page_data.get('status') == 'failed':
                    state['status'] = 'failed'
                    state['page_data'] = page_data
                    last_state = state
                    break
        time.sleep(1.0)
    agent_browser_eval(
        bound=bound,
        session_id=session_id,
        expr='(()=>window.__matrixCliCapture && window.__matrixCliCapture.restore ? window.__matrixCliCapture.restore() : null)()',
        timeout=10.0,
    )
    raise SystemExit(f'auto capture ticket failed or timed out: {last_state}')




def browser_target_health(*, bound: str = "", session_id: str = "", timeout: float = 10.0) -> dict[str, Any]:
    return browser_txt_state(bound=bound, session_id=session_id, timeout=timeout)




def ensure_browser_target(*, bound: str = "", session_id: str = "", timeout: float = 30.0, force_new: bool = False) -> dict[str, Any]:
    if session_id:
        state = browser_target_health(session_id=session_id, timeout=timeout)
        return {'session_id': session_id, 'bound': '', 'temporary': False, 'state': state, 'source': 'session-id'}
    selected_bound = bound or DEFAULT_BOUND
    if not force_new:
        try:
            state = browser_target_health(bound=selected_bound, timeout=timeout)
            return {'session_id': '', 'bound': selected_bound, 'temporary': False, 'state': state, 'source': 'bound'}
        except BaseException:
            ensure_browser_bridge(timeout=max(timeout, 60.0))
            try:
                state = browser_target_health(bound=selected_bound, timeout=timeout)
                return {'session_id': '', 'bound': selected_bound, 'temporary': False, 'state': state, 'source': 'bound-after-bridge-up'}
            except BaseException:
                pass
    else:
        ensure_browser_bridge(timeout=max(timeout, 60.0))
    sid = agent_browser_open_new_tab(MATRIX_TXT_URL, timeout=timeout)
    deadline = time.time() + timeout
    last_error: BaseException | None = None
    while time.time() < deadline:
        try:
            state = browser_target_health(session_id=sid, timeout=timeout)
            return {'session_id': sid, 'bound': '', 'temporary': True, 'state': state, 'source': 'temp-tab-forced' if force_new else 'temp-tab'}
        except BaseException as exc:
            last_error = exc
            time.sleep(1.0)
    raise SystemExit(f'failed to prepare temporary matrix tab: {last_error}')




def prepare_browser_fp(*, bound: str = "", session_id: str = "", fp: str, timeout: float = 15.0) -> dict[str, Any]:
    script = f"""
(() => {{
  const findTxt = () => {{
    for (const el of Array.from(document.querySelectorAll('*'))) {{
      const v = el && el.__vue__;
      if (v && typeof v.submit === 'function' && v.captcha && typeof v.callback === 'function') return v;
    }}
    return null;
  }};
  const txt = findTxt();
  if (!txt) return {{ error: 'txt-component-not-found' }};
  localStorage.setItem('fp', {json.dumps(fp)});
  try {{ localStorage.removeItem('aiGenAccessToken'); }} catch (_e) {{}}
  try {{ if (txt.websock) txt.websock.close(); }} catch (_e) {{}}
  txt.wsConnected = false;
  txt.connecting = false;
  txt.init = false;
  txt.processing = false;
  txt.pendingMessage = null;
  return {{
    status: 'prepared',
    fp: localStorage.getItem('fp'),
    remaining: txt.aiGenTxtRemainingCount,
    wsConnected: txt.wsConnected
  }};
}})()
"""
    result = agent_browser_execute_js(bound=bound, session_id=session_id, script=script, timeout=timeout)
    if isinstance(result, dict) and result.get('error'):
        raise SystemExit(f'prepare_browser_fp failed: {result}')
    return result
