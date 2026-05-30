"""CDP-based media detection: browser JS injection and orchestration."""
from __future__ import annotations

import argparse
import base64
import contextlib
import json
import time
from pathlib import Path
from typing import Any

from .config import (
    DEFAULT_BOUND,
    DEFAULT_MEDIA_BOUND,
    DEFAULT_MEDIA_XFF,
    MATRIX_PIC_URL,
    PIC_WS_URL,
    VIDEO_CHUNK_SIZE,
)
from .transport import (
    BrowserCdpConnection,
    agent_browser_action,
    agent_browser_close_tab,
    agent_browser_execute_js,
    agent_browser_get_fp,
    agent_browser_open_new_tab,
    browser_cdp_eval,
    browser_cdp_get_fp,
    browser_cdp_wait_target_ready,
    browser_ws_endpoint,
    egress_meta,
    make_fp_for_mode,
    normalize_cdp_context_proxy_server,
    wait_browser_session_ready,
)
from .ws_proxy import MediaWsProxy
from .browser_state import ensure_matrix_media_bound
from .media_detect import (
    issue_media_ticket,
    upload_video_file,
)


def cdp_media_wait_js(
    *,
    media_type: str,
    fp: str,
    ws_url: str,
    image_b64: str = "",
    video_cos_url: str = "",
    timeout_ms: int = 90000,
    fp_source: str = "cli",
    ticket: str = "",
    randstr: str = "",
    auto_feedback: bool = False,
) -> str:
    if media_type not in {"image", "video"}:
        raise SystemExit(f"unsupported media_type: {media_type}")
    if media_type == "image" and not image_b64:
        raise SystemExit("missing image_b64")
    if media_type == "video" and not video_cos_url:
        raise SystemExit("missing video_cos_url")
    if fp_source not in {"cli", "browser"}:
        raise SystemExit(f"unsupported fp_source: {fp_source}")
    media_json = json.dumps(media_type)
    return """
(async () => {
  const sleep = (ms) => new Promise(r => setTimeout(r, ms));
  const state = {status:'starting', protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:__FP__, fpSource:__FP_SOURCE__, logs:[], snapshots:[], proxyUrl:__WS_URL__, startedAt:Date.now(), sentPayload:false, sentTicket:false};
  window.__matrixAiCliCdpMedia = state;
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
    const candidates = nodes
      .filter((el) => rank(el) < 99)
      .sort((a, b) => rank(a) - rank(b));
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
  function activeFp() {
    return (__FP_SOURCE__ === 'cli') ? state.fp : localStorage.getItem('fp');
  }
  async function waitActiveFp(previous) {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      const cur = localStorage.getItem('fp');
      if (cur && (!previous || cur !== previous)) return cur;
      await sleep(250);
    }
    return localStorage.getItem('fp');
  }
  function findFeedbackDetail() {
    const token = pic && pic.data ? pic.data.feedback_token : '';
    const uuid = pic && pic.data ? pic.data.uuid : '';
    const candidates = [];
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const v = el && el.__vue__;
      if (v && typeof v.submitFeedback === 'function') candidates.push(v);
    }
    const score = (v) => {
      if (token && v.feedbackToken === token) return 0;
      if (uuid && v.uuid === uuid) return 1;
      if (v.img || v.cos || v.txt) return 2;
      return 9;
    };
    candidates.sort((a, b) => score(a) - score(b));
    return candidates[0] || null;
  }
  async function tryAutoFeedback(finalSnap) {
    const before = pic ? pic.aiGenPicRemainingCount : null;
    const token = pic && pic.data ? pic.data.feedback_token : '';
    let detail = null;
    const detailDeadline = Date.now() + 5000;
    while (Date.now() < detailDeadline) {
      detail = findFeedbackDetail();
      if (detail) break;
      await sleep(250);
    }
    if (!detail) return {attempted:true, ok:false, reason:'detail-not-found', before, token: token || null};
    try {
      if (typeof detail.handleLike === 'function') {
        const likeRet = detail.handleLike(true);
        if (likeRet && typeof likeRet.then === 'function') await likeRet;
        await sleep(250);
      }
      try {
        detail.currentFeedbackStatus = true;
        detail.feedbackSubmitted = false;
        detail.feedbackOption = '1';
        if (!detail.feedbackForm) detail.feedbackForm = {};
        if (detail.userThinkHuman) {
          detail.feedbackForm.reason = detail.feedbackForm.reason || 'manual verification: model result is accurate';
        } else {
          detail.modelSelectValue = detail.modelSelectValue || 'other';
          detail.feedbackForm.modelName = detail.feedbackForm.modelName || 'unknown';
          detail.feedbackForm.promptInfo = detail.feedbackForm.promptInfo || 'manual verification: model result is accurate';
        }
      } catch (_) {}
      const ret = detail.submitFeedback(true, true);
      if (ret && typeof ret.then === 'function') await ret;
      await sleep(1800);
      const after = pic ? pic.aiGenPicRemainingCount : null;
      const added = (Number.isFinite(Number(after)) && Number.isFinite(Number(before))) ? Number(after) - Number(before) : null;
      return {
        attempted:true,
        ok: added !== null ? added > 0 : true,
        before,
        after,
        added,
        liked: !!detail.liked,
        disliked: !!detail.disliked,
        token: token || detail.feedbackToken || null,
        final: finalSnap ? {remaining: finalSnap.remaining, data: finalSnap.data} : null,
      };
    } catch (e) {
      return {attempted:true, ok:false, reason:'submitFeedback-error', error:String(e && e.stack || e), before, token: token || null};
    }
  }
  let pic = null;
  let left = null;
  const componentDeadline = Date.now() + 20000;
  while (Date.now() < componentDeadline) {
    pic = findPic();
    left = findLeft();
    if (pic && left) break;
    await sleep(250);
  }
  if (!pic || !left) {
    state.mediaTab = clickMediaTab();
    const switchedDeadline = Date.now() + 20000;
    while (Date.now() < switchedDeadline) {
      pic = findPic();
      left = findLeft();
      if (pic && left) break;
      await sleep(250);
    }
  }
  if (!pic || !left) return {status:'error', ok:false, error:'component-not-found', picFound:!!pic, leftFound:!!left, mediaTab:state.mediaTab || null};
  state.initial = {href: location.href, fp: localStorage.getItem('fp'), remaining: pic.aiGenPicRemainingCount, wsReady: pic.websock ? pic.websock.readyState : null, data: slimData(pic.data)};
  let reuseExistingWs = false;
  if (__FP_SOURCE__ === 'cli') {
    state.fp = __FP__;
  } else {
    state.fp = await waitActiveFp(__RESET_BEFORE_FP__);
    if (!state.fp) return {status:'error', ok:false, error:'browser-fp-missing', protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:null, initial:state.initial, logs:state.logs};
    reuseExistingWs = !!(pic.websock && pic.websock.readyState === WebSocket.OPEN && pic.data && pic.data.status === 'success' && pic.data.availableUses !== undefined && pic.data.ai_generated === undefined);
  }
  if (!reuseExistingWs) {
    try { if (pic.websock) pic.websock.close(); } catch (_) {}
    pic.websock = null; pic.pendingMessage = null; pic.processing = false; pic.data = {}; pic.aiGenerated = -1; pic.aiGenPicRemainingCount = -1;
    const ws = new WebSocket(__WS_URL__);
    pic.websock = ws;
    try { pic.$store.commit('setWs', ws); } catch (_) {}
    if (__FP_SOURCE__ === 'cli') {
      ws.onopen = function() {
        try {
          state.logs.push({kind:'ws.open.cli-fp', ts:Date.now(), fp:state.fp});
          ws.send(JSON.stringify({fp: state.fp}));
        } catch (e) {
          state.logs.push({kind:'ws.open.cli-fp.error', ts:Date.now(), error:String(e && e.stack || e)});
        }
      };
    } else {
      ws.onopen = pic.websocketOnopen.bind(pic);
    }
    ws.onerror = pic.websocketOnerror.bind(pic);
    ws.onmessage = pic.websocketOnmessage.bind(pic);
    ws.onclose = pic.websocketOnclose.bind(pic);
  } else {
    state.logs.push({kind:'ws.reuse', ts:Date.now(), fp:localStorage.getItem('fp'), readyState:pic.websock.readyState});
  }
  function patchWs() {
    try {
      if (pic.websock && !pic.websock.__matrixAiCliPatched) {
        const oldSend = pic.websock.send.bind(pic.websock);
        pic.websock.send = function(data) {
          let entry = {kind:'ws.send', ts:Date.now()};
          try {
            if (typeof data === 'string') {
              const parsed = JSON.parse(data);
              if (parsed.ticket) { parsed.ticket = '<ticket>'; state.sentTicket = true; }
              if (parsed.video_cos_url) state.sentPayload = true;
              entry.data = parsed;
            } else if (data instanceof Blob) { state.sentPayload = true; entry.blob = {size:data.size, type:data.type}; }
            else if (data instanceof ArrayBuffer) { state.sentPayload = true; entry.arrayBuffer = {byteLength:data.byteLength}; }
            else entry.other = Object.prototype.toString.call(data);
          } catch (e) { entry.raw = String(data).slice(0, 200); }
          state.logs.push(entry);
          return oldSend(data);
        };
        pic.websock.__matrixAiCliPatched = true;
        state.logs.push({kind:'ws.patch', ts:Date.now(), readyState:pic.websock.readyState});
      }
    } catch (e) { state.logs.push({kind:'ws.patch.error', error:String(e), ts:Date.now()}); }
  }
  if (!reuseExistingWs) {
    const hsDeadline = Date.now() + 18000;
    while (Date.now() < hsDeadline) {
      patchWs();
      if (pic.data && pic.data.status === 'success' && pic.data.availableUses !== undefined) break;
      if (pic.data && pic.data.status === 'failed') break;
      await sleep(250);
    }
  } else {
    patchWs();
  }
  state.handshake = {fp:activeFp(), data:slimData(pic.data), remaining:pic.aiGenPicRemainingCount, wsReady:pic.websock ? pic.websock.readyState : null, reused: reuseExistingWs};
  if (!(pic.data && pic.data.status === 'success')) {
    state.status = 'handshake-failed';
    return {status:'handshake-failed', ok:false, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, logs:state.logs};
  }
  if (__MANUAL_TICKET__ && __MANUAL_RANDSTR__) {
    try {
      patchWs();
      pic.websock.send(JSON.stringify({ticket: __MANUAL_TICKET__, randstr: __MANUAL_RANDSTR__}));
    } catch (e) {
      return {status:'ticket-send-error', ok:false, error:String(e && e.stack || e), protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, logs:state.logs};
    }
    const ticketDeadline = Date.now() + 12000;
    while (Date.now() < ticketDeadline) {
      patchWs();
      if (pic.data && pic.data.code) break;
      if (pic.data && pic.data.status === 'failed') break;
      await sleep(250);
    }
    state.ticket = {data: slimData(pic.data), remaining: pic.aiGenPicRemainingCount, wsReady: pic.websock ? pic.websock.readyState : null};
    if (!(pic.data && String(pic.data.code) === '1' && String(pic.data.evil_level) === '0')) {
      state.status = 'ticket-rejected';
      return {status:'ticket-rejected', ok:false, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket, logs:state.logs, snapshots:state.snapshots.slice(-20)};
    }
  }
  try {
    try {
      pic.data = {};
      pic.aiGenerated = -1;
      pic.processing = false;
      pic.showFeedback = false;
      pic.mllmMessage = undefined;
    } catch (_) {}
    if (__MEDIA_TYPE__ === 'video') {
      left.form.base64 = ''; left.form.imageUrl = ''; left.form.cos = __VIDEO_COS_URL__;
    } else {
      left.form.base64 = 'data:image/png;base64,__IMAGE_B64__'; left.form.imageUrl = ''; left.form.cos = '';
    }
    left.onSubmit();
  } catch (e) {
    return {status:'submit-error', ok:false, error:String(e && e.stack || e), protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:localStorage.getItem('fp'), initial:state.initial, handshake:state.handshake, logs:state.logs};
  }
  const deadline = Date.now() + __TIMEOUT_MS__;
  let last = null;
  while (Date.now() < deadline) {
    patchWs();
    const payloadSentNow = !!state.sentPayload;
    const snap = {ts:Date.now(), processing:pic.processing, remaining:pic.aiGenPicRemainingCount, aiGenerated:pic.aiGenerated, data:slimData(pic.data), wsReady:pic.websock ? pic.websock.readyState : null, logs:state.logs.length, sentPayload: payloadSentNow, sentTicket: !!state.sentTicket};
    last = snap;
    state.snapshots.push(snap);
    if (payloadSentNow && pic.data && pic.data.status === 'success' && pic.data.ai_generated !== undefined) {
      const feedback = __AUTO_FEEDBACK__ ? await tryAutoFeedback(snap) : null;
      state.feedback = feedback;
      return {status:'success', ok:true, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket || null, final:snap, feedback, result:slimData(pic.data), logs:state.logs, snapshots:state.snapshots.slice(-20)};
    }
    if (pic.data && (pic.data.status === 'failed' || pic.data.status === 'limited')) {
      return {status:'failed', ok:false, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket || null, final:snap, result:slimData(pic.data), logs:state.logs, snapshots:state.snapshots.slice(-20)};
    }
    if (pic.data && pic.data.code && !(String(pic.data.code) === '1' && String(pic.data.evil_level) === '0')) {
      return {status:'failed', ok:false, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket || null, final:snap, result:slimData(pic.data), logs:state.logs, snapshots:state.snapshots.slice(-20)};
    }
    await sleep(700);
  }
  if (!state.sentPayload) return {status:'payload-not-sent', ok:false, error:'no ticket/blob payload sent in current run', protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket || null, final:last, result:last ? last.data : null, logs:state.logs, snapshots:state.snapshots.slice(-20)};
  return {status:'timeout', ok:false, protocol_mode:'cdp', media_type:__MEDIA_TYPE__, fp:activeFp(), initial:state.initial, handshake:state.handshake, ticket:state.ticket || null, final:last, result:last ? last.data : null, logs:state.logs, snapshots:state.snapshots.slice(-20)};
})()
""".replace("__MEDIA_TYPE__", media_json).replace("__FP_SOURCE__", json.dumps(fp_source)).replace("__FP__", json.dumps(fp)).replace("__WS_URL__", json.dumps(ws_url)).replace("__VIDEO_COS_URL__", json.dumps(video_cos_url)).replace("__IMAGE_B64__", image_b64).replace("__TIMEOUT_MS__", str(int(timeout_ms))).replace("__MANUAL_TICKET__", json.dumps(ticket)).replace("__MANUAL_RANDSTR__", json.dumps(randstr)).replace("__AUTO_FEEDBACK__", "true" if auto_feedback else "false").replace("__RESET_BEFORE_FP__", json.dumps(fp if fp_source == "browser" else ""))




def normalize_cdp_media_result(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            with contextlib.suppress(Exception):
                parsed = json.loads(stripped)
                if isinstance(parsed, dict):
                    return parsed
        return {
            "status": "error",
            "ok": False,
            "error": stripped[:1000] or "empty cdp result string",
        }
    return {
        "status": "error",
        "ok": False,
        "error": f"unexpected cdp eval result: {type(value).__name__}",
    }




def cdp_media_report(args: argparse.Namespace, media_type: str) -> dict[str, Any]:
    setattr(args, "media_type", media_type)
    input_path = Path(args.image_file if media_type == "image" else args.video_file)
    if not input_path.exists():
        raise SystemExit(f"missing input file: {input_path}")
    cdp_fp_source = getattr(args, "cdp_fp_source", "cli") or "cli"
    if cdp_fp_source not in {"cli", "browser"}:
        raise SystemExit(f"unsupported cdp fp source: {cdp_fp_source}")
    fp = "" if cdp_fp_source == "browser" else make_fp_for_mode(getattr(args, "fp_mode", "fresh"), getattr(args, "fp", ""))
    if cdp_fp_source == "cli" and not fp:
        raise SystemExit("missing fp; use --fp-mode fresh or --fp")
    effective_xff = getattr(args, "xff", "") or (DEFAULT_MEDIA_XFF if getattr(args, "fp_mode", "fresh") == "fresh" else "")
    cdp_ws_mode = getattr(args, "cdp_ws_mode", "proxy") or "proxy"
    if cdp_ws_mode not in {"proxy", "direct"}:
        raise SystemExit(f"unsupported cdp ws mode: {cdp_ws_mode}")
    upload_meta: dict[str, Any] | None = None
    image_b64 = ""
    video_cos_url = ""
    if media_type == "image":
        image_bytes = input_path.read_bytes()
        if not image_bytes:
            raise SystemExit(f"empty image file: {input_path}")
        image_b64 = base64.b64encode(image_bytes).decode()
    else:
        upload_meta = upload_video_file(
            input_path,
            fp=fp,
            xff=effective_xff,
            timeout=getattr(args, "upload_timeout", getattr(args, "timeout", 90.0)),
            chunk_size=getattr(args, "chunk_size", VIDEO_CHUNK_SIZE),
        )
        video_cos_url = upload_meta.get("cosURL") or ""
    opened_session = ""
    target: dict[str, Any] = {}
    cdp_new_tab = bool(getattr(args, "cdp_new_tab", True))
    cdp_close_tab = bool(getattr(args, "cdp_close_tab", True))
    cdp_tab_wait_sec = float(getattr(args, "cdp_tab_wait_sec", 4.0) or 0.0)
    cdp_target_mode = getattr(args, "cdp_target_mode", "extension-tab") or "extension-tab"
    if cdp_target_mode not in {"extension-tab", "browser-context"}:
        raise SystemExit(f"unsupported cdp target mode: {cdp_target_mode}")
    cdp_reset_browser_fp = getattr(args, "cdp_reset_browser_fp", None)
    if cdp_reset_browser_fp is None:
        cdp_reset_browser_fp = cdp_fp_source == "browser" and getattr(args, "fp_mode", "fresh") == "fresh"
    wire_xff = effective_xff if cdp_ws_mode == "proxy" else ""
    ws_url = PIC_WS_URL
    proxy_events: list[dict[str, Any]] = [{"event": "direct-ws", "ws_url": ws_url}] if cdp_ws_mode == "direct" else []
    result: dict[str, Any] = {}
    env_meta: dict[str, Any] | None = None
    cdp_auto_env = bool(getattr(args, "cdp_auto_env", False))
    cdp_auto_feedback = bool(getattr(args, "cdp_auto_feedback", False))
    ticket = ""
    randstr = ""
    ticket_meta: dict[str, Any] | None = None
    if getattr(args, "ticket", None) or getattr(args, "randstr", None) or getattr(args, "ticket_json", None) or getattr(args, "ticket_command", ""):
        ticket, randstr, ticket_meta = issue_media_ticket(args, fp=fp or getattr(args, "fp", "") or "", iteration=1)

    def run_cdp_script(target_ws_url: str) -> dict[str, Any]:
        nonlocal opened_session, target, fp

        def build_script() -> str:
            return cdp_media_wait_js(
                media_type=media_type,
                fp=fp,
                ws_url=target_ws_url,
                image_b64=image_b64,
                video_cos_url=video_cos_url,
                timeout_ms=int(max(10.0, float(args.timeout)) * 1000),
                fp_source=cdp_fp_source,
                ticket=ticket,
                randstr=randstr,
                auto_feedback=cdp_auto_feedback,
            )

        if cdp_target_mode == "browser-context":
            ws_endpoint = browser_ws_endpoint(
                ws_endpoint=getattr(args, "cdp_browser_ws_endpoint", "") or "",
                version_url=getattr(args, "cdp_browser_version_url", "") or "",
                state_file=getattr(args, "cdp_browser_state_file", "") or "",
            )
            with BrowserCdpConnection(ws_endpoint, timeout=float(args.timeout) + 45.0) as conn:
                context_proxy_server = normalize_cdp_context_proxy_server(str(getattr(args, "cdp_context_proxy_server", "") or ""))
                ctx_params: dict[str, Any] = {}
                if context_proxy_server:
                    ctx_params["proxyServer"] = context_proxy_server
                    ctx_params["proxyBypassList"] = "<-loopback>"
                ctx = conn.call("Target.createBrowserContext", ctx_params, timeout=10.0)
                browser_context_id = str(ctx.get("browserContextId") or "")
                if not browser_context_id:
                    raise RuntimeError(f"missing browserContextId: {ctx}")
                target_info: dict[str, Any] = {
                    "browser_context_id": browser_context_id,
                    "source": "browser-context",
                    "temporary": True,
                    "proxy_server": context_proxy_server,
                }
                try:
                    created = conn.call(
                        "Target.createTarget",
                        {"url": MATRIX_PIC_URL, "browserContextId": browser_context_id},
                        timeout=max(15.0, cdp_tab_wait_sec + 10.0),
                    )
                    target_id = str(created.get("targetId") or "")
                    if not target_id:
                        raise RuntimeError(f"missing targetId: {created}")
                    attach = conn.call(
                        "Target.attachToTarget",
                        {"targetId": target_id, "flatten": True},
                        timeout=10.0,
                    )
                    session_id = str(attach.get("sessionId") or "")
                    if not session_id:
                        raise RuntimeError(f"missing sessionId: {attach}")
                    target_info.update({"target_id": target_id, "session_id": session_id})
                    conn.call("Page.enable", session_id=session_id, timeout=10.0)
                    conn.call("Runtime.enable", session_id=session_id, timeout=10.0)
                    browser_cdp_wait_target_ready(conn, session_id=session_id, timeout=max(30.0, cdp_tab_wait_sec + 20.0))
                    if cdp_reset_browser_fp:
                        target_info["browser_fp_reset"] = browser_cdp_eval(
                            conn,
                            session_id=session_id,
                            expression='(()=>{const before=localStorage.getItem("fp"); localStorage.removeItem("fp"); location.reload(); return {reset:true,before};})()',
                            timeout=10.0,
                        )
                        time.sleep(1.0)
                        target_info["ready_state_after_reset"] = browser_cdp_wait_target_ready(conn, session_id=session_id, timeout=max(30.0, cdp_tab_wait_sec + 20.0))
                    if cdp_fp_source == "browser":
                        fp = browser_cdp_get_fp(conn, session_id=session_id, timeout=10.0)
                        target_info["effective_fp"] = fp
                    if cdp_tab_wait_sec > 0:
                        time.sleep(cdp_tab_wait_sec)
                    target = target_info
                    value = browser_cdp_eval(conn, session_id=session_id, expression=build_script(), timeout=float(args.timeout) + 45.0)
                    return normalize_cdp_media_result(value)
                finally:
                    with contextlib.suppress(Exception):
                        conn.call("Target.disposeBrowserContext", {"browserContextId": browser_context_id}, timeout=10.0)
        if cdp_new_tab:
            opened_session = agent_browser_open_new_tab(MATRIX_PIC_URL, timeout=max(30.0, float(args.timeout)))
            target = {"session_id": opened_session, "bound": "", "temporary": True, "source": "new-tab"}
            target["ready_state"] = wait_browser_session_ready(opened_session, timeout=max(30.0, cdp_tab_wait_sec + 20.0))
            if cdp_reset_browser_fp:
                target["browser_fp_reset"] = agent_browser_execute_js(
                    session_id=opened_session,
                    script="(()=>{const before=localStorage.getItem('fp'); localStorage.removeItem('fp'); setTimeout(()=>location.reload(),50); return {reset:true,before,after:localStorage.getItem('fp')};})()",
                    timeout=15.0,
                )
                time.sleep(0.5)
                target["ready_state_after_reset"] = wait_browser_session_ready(opened_session, timeout=max(30.0, cdp_tab_wait_sec + 20.0))
            if cdp_fp_source == "browser":
                fp = agent_browser_get_fp(session_id=opened_session, timeout=10.0)
                target["effective_fp"] = fp
            if cdp_tab_wait_sec > 0:
                time.sleep(cdp_tab_wait_sec)
            return normalize_cdp_media_result(agent_browser_execute_js(session_id=opened_session, script=build_script(), timeout=float(args.timeout) + 45.0))
        nonlocal env_meta
        bound = getattr(args, "bound", DEFAULT_BOUND)
        session_id = getattr(args, "session_id", "")
        if cdp_auto_env and cdp_fp_source == "browser":
            env_meta = ensure_matrix_media_bound(
                bound=bound,
                session_id=session_id,
                timeout=float(getattr(args, "cdp_env_timeout", 90.0) or 90.0),
                force_new=bool(getattr(args, "cdp_force_new_bound", False)),
                reset_fp=bool(getattr(args, "cdp_reset_bound_fp", False)),
                auto_refresh_fp=bool(getattr(args, "cdp_auto_refresh_fp", False)),
                refresh_threshold=int(getattr(args, "cdp_refresh_threshold", 1) or 1),
            )
            if env_meta.get("session_id") and not session_id:
                session_id = str(env_meta.get("session_id") or "")
        target = {"session_id": session_id, "bound": bound, "temporary": False, "source": "bound-or-session", "env": env_meta}
        if cdp_fp_source == "browser":
            fp = agent_browser_get_fp(bound=bound, session_id=session_id, timeout=10.0)
            target["effective_fp"] = fp
        return normalize_cdp_media_result(agent_browser_execute_js(bound=bound, session_id=session_id, script=build_script(), timeout=float(args.timeout) + 45.0))

    try:
        if cdp_ws_mode == "proxy":
            with MediaWsProxy(xff=effective_xff, timeout=max(30.0, float(args.timeout)), egress_proxy=str(getattr(args, "egress_proxy", "") or "")) as proxy:
                ws_url = proxy.url
                result = run_cdp_script(ws_url)
                proxy_events = proxy.events
        else:
            result = run_cdp_script(ws_url)
    finally:
        if opened_session and cdp_close_tab:
            try:
                agent_browser_close_tab(opened_session)
            except BaseException:
                pass
    final = (result or {}).get("result") or (result or {}).get("final", {}).get("data") or {}
    if not final and result:
        hs_data = ((result or {}).get("handshake") or {}).get("data") or {}
        final = {"status": (result or {}).get("status"), "msg": (result or {}).get("error") or hs_data.get("msg")}
    return {
        "fp": final.get("fp") or (result or {}).get("fp") or fp,
        "media_type": media_type,
        "protocol_mode": "cdp",
        "cdp_ws_mode": cdp_ws_mode,
        "cdp_fp_source": cdp_fp_source,
        "cdp_target_mode": cdp_target_mode,
        "cdp_reset_browser_fp": bool(cdp_reset_browser_fp),
        "cdp_auto_env": cdp_auto_env,
        "cdp_auto_feedback": cdp_auto_feedback,
        "cdp_browser_version_url": str(getattr(args, "cdp_browser_version_url", "") or ""),
        "cdp_context_proxy_server": str(getattr(args, "cdp_context_proxy_server", "") or ""),
        "egress_proxy": str(getattr(args, "egress_proxy", "") or ""),
        "egress": egress_meta(str(getattr(args, "egress_proxy", "") or "")) if str(getattr(args, "egress_proxy", "") or "") else {"enabled": False},
        "requested_xff": effective_xff,
        "xff": wire_xff,
        "input_file": str(input_path),
        "input_size": input_path.stat().st_size,
        "headers": {"X-Forwarded-For": wire_xff} if wire_xff else {},
        "wire_ws_url": ws_url,
        "browser_target": target,
        "upload": upload_meta,
        "payload_sent": any(((item.get("blob") or item.get("data", {}).get("video_cos_url")) for item in ((result or {}).get("logs") or []))),
        "result": final,
        "logs": (result or {}).get("logs") or [],
        "proxy_events": proxy_events,
        "handshake": (result or {}).get("handshake"),
        "initial": (result or {}).get("initial"),
        "snapshots": (result or {}).get("snapshots") or [],
        "ticket_provider": ticket_meta,
        "ticket": (result or {}).get("ticket"),
        "feedback": (result or {}).get("feedback"),
        "cdp_env": env_meta,
        "cdp_result": result,
    }
