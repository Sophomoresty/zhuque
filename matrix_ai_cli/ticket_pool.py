"""Browser-backed multi-lane ticket pool for image batches."""
from __future__ import annotations

import contextlib
import math
import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from .browser_cdp import BrowserCdpConnection, _target_for_legacy_selector, browser_cdp_wait_target_ready, browser_ws_endpoint
from .browser_state import ensure_matrix_media_bound
from .config import DEFAULT_MEDIA_BOUND, MATRIX_PIC_URL
from .transport import agent_browser_execute_js, normalize_cdp_context_proxy_server


@dataclass
class PooledTicket:
    fp: str
    ticket: str
    randstr: str
    max_uses: int
    remaining_uses: int
    captured_at: float = field(default_factory=time.time)


@dataclass
class TicketLane:
    lane_id: int
    session_id: str
    browser_context_id: str = ""
    context_proxy_server: str = ""
    fp: str = ""
    current: PooledTicket | None = None
    busy: bool = False
    refreshing: bool = False
    captures: int = 0
    failed_captures: int = 0
    session_refreshes: int = 0


_CAPTURE_IMAGE_TICKET_JS = """
(async () => {
  function findPic() {
    for (const el of Array.from(document.querySelectorAll('*'))) {
      const v = el && el.__vue__;
      if (v && v.aiGenPicRemainingCount !== undefined
          && typeof v.submit === 'function'
          && v.captcha && typeof v.captcha.show === 'function') return v;
    }
    return null;
  }
  const pic = findPic();
  if (!pic) return { ok: false, error: 'pic-component-not-found' };

  const fp = localStorage.getItem('fp');
  if (!fp) return { ok: false, error: 'no-fp-in-localStorage' };

  pic.processing = false;
  const state = { status: 'pending', fp, logs: [] };

  const oldCb = pic.captcha.options.callback;
  pic.captcha.options.callback = function(payload) {
    state.logs.push({ kind: 'callback', payload, ts: Date.now() });
    if (payload && payload.ticket && payload.randstr) {
      state.status = 'captured';
      state.payload = { ticket: payload.ticket, randstr: payload.randstr };
      state.capturedAt = Date.now();
      pic.processing = false;
      return undefined;
    }
    return oldCb && oldCb.apply(this, arguments);
  };

  if (pic.captcha.initOpts && typeof pic.captcha.initOpts.callback === 'function') {
    const oldInitCb = pic.captcha.initOpts.callback;
    pic.captcha.initOpts.callback = function(payload) {
      state.logs.push({ kind: 'initOpts.callback', payload, ts: Date.now() });
      if (payload && payload.ticket && payload.randstr) {
        state.status = 'captured';
        state.payload = { ticket: payload.ticket, randstr: payload.randstr };
        state.capturedAt = Date.now();
        pic.processing = false;
        return undefined;
      }
      return oldInitCb && oldInitCb.apply(this, arguments);
    };
  }

  window.__matrixPicCapture = state;
  window.__matrixPicRestore = () => {
    pic.captcha.options.callback = oldCb;
    pic.processing = false;
    state.restoredAt = Date.now();
  };

  pic.captcha.show();
  state.status = 'shown';
  return { ok: true, status: 'shown', fp, remaining: pic.aiGenPicRemainingCount };
})()
"""

_POLL_CAPTURE_JS = "(()=>window.__matrixPicCapture || null)()"
_RESTORE_JS = "(()=>{if(window.__matrixPicRestore){window.__matrixPicRestore();return true}return false})()"


def _inject_mouse_activity(*, bound: str = "", session_id: str = "", duration: float = 2.0) -> None:
    try:
        target_id = _target_for_legacy_selector(bound=bound or DEFAULT_MEDIA_BOUND, session_id=session_id, timeout=10.0)
        with BrowserCdpConnection(browser_ws_endpoint(), timeout=max(15.0, duration + 10.0)) as conn:
            attach = conn.call("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout=10.0)
            cdp_session = attach.get("sessionId", "")
            x, y = 600.0, 400.0
            for _ in range(int(duration * 20)):
                angle = random.uniform(0, 2 * math.pi)
                speed = random.uniform(3, 18)
                x = max(100, min(1600, x + speed * math.cos(angle)))
                y = max(100, min(800, y + speed * math.sin(angle)))
                conn.call("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": int(x), "y": int(y)}, session_id=cdp_session, timeout=5.0)
                time.sleep(0.05)
            conn.call("Target.detachFromTarget", {"sessionId": cdp_session}, timeout=5.0)
    except Exception:
        pass


def _capture_one_image_ticket(*, bound: str = "", session_id: str = "", timeout: float = 60.0) -> dict[str, Any]:
    _inject_mouse_activity(bound=bound, session_id=session_id, duration=2.0)
    install = agent_browser_execute_js(bound=bound or DEFAULT_MEDIA_BOUND, session_id=session_id, script=_CAPTURE_IMAGE_TICKET_JS, timeout=min(timeout, 20.0))
    if isinstance(install, dict) and install.get("error"):
        return {"ok": False, "error": f"install failed: {install.get('error')}"}
    deadline = time.time() + timeout
    last_state: dict[str, Any] | None = None
    while time.time() < deadline:
        state = agent_browser_execute_js(bound=bound or DEFAULT_MEDIA_BOUND, session_id=session_id, script=_POLL_CAPTURE_JS, timeout=10.0)
        if isinstance(state, dict):
            last_state = state
            if state.get("status") == "captured" and isinstance(state.get("payload"), dict):
                agent_browser_execute_js(bound=bound or DEFAULT_MEDIA_BOUND, session_id=session_id, script=_RESTORE_JS, timeout=10.0)
                return {"ok": True, "fp": state.get("fp", ""), "ticket": state["payload"]["ticket"], "randstr": state["payload"]["randstr"]}
        time.sleep(1.0)
    agent_browser_execute_js(bound=bound or DEFAULT_MEDIA_BOUND, session_id=session_id, script=_RESTORE_JS, timeout=10.0)
    return {"ok": False, "error": "timeout", "last_state": last_state}


class BrowserTicketPool:
    def __init__(
        self,
        *,
        bound: str = "",
        session_id: str = "",
        lane_count: int = 1,
        max_uses_per_ticket: int = 4,
        capture_timeout: float = 60.0,
        capture_cooldown: float = 2.0,
        context_proxy_pool: list[str] | None = None,
    ):
        self._bound = bound or DEFAULT_MEDIA_BOUND
        self._seed_session_id = session_id
        self._lane_count = max(1, int(lane_count or 1))
        self._max_uses = max(1, int(max_uses_per_ticket or 1))
        self._capture_timeout = capture_timeout
        self._capture_cooldown = capture_cooldown
        self._context_proxy_pool = [normalize_cdp_context_proxy_server(x) for x in (context_proxy_pool or []) if str(x).strip()]
        self._lock = threading.Lock()
        self._available = threading.Condition(self._lock)
        self._lanes: list[TicketLane] = []
        self._next_lane_index = 0
        self._stats = {"lane_count": self._lane_count, "captured": 0, "used": 0, "failed_captures": 0, "session_refreshes": 0}

    def start(self) -> "BrowserTicketPool":
        if self._lane_count > 1:
            lanes: list[TicketLane | None] = [None] * self._lane_count
            with ThreadPoolExecutor(max_workers=self._lane_count) as pool:
                futures = {
                    pool.submit(self._open_and_prime_lane, lane_id): lane_id
                    for lane_id in range(self._lane_count)
                }
                for future in as_completed(futures):
                    lane_id = futures[future]
                    lanes[lane_id] = future.result()
            self._lanes = [lane for lane in lanes if lane is not None]
            return self
        for lane_id in range(self._lane_count):
            self._lanes.append(self._open_and_prime_lane(lane_id))
        return self

    def _open_and_prime_lane(self, lane_id: int) -> TicketLane:
        lane = self._open_lane(lane_id, session_id=self._seed_session_id if lane_id == 0 else "")
        self._ensure_lane_ticket(lane)
        return lane

    def stop(self) -> dict[str, Any]:
        for lane in self._lanes:
            self._dispose_lane_context(lane)
        with self._lock:
            self._stats["lanes"] = [
                {
                    "lane_id": lane.lane_id,
                    "session_id": lane.session_id,
                    "browser_context_id": lane.browser_context_id,
                    "context_proxy_server": lane.context_proxy_server,
                    "fp": lane.fp,
                    "captures": lane.captures,
                    "failed_captures": lane.failed_captures,
                    "session_refreshes": lane.session_refreshes,
                    "remaining_uses": lane.current.remaining_uses if lane.current else 0,
                }
                for lane in self._lanes
            ]
            return dict(self._stats)

    def acquire(self, timeout: float = 120.0) -> tuple[str, str, str, dict[str, Any]]:
        deadline = time.time() + timeout
        while True:
            lane = self._claim_ready_lane()
            if lane:
                ticket = lane.current
                assert ticket is not None
                ticket.remaining_uses -= 1
                with self._lock:
                    self._stats["used"] += 1
                return ticket.fp, ticket.ticket, ticket.randstr, {
                    "source": "browser-pool",
                    "lane_id": lane.lane_id,
                    "fp": ticket.fp,
                    "remaining_uses_after": ticket.remaining_uses,
                    "ticket_age_sec": round(time.time() - ticket.captured_at, 2),
                    "cdp_context_proxy_server": lane.context_proxy_server,
                }
            refresh_lane = self._claim_stale_lane()
            if refresh_lane:
                ok = self._ensure_lane_ticket(refresh_lane)
                with self._available:
                    refresh_lane.refreshing = False
                    if not ok:
                        refresh_lane.current = None
                    self._available.notify_all()
                continue
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("ticket pool: no lane available within timeout")
            with self._available:
                self._available.wait(timeout=min(remaining, 2.0))

    def release(self, lane_id: int) -> None:
        should_refresh = False
        lane: TicketLane | None = None
        with self._available:
            lane = next((item for item in self._lanes if item.lane_id == lane_id), None)
            if lane is None:
                return
            lane.busy = False
            should_refresh = bool((lane.current is None or lane.current.remaining_uses <= 0) and not lane.refreshing)
            if should_refresh:
                lane.refreshing = True
            self._available.notify_all()
        if lane is None or not should_refresh:
            return
        if self._max_uses <= 1:
            self._refresh_lane_session(lane)
        ok = self._ensure_lane_ticket(lane)
        with self._available:
            lane.refreshing = False
            if not ok:
                lane.current = None
            self._available.notify_all()

    @property
    def stats(self) -> dict[str, Any]:
        return self.stop()

    def _open_lane(self, lane_id: int, *, session_id: str = "") -> TicketLane:
        if not session_id:
            try:
                ws = browser_ws_endpoint()
                with BrowserCdpConnection(ws, timeout=max(30.0, self._capture_timeout + 15.0)) as conn:
                    context_proxy_server = self._context_proxy_pool[lane_id % len(self._context_proxy_pool)] if self._context_proxy_pool else ""
                    ctx_params = {"proxyServer": context_proxy_server} if context_proxy_server else {}
                    ctx = conn.call("Target.createBrowserContext", ctx_params, timeout=10.0)
                    browser_context_id = str(ctx.get("browserContextId") or "")
                    created = conn.call("Target.createTarget", {"url": MATRIX_PIC_URL, "browserContextId": browser_context_id}, timeout=20.0)
                    target_id = str(created.get("targetId") or "")
                    attach = conn.call("Target.attachToTarget", {"targetId": target_id, "flatten": True}, timeout=10.0)
                    cdp_session = str(attach.get("sessionId") or "")
                    conn.call("Page.enable", session_id=cdp_session, timeout=10.0)
                    conn.call("Runtime.enable", session_id=cdp_session, timeout=10.0)
                    state = browser_cdp_wait_target_ready(conn, session_id=cdp_session, timeout=30.0)
                    with contextlib.suppress(Exception):
                        conn.call("Target.detachFromTarget", {"sessionId": cdp_session}, timeout=5.0)
                    return TicketLane(lane_id=lane_id, session_id=target_id, browser_context_id=browser_context_id, context_proxy_server=context_proxy_server, fp=str(state.get("fp") or ""))
            except Exception:
                pass
        bound_state = ensure_matrix_media_bound(bound=self._bound, session_id=session_id, timeout=90.0, force_new=bool(lane_id or not session_id), auto_refresh_fp=True)
        state = bound_state.get("state") or bound_state
        return TicketLane(lane_id=lane_id, session_id=str(bound_state.get("session_id") or session_id or ""), fp=str(state.get("fp") or ""))

    def _claim_ready_lane(self) -> TicketLane | None:
        with self._available:
            if not self._lanes:
                return None
            for offset in range(len(self._lanes)):
                index = (self._next_lane_index + offset) % len(self._lanes)
                lane = self._lanes[index]
                if lane.busy or lane.refreshing or lane.current is None or lane.current.remaining_uses <= 0:
                    continue
                lane.busy = True
                self._next_lane_index = (index + 1) % len(self._lanes)
                return lane
            return None

    def _claim_stale_lane(self) -> TicketLane | None:
        with self._available:
            for lane in self._lanes:
                if lane.busy or lane.refreshing:
                    continue
                if lane.current is not None and lane.current.remaining_uses > 0:
                    continue
                lane.refreshing = True
                return lane
            return None

    def _refresh_lane_session(self, lane: TicketLane) -> None:
        self._dispose_lane_context(lane)
        opened = self._open_lane(lane.lane_id)
        lane.session_id = opened.session_id
        lane.browser_context_id = opened.browser_context_id
        lane.context_proxy_server = opened.context_proxy_server
        lane.fp = opened.fp
        lane.session_refreshes += 1
        with self._lock:
            self._stats["session_refreshes"] += 1

    def _dispose_lane_context(self, lane: TicketLane) -> None:
        if not lane.browser_context_id:
            return
        try:
            with BrowserCdpConnection(browser_ws_endpoint(), timeout=20.0) as conn:
                conn.call("Target.disposeBrowserContext", {"browserContextId": lane.browser_context_id}, timeout=10.0)
        except Exception:
            pass
        lane.browser_context_id = ""

    def _ensure_lane_ticket(self, lane: TicketLane) -> bool:
        for attempt in range(2):
            result = _capture_one_image_ticket(bound=self._bound, session_id=lane.session_id, timeout=self._capture_timeout)
            if result.get("ok"):
                lane.fp = str(result.get("fp") or lane.fp)
                lane.current = PooledTicket(
                    fp=lane.fp,
                    ticket=str(result["ticket"]),
                    randstr=str(result["randstr"]),
                    max_uses=self._max_uses,
                    remaining_uses=self._max_uses,
                )
                lane.captures += 1
                with self._lock:
                    self._stats["captured"] += 1
                return True
            error = str(result.get("error") or "")
            last = result.get("last_state") if isinstance(result.get("last_state"), dict) else {}
            lane.failed_captures += 1
            with self._lock:
                self._stats["failed_captures"] += 1
            if error == "timeout" and last.get("status") in {"shown", "pending"}:
                self._refresh_lane_session(lane)
                continue
            if "no-fp" in error or "pic-component-not-found" in error:
                self._refresh_lane_session(lane)
                continue
            if attempt == 0 and self._capture_cooldown > 0:
                time.sleep(self._capture_cooldown)
        return False
