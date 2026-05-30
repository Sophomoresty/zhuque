"""Local WebSocket proxy for media detection with XFF injection."""
from __future__ import annotations

import asyncio
import contextlib
import inspect
import json
import ssl as ssl_module
import threading
import time
from typing import Any

import websockets

from .config import (
    DEFAULT_UA,
    HTTP_BASE,
    PIC_WS_URL,
)
from .transport import make_ws_proxy_socket


def _websockets_async_extra_headers_name() -> str:
    try:
        params = inspect.signature(websockets.connect).parameters
        if "additional_headers" in params:
            return "additional_headers"
    except Exception:
        pass
    return "extra_headers"



class MediaWsProxy:
    def __init__(self, *, xff: str = "", port: int = 0, timeout: float = 60.0, egress_proxy: str = ""):
        self.xff = xff
        self.egress_proxy = str(egress_proxy or "").strip()
        self.port = int(port or 0)
        self.timeout = timeout
        self.loop: asyncio.AbstractEventLoop | None = None
        self.server: Any = None
        self.thread: threading.Thread | None = None
        self.ready = threading.Event()
        self.error: BaseException | None = None
        self.events: list[dict[str, Any]] = []
        self.connections: set[Any] = set()
        self.targets: set[Any] = set()

    def __enter__(self) -> "MediaWsProxy":
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, name="matrix-media-ws-proxy", daemon=True)
        self.thread.start()
        if not self.ready.wait(self.timeout):
            raise RuntimeError("media ws proxy start timeout")
        if self.error:
            raise RuntimeError(f"media ws proxy failed: {self.error!r}")
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.loop and self.server:
            fut = asyncio.run_coroutine_threadsafe(self._stop(), self.loop)
            with contextlib.suppress(Exception):
                fut.result(timeout=5)
        if self.loop:
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=5)

    @property
    def url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def _run_loop(self) -> None:
        assert self.loop is not None
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._start())
            self.ready.set()
            self.loop.run_forever()
        except BaseException as exc:
            self.error = exc
            self.ready.set()
        finally:
            with contextlib.suppress(Exception):
                self.loop.run_until_complete(self.loop.shutdown_asyncgens())
            self.loop.close()

    async def _start(self) -> None:
        self.server = await websockets.serve(self._handler, "127.0.0.1", self.port, max_size=20 * 1024 * 1024)
        sock = next(iter(self.server.sockets), None)
        if not sock:
            raise RuntimeError("media ws proxy socket missing")
        self.port = int(sock.getsockname()[1])
        self.events.append({"event": "proxy-start", "port": self.port, "xff": self.xff, "egress_proxy": self.egress_proxy})

    async def _stop(self) -> None:
        for ws in list(self.connections):
            with contextlib.suppress(Exception):
                await ws.close()
        for ws in list(self.targets):
            with contextlib.suppress(Exception):
                await ws.close()
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        await asyncio.sleep(0.1)

    async def _handler(self, client, path=None) -> None:
        target = None
        self.connections.add(client)
        try:
            headers = {
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "Accept-Language": "zh-CN,zh;q=0.9",
            }
            if self.xff:
                headers["X-Forwarded-For"] = self.xff
            kwargs = {
                "origin": HTTP_BASE,
                "user_agent_header": DEFAULT_UA,
                "max_size": 20 * 1024 * 1024,
                _websockets_async_extra_headers_name(): headers,
            }
            if self.egress_proxy:
                sock, server_hostname = make_ws_proxy_socket(PIC_WS_URL, self.egress_proxy, timeout=self.timeout)
                kwargs.update({"sock": sock, "ssl": ssl_module.create_default_context(), "server_hostname": server_hostname})
            target = await websockets.connect(PIC_WS_URL, **kwargs)
            self.targets.add(target)
            self.events.append({"event": "target-connected", "xff": self.xff, "egress_proxy": self.egress_proxy})

            async def c2t() -> None:
                async for msg in client:
                    self.events.append({"event": "c2t", "type": "bytes" if isinstance(msg, bytes) else "text", "len": len(msg)})
                    await target.send(msg)

            async def t2c() -> None:
                async for msg in target:
                    preview = msg[:180] if isinstance(msg, str) else ""
                    self.events.append({"event": "t2c", "type": "bytes" if isinstance(msg, bytes) else "text", "len": len(msg), "preview": preview})
                    await client.send(msg)

            await asyncio.gather(c2t(), t2c())
        except Exception as exc:
            self.events.append({"event": "proxy-error", "error": repr(exc)})
            with contextlib.suppress(Exception):
                await client.close(code=1011, reason=str(exc)[:100])
        finally:
            if target:
                with contextlib.suppress(Exception):
                    await target.close()
                self.targets.discard(target)
            self.connections.discard(client)



