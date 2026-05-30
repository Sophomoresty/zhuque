"""Windowed browser-pool batch runner for image detection."""
from __future__ import annotations

import argparse
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Callable

from .batch import batch_media_item_args
from .media_batch_job import run_batch_media_detect_job
from .ticket_pool import BrowserTicketPool


def run_browser_pool_windows(
    *,
    args: argparse.Namespace,
    image_paths: list[Path],
    reports_dir: Path,
    concurrency: int,
    jsonl: Any,
    record_batch_compact: Callable[[argparse.Namespace, dict[str, Any]], bool],
    enter_worker: Callable[[], None],
    exit_worker: Callable[[], None],
    should_stop: Callable[[], bool],
    route_notes: list[str],
) -> None:
    pool_bound = str(getattr(args, "browser_pool_bound", "") or "")
    pool_session = str(getattr(args, "browser_pool_session_id", "") or "")
    requested_max_uses = max(1, int(getattr(args, "browser_pool_max_uses", 1) or 1))
    if requested_max_uses != 1:
        route_notes.append(f"browser-pool-ticket-max-uses-clamped:{requested_max_uses}->1")
    ticket_pool = BrowserTicketPool(
        bound=pool_bound,
        session_id=pool_session,
        lane_count=concurrency,
        max_uses_per_ticket=1,
        capture_timeout=float(getattr(args, "ticket_timeout", 60.0) or 60.0),
        capture_cooldown=float(getattr(args, "browser_pool_cooldown", 2.0) or 2.0),
        context_proxy_pool=list(getattr(args, "_cdp_context_proxy_pool", []) or []),
    ).start()
    try:
        queued = 0
        stop_queued = False
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            while not stop_queued and queued < len(image_paths):
                batch_jobs: list[dict[str, Any]] = []
                while (
                    not stop_queued
                    and not should_stop()
                    and queued < len(image_paths)
                    and len(batch_jobs) < concurrency
                ):
                    i = queued + 1
                    image_path = image_paths[queued]
                    queued += 1
                    item_args = batch_media_item_args(args, image_path, i)
                    setattr(item_args, "_batch_total", len(image_paths))
                    setattr(item_args, "_route_attempt_offset", int(getattr(args, "route_attempt_offset", 0) or 0))
                    setattr(item_args, "attempts", 1)
                    try:
                        fp, ticket, randstr, ticket_meta = ticket_pool.acquire(timeout=120.0)
                    except TimeoutError as exc:
                        compact = {
                            "ok": False,
                            "protocol_mode": getattr(args, "driver", "pure"),
                            "media_type": "image",
                            "status": "failed",
                            "i": i,
                            "input_file": str(image_path),
                            "error": f"browser-pool acquire timeout: {exc}",
                            "elapsed_sec": 0,
                            "report_json": "",
                        }
                        ok = record_batch_compact(item_args, compact)
                        jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(",", ":")) + "\n")
                        jsonl.flush()
                        stop_queued = bool(getattr(args, "stop_on_fail", False) and not ok) or should_stop()
                        continue
                    setattr(item_args, "_prepared_fp", fp)
                    if ticket_meta.get("cdp_context_proxy_server"):
                        setattr(item_args, "egress_proxy", str(ticket_meta.get("cdp_context_proxy_server") or ""))
                    setattr(item_args, "fp", fp)
                    setattr(item_args, "fp_mode", "fixed")
                    batch_jobs.append(
                        {
                            "i": i,
                            "image_path": image_path,
                            "item_args": item_args,
                            "report_path": reports_dir / f"{i:06d}-{image_path.stem}.json",
                            "ticket": ticket,
                            "randstr": randstr,
                            "ticket_meta": ticket_meta,
                            "lane_id": int(ticket_meta.get("lane_id", -1) or -1),
                        }
                    )
                if not batch_jobs:
                    break

                future_map = {}
                for job in batch_jobs:
                    def worker(current_job: dict[str, Any] = job) -> dict[str, Any]:
                        enter_worker()
                        try:
                            return run_batch_media_detect_job(
                                item_args=current_job["item_args"],
                                image_path=current_job["image_path"],
                                report_path=current_job["report_path"],
                                i=current_job["i"],
                                started_at=time.time(),
                                ticket=current_job["ticket"],
                                randstr=current_job["randstr"],
                                ticket_meta=current_job["ticket_meta"],
                            )
                        finally:
                            if current_job["lane_id"] >= 0:
                                ticket_pool.release(current_job["lane_id"])
                            exit_worker()

                    future_map[pool.submit(worker)] = job

                for future in as_completed(future_map):
                    job = future_map[future]
                    compact = future.result()
                    ok = record_batch_compact(job["item_args"], compact)
                    jsonl.write(json.dumps(compact, ensure_ascii=False, separators=(",", ":")) + "\n")
                    jsonl.flush()
                    if should_stop() or (getattr(args, "stop_on_fail", False) and not ok):
                        stop_queued = True
    finally:
        route_notes.append(f"browser-pool-stats:{json.dumps(ticket_pool.stop())}")
