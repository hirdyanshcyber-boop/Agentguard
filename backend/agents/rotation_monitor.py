"""
LangGraph agent: continuous NHI rotation monitor.

Graph:
  check_rotation → evaluate_results → [alert_if_needed | done]
                       ↑___________________________|  (loop every interval)
"""
import asyncio
import structlog
from datetime import datetime, timezone
from typing import TypedDict, Literal
from langgraph.graph import StateGraph, END
from ..core.database import AsyncSessionLocal
from ..services.rotation_service import RotationService

log = structlog.get_logger()
svc = RotationService()


class MonitorState(TypedDict):
    last_run: str | None
    last_summary: dict | None
    critical_count: int
    run_count: int
    errors: list[str]


async def check_rotation(state: MonitorState) -> MonitorState:
    try:
        async with AsyncSessionLocal() as db:
            summary = await svc.check_all(db)
        log.info("monitor_check_complete", summary=summary)
        return {
            **state,
            "last_run": datetime.now(timezone.utc).isoformat(),
            "last_summary": summary,
            "critical_count": summary.get("never_rotated", 0) + summary.get("overdue", 0),
            "run_count": state.get("run_count", 0) + 1,
        }
    except Exception as e:
        log.error("monitor_check_failed", error=str(e))
        return {
            **state,
            "errors": state.get("errors", []) + [str(e)],
            "run_count": state.get("run_count", 0) + 1,
        }


async def evaluate_results(state: MonitorState) -> MonitorState:
    if state.get("critical_count", 0) > 0:
        log.warning("monitor_critical_violations", count=state["critical_count"],
                    summary=state.get("last_summary"))
    return state


def route_after_eval(state: MonitorState) -> Literal["done"]:
    # Always end — caller re-invokes on schedule
    return "done"


def build_monitor_graph() -> StateGraph:
    graph = StateGraph(MonitorState)
    graph.add_node("check_rotation", check_rotation)
    graph.add_node("evaluate_results", evaluate_results)
    graph.set_entry_point("check_rotation")
    graph.add_edge("check_rotation", "evaluate_results")
    graph.add_conditional_edges("evaluate_results", route_after_eval, {"done": END})
    return graph.compile()


monitor_graph = build_monitor_graph()


async def run_monitor_loop(interval_seconds: int = 3600):
    """Run rotation monitor on a schedule. Call once at startup."""
    state: MonitorState = {
        "last_run": None,
        "last_summary": None,
        "critical_count": 0,
        "run_count": 0,
        "errors": [],
    }
    log.info("rotation_monitor_started", interval_seconds=interval_seconds)
    while True:
        state = await monitor_graph.ainvoke(state)
        await asyncio.sleep(interval_seconds)
