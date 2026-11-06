"""Gate AgentDojo's banking tools through the AgentDelegation gateway.

`GatedRuntime` is a drop-in `FunctionsRuntime`: read-only tools run as usual, and every tool that changes state is
sent to the experiment gateway (eval/AgentDojoGateway) first. A denied call never reaches the tool; the model gets
a `PermissionDenied` error instead, as it would from a real API behind the gateway.
"""

from __future__ import annotations

import json
import urllib.request
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field

from agentdojo.functions_runtime import FunctionCall, FunctionCallArgTypes, FunctionReturnType, FunctionsRuntime, TaskEnvironment

# State-changing banking tools and the gateway action each maps to.
SENSITIVE = {
    "send_money": "banking.send_money",
    "schedule_transaction": "banking.schedule_transaction",
    "update_scheduled_transaction": "banking.update_scheduled_transaction",
    "update_password": "banking.update_password",
    "update_user_info": "banking.update_user_info",
}

# Account-level changes have no payee; they are authorized against this recipient with amount 0.
SELF = "self"


@dataclass(frozen=True)
class GatedCall:
    action: str
    recipient: str
    amount: float


def describe(function: str, args: Mapping[str, FunctionCallArgTypes], env: TaskEnvironment | None) -> GatedCall | None:
    """What a tool call means to the gateway, or None for read-only tools.

    `update_scheduled_transaction` may leave the recipient or amount unchanged; then the existing transaction's values
    are what the call authorizes.
    """
    action = SENSITIVE.get(function)
    if action is None:
        return None
    if function in ("send_money", "schedule_transaction"):
        return GatedCall(action, str(args.get("recipient", "")), float(args.get("amount") or 0))
    if function == "update_scheduled_transaction":
        existing = None
        if env is not None:
            existing = next((t for t in env.bank_account.scheduled_transactions if t.id == args.get("id")), None)  # type: ignore[attr-defined]
        recipient = args.get("recipient") or (existing.recipient if existing else "")
        amount = args.get("amount") or (existing.amount if existing else 0)
        return GatedCall(action, str(recipient), float(amount))
    return GatedCall(action, SELF, 0.0)


class GatewayClient:
    def __init__(self, base_url: str = "http://127.0.0.1:5199") -> None:
        self.base_url = base_url.rstrip("/")

    def _post(self, path: str, body: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.loads(res.read())

    def create_task(self, intent: str, scope: "TaskScope") -> str:
        task_id = uuid.uuid4().hex
        self._post(
            "/tasks",
            {
                "taskId": task_id,
                "intent": intent,
                "actions": sorted(scope.actions),
                "recipients": sorted(scope.recipients),
                "maxAmount": scope.max_amount,
                "treeBudget": scope.tree_budget,
            },
        )
        return task_id

    def authorize(self, task_id: str, call: GatedCall) -> tuple[bool, str]:
        d = self._post(
            "/authorize", {"taskId": task_id, "action": call.action, "recipient": call.recipient, "amount": call.amount}
        )
        return bool(d["allowed"]), str(d["reason"])


@dataclass
class TaskScope:
    """What the user approves for one task: the root ticket's scope."""

    actions: set[str] = field(default_factory=set)
    recipients: set[str] = field(default_factory=set)
    max_amount: float = 0.0
    tree_budget: float | None = None


def oracle_scope(ground_truth: list[FunctionCall], env: TaskEnvironment) -> TaskScope:
    """The narrowest scope that still lets the task's own ground-truth calls through.

    This is the best case for the defense: a user who approves exactly what the task needs. The realistic variant,
    where a model proposes the scope from the prompt alone, is `proposed_scope` in run_llm.py.
    """
    scope = TaskScope()
    total = 0.0
    for call in ground_truth:
        gated = describe(call.function, call.args, env)
        if gated is None:
            continue
        scope.actions.add(gated.action)
        scope.recipients.add(gated.recipient)
        scope.max_amount = max(scope.max_amount, gated.amount)
        total += gated.amount
    scope.tree_budget = round(total, 4) if scope.actions else None
    return scope


@dataclass
class GateLog:
    """Every gated decision in one task run, for the results file."""

    decisions: list[tuple[str, str, float, bool, str]] = field(default_factory=list)


def gated_runtime(client: GatewayClient, task_id: str, log: GateLog) -> type[FunctionsRuntime]:
    """A runtime class bound to one gateway task, in the form `TaskSuite.run_task_with_pipeline` expects."""

    class GatedRuntime(FunctionsRuntime):
        def run_function(
            self,
            env: TaskEnvironment | None,
            function: str,
            kwargs: Mapping[str, FunctionCallArgTypes],
            raise_on_error: bool = False,
        ) -> tuple[FunctionReturnType, str | None]:
            gated = describe(function, kwargs, env)
            if gated is not None:
                allowed, reason = client.authorize(task_id, gated)
                log.decisions.append((gated.action, gated.recipient, gated.amount, allowed, reason))
                if not allowed:
                    error = f"PermissionDenied: the delegation gateway refused this call ({reason})."
                    if raise_on_error:
                        raise PermissionError(error)
                    return "", error
            return super().run_function(env, function, kwargs, raise_on_error)

    return GatedRuntime
