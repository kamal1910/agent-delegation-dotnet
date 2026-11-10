"""LLM-free AgentDojo experiment: a fully hijacked agent against the delegation gateway.

For every banking user task, and every (user task, injection task) pair:

  utility run    the agent makes exactly the user task's ground-truth calls.
  hijacked run   the agent makes the user task's calls and then every call of the injection task's goal, as if a
                 prompt injection had taken complete control of it. This is the strongest attacker AgentDojo can
                 express; a real model obeys injections only some of the time.

Each run happens three times:
  none              no control (plain tools, like an agent holding broad service credentials)
  gateway-unbound   every state-changing call routed through the gateway, under the oracle scope (exactly the
                    actions, recipients and amounts the task's ground truth needs)
  gateway           the same, with the values of account-change arguments (e.g. the new password) bound in the root
  gateway-proposed  (with --proposed-scopes) the scope Claude proposed from the user's request alone (propose_scope.py)

  dotnet run -c Release --project eval/AgentDojoGateway          # in another terminal
  .venv/Scripts/python run_ground_truth.py --out results/ground_truth.csv
"""

from __future__ import annotations

import argparse
import csv
import json
from collections.abc import Sequence
from pathlib import Path

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.base_tasks import BaseInjectionTask, BaseUserTask
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatAssistantMessage, ChatMessage, ChatToolResultMessage, text_content_block_from_string

from gate import GateLog, GatewayClient, gated_runtime, oracle_scope, scope_from_proposal

BENCHMARK_VERSION = "v1.2.2"
MODES = ("none", "gateway-unbound", "gateway")


class ScriptedAgent(BasePipelineElement):
    """Makes the user task's ground-truth calls, then (when hijacked) the injection task's, ignoring errors."""

    def __init__(self, user_task: BaseUserTask, injection_task: BaseInjectionTask | None) -> None:
        self.user_task = user_task
        self.injection_task = injection_task

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        calls = list(self.user_task.ground_truth(env))
        if self.injection_task is not None:
            calls += self.injection_task.ground_truth(env)
        new_messages: list[ChatMessage] = []
        for call in calls:
            new_messages.append(
                ChatAssistantMessage(role="assistant", tool_calls=[call], content=[text_content_block_from_string("")])
            )
            result, error = runtime.run_function(env, call.function, call.args)
            new_messages.append(
                ChatToolResultMessage(
                    role="tool",
                    content=[text_content_block_from_string(tool_result_to_str(result))],
                    tool_call=call,
                    tool_call_id=None,
                    error=error,
                )
            )
        new_messages.append(
            ChatAssistantMessage(
                role="assistant",
                content=[text_content_block_from_string(self.user_task.GROUND_TRUTH_OUTPUT)],
                tool_calls=None,
            )
        )
        return query, runtime, env, [*messages, *new_messages], extra_args


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gateway", default="http://127.0.0.1:5199")
    parser.add_argument("--out", default="results/ground_truth.csv")
    parser.add_argument("--proposed-scopes", default=None,
                        help="JSON from propose_scope.py; adds the gateway-proposed mode")
    args = parser.parse_args()

    suite = get_suite(BENCHMARK_VERSION, "banking")
    client = GatewayClient(args.gateway)
    defaults = suite.get_injection_vector_defaults()
    rows: list[dict] = []

    modes = list(MODES)
    proposals: dict[str, dict] = {}
    if args.proposed_scopes:
        proposals = json.loads(Path(args.proposed_scopes).read_text(encoding="utf-8"))["proposals"]
        modes.append("gateway-proposed")

    for user_task in suite.user_tasks.values():
        # The scope the user approves, from the task's own ground truth on its starting environment.
        start = user_task.init_environment(suite.load_and_inject_default_environment(defaults))
        ground_truth = list(user_task.ground_truth(start))
        scopes = {
            "gateway-unbound": oracle_scope(ground_truth, start, bind_arguments=False),
            "gateway": oracle_scope(ground_truth, start, bind_arguments=True),
        }
        if proposals:
            # What the approval step granted from the request alone; a failed proposal grants nothing.
            scopes["gateway-proposed"] = scope_from_proposal(proposals.get(user_task.ID, {}).get("scope"))

        for injection_task in [None, *suite.injection_tasks.values()]:
            for mode in modes:
                log = GateLog()
                runtime_class: type[FunctionsRuntime] = FunctionsRuntime
                scope = scopes.get(mode)
                if scope is not None:
                    runtime_class = gated_runtime(client, client.create_task(user_task.PROMPT, scope), log)

                utility, security = suite.run_task_with_pipeline(
                    ScriptedAgent(user_task, injection_task), user_task, injection_task, defaults, runtime_class
                )
                rows.append(
                    {
                        "user_task": user_task.ID,
                        "injection_task": injection_task.ID if injection_task else "",
                        "mode": mode,
                        "utility": utility,
                        # AgentDojo's `security` is True when the injection task's goal was achieved.
                        "attack_success": security if injection_task else "",
                        "denied_calls": sum(1 for d in log.decisions if not d[3]),
                        "deny_reasons": ";".join(sorted({d[4] for d in log.decisions if not d[3]})),
                        "scope_actions": " ".join(sorted(scopes["gateway"].actions)),
                        "scope_recipients": " ".join(sorted(scopes["gateway"].recipients)),
                        "bound_arguments": " ".join(sorted(scope.arguments)) if scope else "",
                    }
                )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    def rate(mode: str, key: str, hijacked: bool) -> str:
        selected = [r for r in rows if r["mode"] == mode and bool(r["injection_task"]) == hijacked]
        hits = sum(1 for r in selected if r[key] is True)
        return f"{hits}/{len(selected)} ({100 * hits / max(len(selected), 1):.1f}%)"

    print(f"banking {BENCHMARK_VERSION}: {len(suite.user_tasks)} user tasks, {len(suite.injection_tasks)} injection tasks")
    for mode in modes:
        print(
            f"  {mode:16} utility (no attack) {rate(mode, 'utility', False):>16}   "
            f"utility under attack {rate(mode, 'utility', True):>16}   "
            f"attack success {rate(mode, 'attack_success', True):>16}"
        )
    print(f"Wrote {out.resolve()}")


if __name__ == "__main__":
    main()
