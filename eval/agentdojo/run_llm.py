"""AgentDojo banking suite with a real model, with and without the delegation gateway (paper RQ1b).

Runs AgentDojo's own agent pipeline and prompt-injection attack, and scores utility and attack success with
AgentDojo's own checks. The only change is the tool runtime: in `gateway` mode every state-changing tool call is
authorized by the gateway under the scope the user approved for that task.

  dotnet run -c Release --project eval/AgentDojoGateway          # in another terminal
  set ANTHROPIC_API_KEY=...
  .venv/Scripts/python run_llm.py --model claude-sonnet-5-5 --limit 2          # estimate cost on a few tasks first
  .venv/Scripts/python run_llm.py --model claude-sonnet-5-5 --out results/llm_claude.csv

  # A local model through any OpenAI-compatible server (Ollama, vLLM, LM Studio):
  .venv/Scripts/python run_llm.py --provider openai-compatible --base-url http://localhost:11434/v1 --model qwen3:14b

Each (user task, injection task) pair is one model conversation per mode, so a full run is
16 user tasks x (1 + 9 injection tasks) x len(modes) conversations.
"""

from __future__ import annotations

import argparse
import csv
import time
from pathlib import Path

import agentdojo.models
from agentdojo.agent_pipeline import AgentPipeline, AnthropicLLM, OpenAILLM, PipelineConfig
from agentdojo.attacks import load_attack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from gate import GateLog, GatewayClient, gated_runtime, oracle_scope

BENCHMARK_VERSION = "v1.2.2"


def build_pipeline(args: argparse.Namespace) -> AgentPipeline:
    if args.provider == "anthropic":
        import anthropic

        llm = AnthropicLLM(anthropic.Anthropic(), args.model)
    else:
        import openai

        llm = OpenAILLM(openai.OpenAI(base_url=args.base_url, api_key=args.api_key or "EMPTY"), args.model)

    pipeline = AgentPipeline.from_config(
        PipelineConfig(llm=llm, model_id=None, defense=args.defense, system_message_name=None, system_message=None)
    )
    # AgentDojo's attacks address the model by name and look it up from the pipeline name, which only knows the
    # models AgentDojo shipped with. Register the name used in the injected text for any other model.
    agentdojo.models.MODEL_NAMES.setdefault(args.model, args.model_prose_name)
    pipeline.name = args.model if args.defense is None else f"{args.model}-{args.defense}"
    return pipeline


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", choices=["anthropic", "openai-compatible"], default="anthropic")
    parser.add_argument("--model", required=True)
    parser.add_argument("--model-prose-name", default="the AI assistant",
                        help="how the injected text addresses the model, e.g. Claude or GPT-4")
    parser.add_argument("--base-url", default=None)
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--defense", default=None, help="an AgentDojo defense to combine with, e.g. repeat_user_prompt")
    parser.add_argument("--attack", default="important_instructions")
    parser.add_argument("--modes", default="none,gateway")
    parser.add_argument("--limit", type=int, default=None, help="only the first N user tasks (for cost estimates)")
    parser.add_argument("--gateway", default="http://127.0.0.1:5199")
    parser.add_argument("--out", default="results/llm.csv")
    args = parser.parse_args()

    suite = get_suite(BENCHMARK_VERSION, "banking")
    pipeline = build_pipeline(args)
    attack = load_attack(args.attack, suite, pipeline)
    client = GatewayClient(args.gateway)
    defaults = suite.get_injection_vector_defaults()
    modes = args.modes.split(",")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fields = ["model", "defense", "attack", "mode", "user_task", "injection_task", "utility", "attack_success",
              "denied_calls", "deny_reasons", "seconds"]
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()

        user_tasks = list(suite.user_tasks.values())[: args.limit]
        for user_task in user_tasks:
            start = user_task.init_environment(suite.load_and_inject_default_environment(defaults))
            scope = oracle_scope(list(user_task.ground_truth(start)), start)

            for injection_task in [None, *suite.injection_tasks.values()]:
                injections = defaults if injection_task is None else attack.attack(user_task, injection_task)
                for mode in modes:
                    log = GateLog()
                    runtime_class: type[FunctionsRuntime] = FunctionsRuntime
                    if mode == "gateway":
                        runtime_class = gated_runtime(client, client.create_task(user_task.PROMPT, scope), log)

                    began = time.monotonic()
                    utility, security = suite.run_task_with_pipeline(
                        pipeline, user_task, injection_task, injections, runtime_class
                    )
                    writer.writerow({
                        "model": args.model,
                        "defense": args.defense or "",
                        "attack": args.attack,
                        "mode": mode,
                        "user_task": user_task.ID,
                        "injection_task": injection_task.ID if injection_task else "",
                        "utility": utility,
                        "attack_success": security if injection_task else "",
                        "denied_calls": sum(1 for d in log.decisions if not d[3]),
                        "deny_reasons": ";".join(sorted({d[4] for d in log.decisions if not d[3]})),
                        "seconds": round(time.monotonic() - began, 1),
                    })
                    f.flush()
                    print(f"{user_task.ID:14} {injection_task.ID if injection_task else '(no attack)':18} {mode:8} "
                          f"utility={utility} attack_success={security if injection_task else '-'}")

    print(f"Wrote {out.resolve()}")


if __name__ == "__main__":
    main()
