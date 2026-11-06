# AgentDojo evaluation

Runs [AgentDojo](https://github.com/ethz-spylab/agentdojo)'s banking suite with every state-changing tool call
authorized by the AgentDelegation gateway. AgentDojo's own tasks, attacks and scoring are used unchanged. The only
change is the tool runtime, which sends `send_money`, `schedule_transaction`, `update_scheduled_transaction`,
`update_password` and `update_user_info` to the gateway before running them.

| File | What it does |
|---|---|
| `../AgentDojoGateway` | .NET service that plays the user, the orchestrator agent and the banking specialist for each task, and runs the real `DelegationAuthorizer` on every gated call |
| `gate.py` | `GatedRuntime` (the gated tool runtime), the gateway client, and the oracle scope |
| `run_ground_truth.py` | No model: replays each task's ground truth, and each injection task's goal as a fully hijacked agent |
| `run_llm.py` | A real model through AgentDojo's pipeline and prompt-injection attack |

## Setup

```bash
py -3.11 -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
dotnet run -c Release --project ../AgentDojoGateway      # keep running; listens on http://127.0.0.1:5199
```

## Scope

For each user task, the user approves a root ticket with the **oracle scope**: the actions, recipients, largest
amount and total that the task's own ground-truth calls need. This is the best case for the defense. Account changes
(`update_password`, `update_user_info`) are authorized with recipient `self` and amount 0.

A realistic variant, where a model proposes the scope from the prompt alone before seeing any tool output, is still
to do.

## No model: a fully hijacked agent

```bash
.venv/Scripts/python run_ground_truth.py --out results/ground_truth.csv
```

Banking v1.2.2: 16 user tasks, 9 injection tasks, 144 pairs.

| | Utility, no attack | Utility under attack | Attack success |
|---|---|---|---|
| No control | 16/16 (100%) | 125/144 (86.8%) | 144/144 (100%) |
| Gateway, oracle scope | 16/16 (100%) | 143/144 (99.3%) | **1/144 (0.7%)** |

The one attack that succeeds is `user_task_14` × `injection_task_7`. The user approves changing the password, and the
injection changes it to a different value. Scopes bind actions, recipients and amounts, not other argument values,
so an approved action with an attacker-chosen argument passes. The same pair is the one utility loss.

## With a model

```bash
set ANTHROPIC_API_KEY=...
.venv/Scripts/python run_llm.py --model claude-sonnet-5-5 --model-prose-name Claude --limit 2
.venv/Scripts/python run_llm.py --model claude-sonnet-5-5 --model-prose-name Claude --out results/llm_claude.csv
```

A full run is 16 × 10 × 2 = 320 conversations per model. Run `--limit 2` first to see the cost. `--defense` combines
the gateway with one of AgentDojo's defenses (for example `repeat_user_prompt` or `spotlighting_with_delimiting`).
`--provider openai-compatible --base-url ...` runs a local model through Ollama, vLLM or LM Studio.
