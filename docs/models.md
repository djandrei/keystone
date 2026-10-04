# Keystone — LLM Models

Keystone talks to one OpenAI- or Anthropic-compatible endpoint per model, set by
the admin under **Settings** (stored in `system_settings`; keys are deployment
secrets in the environment, never the DB).

The endpoint must be reachable from Keystone's containers. A hosted API needs
nothing more. For a model served by **another container on the same host**,
attach that container to Keystone's network and use its container name in the
URL — `localhost` inside Keystone's containers is the container itself:

```bash
docker network connect keystone_default <llm-container>   # dev stack
# then, in Settings: http://<llm-container>:<port>/...
```

The production stack's network is `keystone-prod_default`. Reconnect after the
model's container is recreated.

## Analysis model (required)

- **LLM endpoint URL** + **Default model** — used for the deep, agentic work: the
  RE two-stage analyzer and the VR **reachability** agent (both tool-using ReAct).
- Key: `KEYSTONE_LLM_API_KEY`.

## Triage model (optional — the two-model cascade)

VR **triage** classifies *every* Semgrep finding — high volume, but a narrow
classification. Deep analysis runs only on the few suspicious findings but needs a
capable model. Splitting them lets a **cheap, fast** model do the bulk triage while
the **capable** model does the hard work, cutting cost and latency without losing
depth.

Configure under Settings → **Triage model (optional)**:

- **Triage model** — a cheaper model id (e.g. a "-highspeed" variant on the same
  provider). Blank ⇒ triage reuses the analysis model (single-model behavior).
- **Triage endpoint URL** — optional; blank ⇒ reuse the analysis endpoint. Set it
  to point triage at a *different* provider (e.g. a small local model).
- **Triage key** — `KEYSTONE_TRIAGE_API_KEY`; blank ⇒ reuse `KEYSTONE_LLM_API_KEY`.

Scope: the triage model drives **VR triage only**. RE (extraction + summary) and VR
reachability stay on the analysis model. Use **Test triage connection** to validate
the triage endpoint/key.

Mechanism: the worker binds the triage LM to the triage agent (`dspy.set_lm`) and
leaves the global LM as the analysis model, so only the triage step routes
differently.
