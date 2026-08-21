---
id: celery
title: Celery
kind: framework
language: python
detect:
  imports: ["celery", "shared_task"]
entrypoint_files: ["*tasks.py", "*/tasks/*.py"]
entrypoint_markers: ["@shared_task", "@app.task", "@celery_app.task", "@periodic_task"]
logic_layer_files: []
public_api_patterns: []
---

# Celery Review Notes

## Attack Surface

A task is an entrypoint, not just glue. Its arguments are attacker-influenced whenever the enqueue
site passes request input through, so review a task the same way as an HTTP handler. The web view
that calls `.delay()` or `.apply_async()` is the producer, and the task body is where the value
lands.

### Entrypoints

- Task definitions appear in `tasks.py` or a `tasks/` package and are marked by
  `@shared_task`, `@app.task`, or `@celery_app.task`. Periodic tasks wired by
  `crontab()` or a beat schedule run with no caller, so their inputs are config or
  stored state.
- Each task must be traced back to its `.delay(...)` and `.apply_async(...)` callers to
  identify user-controlled arguments.

## Trust Boundaries

### Authorization and IDOR

- A producer check is sufficient only when the authenticated enqueue boundary binds
  the authorized actor, tenant, resource, and operation into integrity-protected task
  data. Otherwise the task must reconstruct and enforce the owner or tenant decision.
  A bare resource id does not carry the producer's authorization context.

## Review Guidance

### Common Sinks and Gotchas

- A task that fetches a URL, runs a command, opens a file path, or renders a
  template from an argument, the same sink classes as a web handler, now reached
  off the request cycle.
- A task that logs full request headers, a response body, or a fetched credential leaks
  secrets and tokens into worker logs. See the
  information-exposure vulnerability class.
- A task with a side effect can run more than once when an unauthenticated or replayable
  producer enqueues it.

## Safe Boundaries

A Celery task is bounded when its producer authenticates the request and binds the actor, tenant,
resource, and operation into protected task data, or the worker reconstructs and checks that
authority before any side effect. Replayable side effects also need an idempotency or current state
control.
