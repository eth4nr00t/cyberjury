---
id: celery
title: Celery
kind: framework
language: python
detect:
  imports: ["celery", "shared_task"]
entrypoint_files: ["*tasks.py", "*/tasks/*.py"]
entrypoint_markers: ["@shared_task", "@app.task", "@celery_app.task", "@periodic_task", ".delay(", ".apply_async(", "crontab("]
logic_layers: ["*/services/*.py", "*services.py", "*/managers/*.py", "*managers.py", "*/dao/*.py", "*dao.py", "*/repositories/*.py"]
---
# Celery Review Notes

A task is an entrypoint, not just glue. Its arguments are attacker-influenced
whenever the enqueue site passes request input through, so review a task the same
way as an HTTP handler. The web view that calls `.delay()` or `.apply_async()` is
the producer, and the task body is where the value lands.

## Entrypoints
- Task definitions in `tasks.py` or a `tasks/` package, marked by `@shared_task`,
  `@app.task`, or `@celery_app.task`. Periodic tasks wired by `crontab()` or a
  beat schedule run with no caller, so their inputs are config or stored state.
- Trace each task back to its `.delay(...)` and `.apply_async(...)` callers to see
  which arguments are user-controlled.

## Authorization / IDOR
- A producer that checked the caller does not carry that identity into the task, so
  a task that acts on a resource by an id in its arguments needs its own owner or
  tenant check.

## Common Sinks / Gotchas
- A task that fetches a URL, runs a command, opens a file path, or renders a
  template from an argument, the same sink classes as a web handler, now reached
  off the request cycle.
- Secret and token exposure. A task that logs full request headers, a response
  body, or a fetched credential leaks it into worker logs. See the
  information-exposure vulnerability class.
- Replayable or duplicate enqueue. A task with a side effect that is enqueued from
  an unauthenticated or replayable producer runs more than once.
