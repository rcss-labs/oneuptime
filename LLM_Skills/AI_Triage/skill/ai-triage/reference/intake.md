# Intake from OneUptime

## 1. What this mapping is

This turns an incident number into the incident file that `case.py init` reads (the file's format is in `reference/formats.md`, section 1).
It was written from the descriptions of the OneUptime MCP tools and from the OneUptime source. It has not run against a live OneUptime.
Tool names below are the generated ones: `list_<things>` and `get_<thing>`. Each `list_` tool takes `query`, `select`, `skip`, `limit`, `sort`;
each `get_` tool takes the record's `id` and `select`. If a name or a shape differs from what is written here, use the nearest tool, keep the
field empty when you cannot fill it, and write the gap in `open_questions` of `report.json`. Do not guess a value.

## 2. The calls, in order

1. `list_incidents` with `query` `{"incidentNumber": <N>}` and `limit` 1. `get_incident` takes only the record id (a UUID), so the number is looked up with the list.
   Select: `_id`, `incidentNumber`, `incidentNumberWithPrefix`, `title`, `description`, `declaredAt`, `createdAt`, `impactStartedAt`,
   `currentIncidentState`, `incidentSeverity`, `monitors`, `labels`. Keep the `_id`.
2. `get_incident_state` with the `_id` found in `currentIncidentState` (a default read returns a relation as `{"_id": ...}` only). Select `name`, `isResolvedState`.
3. `get_incident_severity` with the `_id` found in `incidentSeverity`. Select `name`.
4. `get_monitor` once per `_id` in `monitors`. Select `name`, `monitorType`, `monitorSteps`.
5. `get_label` once per `_id` in `labels`. Select `name`.
6. `list_incident_state_timelines` with `query` `{"incidentId": "<_id>"}`, `sort` `{"startsAt": "ASC"}`. Select `startsAt`, `incidentStateId`.
   Resolve each distinct `incidentStateId` with `get_incident_state` (select `name`, `isResolvedState`).
7. `list_incident_internal_notes` and `list_incident_public_notes` with `query` `{"incidentId": "<_id>"}`. Select `note`, `createdAt` (public notes: `postedAt` if present).
8. Alerts: `list_alerts` is linked to a monitor, not to an incident, and the incident file has no place for them. Skip it, or put what you learn in `notes`.

Write the result to `~/.ai-triage/intake/<number>.json` with the Write tool, then run `case.py init`.

## 3. Field by field

| Incident file field | Source | What to write |
| --- | --- | --- |
| `number` | `incidentNumberWithPrefix`, else `incidentNumber` | Text. Use the same spelling on every run: the case folder is named from it. |
| `title`, `description` | `title`, `description` | As returned |
| `declared_at` | `declaredAt`, else `createdAt` | A time with a zone. A wrapped value such as `{"_type": "DateTime", "value": "..."}` is not accepted: write the inner `value`. |
| `impact_started_at` | `impactStartedAt` | Same; omit when absent |
| `resolved_at` | No field of the incident. The state timeline. | The `startsAt` of the first timeline entry whose state has `isResolvedState` true. Omit when there is none. |
| `state` | `currentIncidentState`, resolved by call 2 | The state `name` |
| `severity` | `incidentSeverity`, resolved by call 3 | The severity `name` |
| `monitors` | `monitors`, resolved by call 4 | Objects `{"name": ..., "type": ..., "target": ...}`. `target` must be a plain URL or host name: take it from inside `monitorSteps` (the request URL of the first step). An object there is ignored by the matching. |
| `labels` | `labels`, resolved by call 5 | A list of the label names, as text. A list of objects is refused. |
| `hostnames` | Host names of the monitor targets | Optional: `case init` also reads them from `monitors[].target` |
| `timeline` | The state timeline of call 6 | Objects `{"time": <startsAt>, "text": "<state name>"}` |
| `notes` | Call 7 | Objects `{"time": <createdAt or postedAt>, "text": <note>}` |
| `url` | No field | The configured `oneuptime.url` (see `config/triage-config.yaml`), then `/incident/<_id>`. Write the link only when that URL is set. |

## 4. A worked example

The calls for incident 1042 (invented values), then the file they give.

```text
list_incidents  query {"incidentNumber": 1042}  limit 1
  -> _id 7d1c0a52-0000-4000-8000-00000000000a, title "Checkout API is down", declaredAt "2026-10-04T10:45:00.000Z",
     impactStartedAt "2026-10-04T10:42:00.000Z", currentIncidentState {"_id": "5e5e0000-0000-4000-8000-0000000000a1"},
     incidentSeverity {"_id": "5e5e0000-0000-4000-8000-0000000000b1"}, monitors [{"_id": "5e5e0000-0000-4000-8000-0000000000c1"}],
     labels [{"_id": "5e5e0000-0000-4000-8000-0000000000d1"}]
get_incident_state a1 -> "Identified", isResolvedState false      get_incident_severity b1 -> "Critical"
get_monitor c1 -> name "Checkout API", monitorSteps ... request URL "https://checkout.example.com/health"
get_label d1 -> "checkout"
list_incident_state_timelines -> 10:45:00Z "Created", 11:20:00Z "Resolved" (isResolvedState true)
```

```json
{
  "number": "1042",
  "title": "Checkout API is down",
  "url": "https://oneuptime.example.com/incident/7d1c0a52-0000-4000-8000-00000000000a",
  "description": "The checkout API health monitor fails; customers cannot pay.",
  "severity": "Critical",
  "state": "Identified",
  "declared_at": "2026-10-04T10:45:00Z",
  "impact_started_at": "2026-10-04T10:42:00Z",
  "resolved_at": "2026-10-04T11:20:00Z",
  "monitors": [{"name": "Checkout API", "type": "API", "target": "https://checkout.example.com/health"}],
  "labels": ["checkout"],
  "hostnames": ["checkout.example.com"],
  "timeline": [
    {"time": "2026-10-04T10:45:00Z", "text": "Created"},
    {"time": "2026-10-04T11:20:00Z", "text": "Resolved"}
  ],
  "notes": []
}
```

## 5. When a call returns another shape

- A relation comes back as an id and the tool to resolve it is missing or fails: leave `state` or `severity` out and say so in `open_questions`.
- A time cannot be read (`declared_at: cannot parse time: <value>`): take the plain time text out of the wrapped value. When there is none, use `createdAt`; when that fails too, stop and ask the engineer.
- No monitor target can be read: write the monitor without `target` and add a `hostnames` entry only if a host name appears in the incident text.
- The number finds no incident, or several: ask the engineer.
- Every gap you leave goes into `open_questions` of `report.json` as one sentence that names the field and the call.
