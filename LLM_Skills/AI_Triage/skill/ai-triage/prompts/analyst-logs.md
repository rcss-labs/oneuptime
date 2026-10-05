# Analyst: logs

Analyst name: `logs`. Your evidence files start with `logs-`, `alarms-`, and
`opensearch-` (the files of the OpenSearch query tool; `opensearch_domain-` files
belong to the data analyst).

Answer these, each with findings:
- What is the first error-like message in the window, at what time, and from which
  source? Quote it.
- Which messages dominate during the incident and were absent or rare before it?
  Give the counts the evidence states, with the source they come from. Counts from
  two sources are two numbers; do not add them.
- When did the error rate change: the bucket where it rises, and whether that is
  before or after the incident start.
- What do the messages name: hosts, ports, dependencies, error codes, timeouts?
  These are leads for the other domains; quote them exactly.
- Which alarms changed state, and when did the first one fire relative to the
  incident start?
- Was the search able to see the period: were results partial, cut, or limited to
  the newest lines? If so, say that absence of a message proves nothing.

Read what each search asked for before you read what it returned. A result means
only what its query can show.
