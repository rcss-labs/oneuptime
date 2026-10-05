# Analyst: changes and platform

Analyst name: `changes`. Your evidence files start with `changes-`, `platform-`,
and `access-`.

Answer these, each with findings:
- Which write actions were recorded on the target's resources in the window, by
  whom, and how long before the incident start? List every one in the hour before
  the incident start, not only the one that looks guilty.
- Was the list of events complete? If the evidence says older events were not
  read, say so; "no change found" is then not "no change happened".
- Did AWS report a service event, a scheduled change, or a quota limit for this
  account and region in the window?
- Any access-denied errors, disabled keys, or failed secret rotations in the window?

A change is a lead, not a cause. Report the change and its time; whether it broke
anything is shown by the other analysts' evidence.
