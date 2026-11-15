# Detection rules

Sentinel ships eight versioned rules. Matches are indicators with supporting event IDs and the thresholds used for evaluation; they are not findings of confirmed compromise. Rules are pure functions over an ordered, bounded SQLite event window.

| Rule ID                           | Default                              | Grouping                                           | Indicator                                                                          |
| --------------------------------- | ------------------------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `ssh.repeated_failures`           | 5 failures / 5 minutes               | Source IP                                          | Repeated OpenSSH authentication failure events.                                    |
| `ssh.username_spray`              | 8 distinct usernames / 10 minutes    | Source IP                                          | Failed SSH authentication across many observed usernames.                          |
| `ssh.failure_then_success`        | 15 minutes                           | Source IP and username                             | An SSH success follows one or more failures for the same observed IP and username. |
| `auth.burst`                      | 20 authentication events / 5 minutes | Source IP                                          | A short-term burst of authentication events.                                       |
| `sudo.repeated_failures`          | 3 failures / 10 minutes              | Host and username, or host when username is absent | Repeated sudo authentication failure messages.                                     |
| `privilege.sudo_session_sequence` | 10 minutes                           | Host                                               | A sudo-command indicator precedes a session-open indicator on the same host.       |
| `auth.out_of_hours`               | 22:00–06:00 UTC                      | User, IP or host                                   | A successful authentication indicator outside the configured UTC hours.            |
| `event.threshold_breach`          | 25 events / 5 minutes                | IP, username, host or source                       | A configured event category exceeds a count threshold.                             |

Thresholds are stored in SQLite and can be changed without adding executable rule code:

```sh
node dist/bin/sentinel.js rules list
node dist/bin/sentinel.js rules disable ssh.username_spray
node dist/bin/sentinel.js rules tune ssh.repeated_failures --thresholds '{"count":8,"windowMs":600000}'
```

Thresholds are validated against rule-specific names and bounds. `windowMs` is limited to seven days, `count` to 100,000, and UTC hours to 0–23. Unknown fields and out-of-range values are rejected. Re-enabling a rule preserves its tuned values.

## Alert generation

Alerts deduplicate by `(ruleId, entity key)`. New supporting evidence increments occurrences; re-evaluating the same evidence does not. New evidence reopens a resolved alert. Each alert retains its first/last seen times, severity, rationale, thresholds and linked event IDs. Analyst notes are stored separately from rule state.

Detection uses bounded windows. If the event or byte cap is exceeded, evaluation fails visibly and the ingestion checkpoint is not advanced; matches are not silently discarded.
