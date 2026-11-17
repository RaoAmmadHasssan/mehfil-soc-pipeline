# Detection Rules: Mehfil Event Planners (Task 2)

Two custom Elastic Security detection rules (EQL) for SSH brute-force detection,
running on the `ssh-auth-*` index.

## Rules

| # | Rule | Severity | Risk |
|---|---|---|---|
| 1 | SSH Brute Force: 6+ Failed Logins from One IP in 60s | High | 73 |
| 2 | SSH Brute Force Followed by Successful Login | **Critical** | 99 |

### Rule 1: brute force

Threshold: more than 5 (so 6 or more) failed logins from a single IP within 60 seconds.

```
sequence by source.ip with maxspan=60s
  [ any where event.outcome == "failure" ] with runs=5
  [ any where event.outcome == "failure" ]
```

### Rule 2: brute force followed by success (possible compromise)

Six failed logins followed by a successful login from the same IP within 30 minutes.

```
sequence by source.ip with maxspan=30m
  [ any where event.outcome == "failure" ] with runs=6
  [ any where event.outcome == "success" ]
```

The 30-minute window is wider than Rule 1 because an attacker often succeeds some
minutes after the burst ends (in the test data the burst ends about 03:26 and the
login happens at 03:40).

Both rules run every 5 minutes. The additional look-back is 240 hours so that the
test data (15 Nov 2026) is covered. In production it would be 1 to 2 minutes.

## MITRE ATT&CK mapping

| Rule | Tactic | Technique | ID |
|---|---|---|---|
| 1 | Credential Access (TA0006) | Brute Force | T1110 |
| 1 | Credential Access (TA0006) | Brute Force: Password Guessing | T1110.001 |
| 2 | Credential Access (TA0006) | Brute Force: Password Guessing | T1110.001 |
| 2 | Initial Access (TA0001) | Valid Accounts | T1078 |

Why: the attacker tries many usernames and passwords against SSH from one IP, which is
password guessing (T1110.001). In Rule 2 the attacker then logs in with a working
account, which is use of Valid Accounts (T1078).

## ECS fields used

| Field | Meaning |
|---|---|
| `source.ip` | Attacking IP (type `ip`) |
| `event.outcome` | `failure` or `success` |
| `event.category` | `authentication` |
| `user.name` | Account that was tried |
| `host.name` | `mehfil-booking` |
| `process.name` | `sshd` |

Logstash maps the raw fields (`src_ip`, `outcome`) to ECS and keeps the old fields,
so the Task 1 dashboard still works.

## Test against the synthetic log

Data: 253 events (245 failed, 8 successful) for 15 Nov 2026.

| Source IP | Failed logins | Result |
|---|---|---|
| 185.220.101.45 | 120 | Rule 1 alerts, plus 1 **Critical** alert from Rule 2 (successful login as `admin`) |
| 45.155.205.233 | 75 | Rule 1 alerts (70) |
| 103.151.122.18 | 40 | Rule 1 alerts (35) |
| 192.168.1.x (staff) | 10 typos in total | No alerts (false positives: 0) |

Total: 221 alerts (220 High, 1 Critical).

Alerts per attacker are `failed logins minus 5`, because the EQL sequence slides one
login at a time. This is noisy but correct.

## Limitations

- Test data is synthetic, so real traffic can need threshold tuning.
- Alert suppression is not available in this license, so one attacker produces many alerts.
- No notification actions (email, Slack) are configured. Alerts show in Kibana only.
- Lab only: Logstash uses the `elastic` superuser. A real deployment needs a write-only user.
