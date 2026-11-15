# Performance procedure and baseline

## Procedure

Build the project and run the synthetic benchmark:

```sh
npm run bench -- 1000
```

The optional argument is an event count from 1 to 10,000. The script creates a temporary NDJSON source and SQLite database, imports the records through the configured bounded queue and detection engine, measures elapsed time and detection durations, samples process RSS, reports database growth, then removes the temporary directory. The corpus contains synthetic authentication success/failure indicators and no real security data.

The reported throughput includes parsing, event storage, detection and checkpoint writes. Mean detection latency is the measured time in `DetectionEngine.evaluateAt` per event. RSS is process-wide and sampled during ingestion; database bytes include the main file and any SQLite WAL/SHM sidecars that remain after a clean close.

## Recorded baseline

Measured on 14 November 2026 in the available Linux x86_64 environment (12 logical CPUs), using Node.js `v26.3.1` and SQLite `3.53.4`. This is a local synthetic baseline, not a production workload or a Node.js 24 measurement.

| Metric                                         |               Result |
| ---------------------------------------------- | -------------------: |
| Synthetic records                              |                1,000 |
| Input file size                                |        342,302 bytes |
| Records parsed and stored                      | 1,000 / 1,000 (100%) |
| Parser failures                                |                    0 |
| Total ingestion, detection and checkpoint time |          5,240.04 ms |
| Throughput                                     |      190.84 events/s |
| Detection evaluations                          |                1,000 |
| Total detection evaluation time                |          4,702.03 ms |
| Mean detection latency                         | 4.7020 ms/evaluation |
| Starting process RSS                           |     58,400,768 bytes |
| Peak sampled process RSS                       |    118,628,352 bytes |
| Database size after clean close                |      1,933,312 bytes |
| Database growth                                | 1,933.31 bytes/event |

The event timestamps fall within a compact synthetic period so the default bounded detection windows are exercised. Rules, filesystem cache, Node.js version, virtualisation and the host CPU model affect results; compare measurements only under similar conditions. The detection event/byte caps deliberately fail with a visible source-health error instead of dropping matches.
