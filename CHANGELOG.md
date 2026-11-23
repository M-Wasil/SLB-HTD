# Change log

Last reviewed: 2026-11-24. Review after major project changes.

## Unreleased

### Added

- Automatic Matplotlib E1–E4 chart generation (`experiments/figures/*.png`) directly from measured CSVs in `analyze_results.py` (disable with `--no-plots`).
- Full 9-page submission-ready measured technical report (`output/pdf/SLB_HTD_Technical_Report.pdf`) incorporating all measured E1–E4 summary tables (Mean ± SD, Min, Max, p50, p95, p99), measured charts, topology diagram, and honest baseline bottleneck analysis.
- Unit test coverage for epoch-stamped HAProxy `DOWN` log parsing (`test_analyze_results.py`).
- Project context, architecture handoff, and interactive browser simulator (`simulator/`).

### Fixed

- **Client ephemeral port exhaustion (`setup_topology.bash`):** Widened `net.ipv4.ip_local_port_range="1024 65535"`, enabled `net.ipv4.tcp_tw_reuse=1`, and raised `net.core.somaxconn=4096` inside `ns-client` and `ns-lb`.
- **HAProxy E3 detection timestamps (`run_experiments.bash`):** Wrapped HAProxy stdout/stderr with an inline `[EPOCH=...]` line timestamper so `analyze_results.py` computes HAProxy's exact `DOWN` detection time in future runs.
- **HTTP protocol & health-check edge cases (`slb.py`):** Added explicit `405 Method Not Allowed` (non-`GET`) and `501 Not Implemented` (body-bearing requests) guards, prevented mid-stream `502` injection after response bytes have started streaming (`response_started` flag), and enforced a single total 500 ms deadline per `/health` probe.
- **Live `.pcapng` capture naming (`run_poc_demo.bash`):** Updated live captures to save `.pcapng` files (`c1_client_to_lb.pcapng`, `c2_dmz_to_lb.pcapng`, `c3_backend_bridge_normal_and_health.pcapng`, `c3_failover_and_recovery.pcapng`), save `routing_verification.txt`, and clean up background processes on exit.
