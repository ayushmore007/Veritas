"""Integration test for Phase 1 traffic generation (requires UDP loopback)."""

import pytest

pytest.importorskip("aioquic")

from veritas.testbed.orchestrator import LabOrchestrator


@pytest.mark.asyncio
@pytest.mark.slow
async def test_generate_all_scenarios():
    orch = LabOrchestrator()
    cert, key = orch.ensure_certs()
    ca_path = orch.certs_dir / "ca.crt"
    servers = await orch.start_servers(cert, key)
    try:
        records = await orch.run_all_scenarios(ca_path=ca_path)
    finally:
        await orch.stop_servers(servers)

    assert len(records) == 5
    classes = {r.traffic_class.value for r in records}
    assert classes == {"benign", "malicious"}
    attacks = {r.attack_type.value for r in records if r.attack_type}
    assert attacks == {"c2_beacon", "data_exfil", "scan_probe"}
