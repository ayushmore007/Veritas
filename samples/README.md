# Sample capture

`sample-run.pcapng` is one complete lab run: **5 QUIC/HTTP-3 flows** (2 benign: `browse`, `stream`;
3 malicious: `c2_beacon`, `scan_probe`, `data_exfil`), recorded on loopback by this repository's testbed.

- Upload it in the website's **ML Flow Detector** tab or the app's **ML Detector** tab, or:
  `curl -F file=@samples/sample-run.pcapng http://localhost:8000/api/v1/analyze/pcap`
- Expected: 5 flows, **3 malicious / 2 benign** (server port 4433 = benign, 4434/4435 = malicious; the
  model never sees ports, they are only how you can check the answer).
- It comes from the **held-out test split** (the shipped model never trained on it), but it is still
  synthetic lab traffic from the same generator, so a correct result shows the pipeline works, not
  that the model is accurate on real networks.
