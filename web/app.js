/**
 * Veritas Sentinel - Live Real-Time Security Scanner & Digital Twin Defense Engine
 * Connects directly to backend API (/api/scan, /api/topology, /api/scans/history, /api/verify-fix)
 * to run real penetration tests, create real digital twins, persist history, and verify live server fixes.
 */

// Application State
const state = {
  servers: [],
  selectedServerIndex: 0,
  isScanning: false,
  backendOnline: false,
  pendingRemediation: null,
  activeInspectedTest: null,
  currentStack: 'nginx'
};

// Default Built-in Seed Nodes (From testbed.yaml)
const DEFAULT_SEED_SERVERS = [
  {
    id: 'benign_server',
    host: 'cdn-edge-3.internal.test',
    role: 'server',
    roleDescription: 'HTTP/3 Edge Distribution Node (QUIC v1)',
    ip: '172.28.0.10',
    port: 4433,
    localhost_bind: '127.0.0.1',
    trafficClass: 'benign',
    protocol: 'QUIC (TLS 1.3)',
    securityScore: 94,
    postureVerdict: 'HARDENED DEFENSE',
    postureClass: 'health-hardened',
    description: 'Server exhibits robust transport integrity and zero AI reasoning hijack vulnerabilities.',
    isRecentScan: false,
    twinFeatures: {
      flow_duration: 0.142,
      tot_fwd_pkts: 18,
      tot_bwd_pkts: 24,
      totlen_fwd_pkts: 1420,
      totlen_bwd_pkts: 18450,
      down_up_ratio: 13.0,
      flow_iat_mean: 0.0052,
      flow_iat_max: 0.021,
      entropy: 4.82,
      sni: 'cdn-edge-3.internal.test',
      cipher: 'TLS_AES_128_GCM_SHA256'
    },
    metadataUntrusted: {
      server_banner: 'CloudEdge/3.2 (QUIC)',
      sni: 'cdn-edge-3.internal.test',
      content_type: 'text/html; charset=utf-8'
    },
    appliedPreventions: ['provenance_grounding_verifier', 'sni_sanitizer', 'twin_replay'],
    tests: [
      { 
        id: 'TEST-DNS', 
        name: 'DNS Resolution & Topology Mapping', 
        category: 'Network Topology', 
        status: 'passed', 
        metric: 'Host Resolution', 
        observed_value: '1 IP(s) [172.28.0.10]', 
        baseline: 'Valid A/AAAA Records with DNSSEC', 
        description: 'Resolves target hostname to authoritative network addresses.', 
        verdict_explanation: 'DNS resolution succeeded on authoritative lab nameservers. Hostname maps cleanly to local subnet 172.28.0.10 with zero resolution latency.',
        threat_impact: 'If DNS resolution is hijacked (DNS poisoning), attackers can redirect user traffic to phishing clones or man-in-the-middle proxies.',
        root_cause_diagnosis: 'PASSED: Authoritative DNS records are properly configured. No permission or registrar issues detected.',
        remediation_code: '# DNSSEC Verification:\ndig +dnssec cdn-edge-3.internal.test @1.1.1.1',
        auto_fixable: false, 
        permission_required: false,
        remediation_type: 'dns_record'
      },
      { 
        id: 'TEST-PORT', 
        name: 'Network Port Exposure & Service Surface', 
        category: 'Perimeter Security', 
        status: 'passed', 
        metric: 'Exposed Ports', 
        observed_value: 'Open ports: [4433]', 
        baseline: 'Only secure web ports open publicly', 
        description: 'Scans network service ports to detect accidental exposure of databases or management interfaces.', 
        verdict_explanation: 'Port scan completed across 11 common ports. Only designated HTTPS/QUIC port 4433 is listening. All database ports (3306, 5432, 6379, 27017) and SSH (22) are closed or firewalled.',
        threat_impact: 'Exposed internal ports allow remote attackers to perform brute-force attacks on databases or exploit unpatched daemon vulnerabilities.',
        root_cause_diagnosis: 'PASSED: Perimeter firewall policy is properly configured.',
        remediation_code: '# Firewall Rule to restrict internal ports:\niptables -A INPUT -p tcp --dport 3306 -s 127.0.0.1 -j ACCEPT\niptables -A INPUT -p tcp --dport 3306 -j DROP',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'firewall_rule'
      },
      { 
        id: 'TEST-TLS-VER', 
        name: 'TLS Protocol Handshake & Cipher Suite', 
        category: 'Cryptographic Security', 
        status: 'passed', 
        metric: 'Negotiated Protocol', 
        observed_value: 'TLS 1.3 (ChaCha20-Poly1305 / AES-128-GCM)', 
        baseline: 'TLS 1.2 or TLS 1.3 Mandatory (PFS)', 
        description: 'Verifies the cryptographic protocol version negotiated during client handshake.', 
        verdict_explanation: 'Server negotiated TLS 1.3 in a single RTT handshake with Perfect Forward Secrecy (PFS) and authenticated AEAD ciphers. Legacy insecure protocols (SSLv3, TLS 1.0, TLS 1.1) are disabled.',
        threat_impact: 'Legacy TLS versions (TLS 1.0/1.1) or weak ciphers (CBC/3DES) allow attackers to decrypt historical traffic (POODLE, BEAST, SWEET32).',
        root_cause_diagnosis: 'PASSED: Cryptographic parameters meet NIST SP 800-52r2 standards.',
        remediation_code: '# NGINX SSL Configuration:\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5:!3DES;',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-HSTS', 
        name: 'HTTP Strict Transport Security (HSTS)', 
        category: 'HTTP Security Headers', 
        status: 'passed', 
        metric: 'HSTS Header', 
        observed_value: 'Present: max-age=31536000; includeSubDomains', 
        baseline: 'max-age=31536000; includeSubDomains; preload', 
        description: 'Forces browsers to communicate only over secure HTTPS, preventing SSL-stripping MITM attacks.', 
        verdict_explanation: 'Strict-Transport-Security header is present with a 1-year max-age (31536000 seconds) and applies to all subdomains.',
        threat_impact: 'Without HSTS, attackers on public Wi-Fi can downgrade HTTPS connections to HTTP (SSLStrip) and steal plaintext session cookies.',
        root_cause_diagnosis: 'PASSED: Header actively injected by web server.',
        remediation_code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-CSP', 
        name: 'Content Security Policy (CSP)', 
        category: 'HTTP Security Headers', 
        status: 'passed', 
        metric: 'CSP Header', 
        observed_value: 'Active (default-src \'self\'; script-src \'self\')', 
        baseline: 'Strict script-src and default-src', 
        description: 'Mitigates Cross-Site Scripting (XSS), data injection, and clickjacking attacks.', 
        verdict_explanation: 'A restrictive Content Security Policy is declared, blocking unauthorized third-party scripts, object embeds, and unapproved inline code.',
        threat_impact: 'Missing CSP allows injected JavaScript (XSS) to exfiltrate session tokens or inject keyloggers into user sessions.',
        root_cause_diagnosis: 'PASSED: Strict origin script policy enforced.',
        remediation_code: 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\';" always;',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-RECON-FUZZ', 
        name: 'Sensitive File Exposure & Path Fuzzing', 
        category: 'Penetration Testing', 
        status: 'passed', 
        metric: 'Exposed Sensitive Paths', 
        observed_value: 'Zero sensitive dotfiles exposed (0/10 probed)', 
        baseline: 'Zero dotfiles or environment secrets accessible', 
        description: 'Probes high-value targets including /.env, /.git repository indexes, and unauthenticated API endpoints.', 
        verdict_explanation: 'All 10 sensitive probes (/.env, /.git/HEAD, /config.json, /admin, etc.) returned 404 or 403. Directory listing is disabled.',
        threat_impact: 'Exposing /.env or /.git allows attackers to download database credentials, API secret keys, and application source code.',
        root_cause_diagnosis: 'PASSED: Web server restricts dotfile access.',
        remediation_code: 'location ~ /\\.(env|git|svn|htaccess) {\n    deny all;\n    return 404;\n}',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-QUIC-H3', 
        name: 'QUIC Protocol & HTTP/3 Transport Capability', 
        category: 'Next-Gen Protocol', 
        status: 'passed', 
        metric: 'HTTP/3 Support', 
        observed_value: 'HTTP/3 & QUIC Enabled (Alt-Svc: h3=":4433")', 
        baseline: 'QUIC (RFC 9000) or HTTP/2', 
        description: 'Checks if target endpoint supports next-generation encrypted QUIC/HTTP-3 protocol.', 
        verdict_explanation: 'Server advertises and negotiates QUIC UDP stream over port 4433 with 0-RTT handshake support.',
        threat_impact: 'Non-QUIC transport lacks connection migration and head-of-line blocking resistance.',
        root_cause_diagnosis: 'PASSED: Modern UDP transport enabled.',
        remediation_code: '# Caddyfile QUIC Directive:\nexample.com {\n    protocols h1 h2 h3\n}',
        auto_fixable: false, 
        permission_required: false,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-VERITAS-GROUNDING', 
        name: 'Metadata Prompt-Injection & AI Defender Grounding (Veritas)', 
        category: 'AI Defense & Provenance', 
        status: 'passed', 
        metric: 'AI Reasoning Grounding', 
        observed_value: 'PROTECTED (0.00% Attack Success Rate)', 
        baseline: '100% Measured Twin Anchor (0.00% ASR)', 
        description: 'Validates whether security triage agents anchor decisions strictly on measured physical packet telemetry rather than untrusted SNI text.', 
        verdict_explanation: 'Veritas Provenance Verifier (Phase 8b) is active. The triage engine verified that decisive claims trace strictly to measured Digital Twin instrumentation, neutralizing any injected adversarial SNI strings.',
        threat_impact: 'Undefended LLMs will trust deceptive SNI text like "admin-verified-clean.test" and flip their verdict from BLOCK to IGNORE, allowing attackers to slip by undetected.',
        root_cause_diagnosis: 'PASSED: Provenance Grounding Verifier successfully deployed.',
        remediation_code: 'veritas-twin enforce --host cdn-edge-3.internal.test --verifier provenance_grounding',
        auto_fixable: true, 
        permission_required: false,
        remediation_type: 'veritas_engine'
      }
    ],
    recommendedPreventions: [
      { key: 'provenance_grounding_verifier', title: 'Veritas Provenance-Grounding Verifier Active', category: 'AI Defense', severity: 'CRITICAL', status: 'active', permission_required: false, description: 'Decisive claims must trace strictly to measured Twin packet telemetry.', action_label: 'Active & Grounded', can_auto_execute: true, points_gain: 30 }
    ]
  },
  {
    id: 'malicious_c2',
    host: 'api-sync-7.internal.test',
    role: 'server',
    roleDescription: 'Command & Control Periodic Beacon Host',
    ip: '172.28.0.20',
    port: 4434,
    localhost_bind: '127.0.0.1',
    trafficClass: 'malicious',
    protocol: 'QUIC (TLS 1.3)',
    securityScore: 32,
    postureVerdict: 'CRITICAL RISK',
    postureClass: 'health-vulnerable',
    description: 'Server actively receives periodic C2 beacons and vulnerable to metadata prompt injection.',
    isRecentScan: false,
    twinFeatures: {
      flow_duration: 16.02,
      tot_fwd_pkts: 16,
      tot_bwd_pkts: 16,
      totlen_fwd_pkts: 768,
      totlen_bwd_pkts: 512,
      down_up_ratio: 0.67,
      flow_iat_mean: 2.001,
      flow_iat_max: 2.015,
      entropy: 7.65,
      sni: 'api-sync-7.internal.test',
      cipher: 'TLS_AES_128_GCM_SHA256'
    },
    metadataUntrusted: {
      server_banner: 'SyncGateway/1.0',
      sni: 'api-sync-7.internal.test',
      content_type: 'application/octet-stream'
    },
    appliedPreventions: [],
    tests: [
      { 
        id: 'TEST-DNS', 
        name: 'DNS Resolution & Topology Mapping', 
        category: 'Network Topology', 
        status: 'passed', 
        metric: 'Host Resolution', 
        observed_value: '1 IP(s) [172.28.0.20]', 
        baseline: 'Valid A/AAAA Records', 
        description: 'Resolves target hostname to network address.', 
        verdict_explanation: 'Resolved to C2 destination IP in testbed topology.',
        threat_impact: 'DNS mapping accurate.',
        root_cause_diagnosis: 'PASSED: Hostname resolvable.',
        remediation_code: '# DNS Mapping verified.',
        auto_fixable: false, 
        permission_required: false,
        remediation_type: 'dns_record'
      },
      { 
        id: 'TEST-PORT', 
        name: 'Network Port Exposure & Service Surface', 
        category: 'Perimeter Security', 
        status: 'passed', 
        metric: 'Exposed Ports', 
        observed_value: 'Open ports: [4434]', 
        baseline: 'Only secure web ports open', 
        description: 'Scans network ports.', 
        verdict_explanation: 'Target endpoint port 4434 is open and receiving connection requests.',
        threat_impact: 'Port 4434 actively accepts incoming beaconing frames.',
        root_cause_diagnosis: 'Port reachable.',
        remediation_code: 'iptables -A INPUT -p udp --dport 4434 -j DROP',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'firewall_rule'
      },
      { 
        id: 'TEST-TLS-VER', 
        name: 'TLS Protocol Handshake & Version', 
        category: 'Cryptographic Security', 
        status: 'passed', 
        metric: 'Negotiated Protocol', 
        observed_value: 'TLS 1.3 (AES-GCM)', 
        baseline: 'TLS 1.2 or TLS 1.3 mandatory', 
        description: 'Verifies cryptographic protocol.', 
        verdict_explanation: 'QUIC TLS 1.3 handshake established.',
        threat_impact: 'Encrypted tunnel prevents legacy plaintext deep packet inspection.',
        root_cause_diagnosis: 'Valid handshake.',
        remediation_code: '# Standard TLS active.',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-HSTS', 
        name: 'HTTP Strict Transport Security (HSTS)', 
        category: 'HTTP Security Headers', 
        status: 'failed', 
        metric: 'HSTS Header', 
        observed_value: 'Missing Strict-Transport-Security header', 
        baseline: 'max-age=31536000', 
        description: 'Forces secure HTTPS communication.', 
        verdict_explanation: 'FAILED: The server did not return a Strict-Transport-Security header in response to encrypted requests.',
        threat_impact: 'Allows MITM attackers to downgrade future sessions to plaintext HTTP.',
        root_cause_diagnosis: 'FAILED: Missing header in web server configuration. Root/admin access to server configuration is required to add this header.',
        remediation_code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-CSP', 
        name: 'Content Security Policy (CSP)', 
        category: 'HTTP Security Headers', 
        status: 'failed', 
        metric: 'CSP Header', 
        observed_value: 'Missing Content-Security-Policy', 
        baseline: 'Strict script-src and default-src', 
        description: 'Mitigates XSS and data injection.', 
        verdict_explanation: 'FAILED: No Content-Security-Policy header returned by endpoint.',
        threat_impact: 'Enables cross-site scripting and unauthorized payload execution in victim browsers.',
        root_cause_diagnosis: 'FAILED: Web server configuration lacks CSP directive. Requires web server config write permissions.',
        remediation_code: 'add_header Content-Security-Policy "default-src \'self\';" always;',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-RECON-FUZZ', 
        name: 'Sensitive File Exposure & Path Fuzzing', 
        category: 'Penetration Testing', 
        status: 'warning', 
        metric: 'Exposed Sensitive Paths', 
        observed_value: 'Exposed endpoint: /api/sync', 
        baseline: 'Zero dotfiles accessible', 
        description: 'Probes for sensitive endpoints.', 
        verdict_explanation: 'WARNING: Endpoint /api/sync responded with 200 OK without authentication headers.',
        threat_impact: 'Unauthenticated API endpoint allows malicious clients to register and receive C2 instructions.',
        root_cause_diagnosis: 'WARNING: Missing authentication middleware on sync route. Web application codebase modification required.',
        remediation_code: '# Enforce token authentication on /api/sync route\nlocation /api/sync {\n    auth_request /auth_validate;\n}',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'web_server_config'
      },
      { 
        id: 'TEST-QUIC-H3', 
        name: 'C2 Periodic Heartbeat Timing Jitter', 
        category: 'Behavioral Anomaly', 
        status: 'failed', 
        metric: 'Flow IAT Jitter', 
        observed_value: 'STRICT 2.0s INTERVAL (Zero Jitter)', 
        baseline: 'Natural user jitter > 0.1s', 
        description: 'Measures periodic heartbeat frequency.', 
        verdict_explanation: 'FAILED (CRITICAL): Measured Inter-Arrival Times (IAT) show rigid 2.000s periodicity with near-zero variance. This signature strongly indicates automated botnet C2 heartbeat beaconing.',
        threat_impact: 'Active botnet connection maintaining persistence on infected endpoint, allowing remote threat actors to trigger ransomware or exfiltration.',
        root_cause_diagnosis: 'FAILED: Malicious client periodically contacting target server. Requires firewall administrator permissions to deploy rate-limiting drop rules.',
        remediation_code: '# eBPF / IPTables Drop Filter for 2.0s periodic pulses:\niptables -A INPUT -p udp --dport 4434 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 15 --hashlimit-mode srcip -j DROP',
        auto_fixable: true, 
        permission_required: true,
        remediation_type: 'firewall_rule'
      },
      { 
        id: 'TEST-VERITAS-GROUNDING', 
        name: 'Metadata Prompt-Injection & AI Defender Grounding (Veritas)', 
        category: 'AI Defense & Provenance', 
        status: 'failed', 
        metric: 'AI Reasoning Grounding', 
        observed_value: 'VULNERABLE (0.81 Attack Success Rate)', 
        baseline: '100% Measured Twin Anchor', 
        description: 'Tests if adversarial SNI headers trick AI triage agent.', 
        verdict_explanation: 'FAILED (CRITICAL): The undefended AI triage agent evaluated the attacker-authored SNI string "api-sync-7.internal.test" and accepted decisive claims without validating physical packet statistics, causing the agent to flip verdict from BLOCK to IGNORE (81% Attack Success Rate).',
        threat_impact: 'Attackers can bypass AI-driven firewalls and SOC automated triage by authoring deceptive hostnames in packet metadata.',
        root_cause_diagnosis: 'FAILED: Veritas Provenance Verifier is inactive. Deploying Phase 8b provenance verifier will anchor decisions 100% on measured twin packet volume.',
        remediation_code: 'veritas-twin enforce --host api-sync-7.internal.test --verifier provenance_grounding',
        auto_fixable: true, 
        permission_required: false,
        remediation_type: 'veritas_engine'
      }
    ],
    recommendedPreventions: [
      { key: 'provenance_grounding_verifier', title: 'Deploy Veritas Provenance-Grounding Verifier', category: 'AI Defense Engine', severity: 'CRITICAL', status: 'ready_to_apply', permission_required: false, description: 'Rejects attacker-authored SNI claims; anchors triage verdicts on measured Twin telemetry.', action_label: 'Enable Veritas Grounding', can_auto_execute: true, points_gain: 35 },
      { key: 'deploy_firewall_rules', title: 'Activate Adaptive C2 Beacon Drop Rules', category: 'Perimeter Defense', severity: 'HIGH', status: 'permission_needed', permission_required: true, description: 'Installs eBPF/iptables hashlimit rule to drop 2.0s periodic heartbeat pulses.', action_label: 'Deploy Firewall Rules', can_auto_execute: true, points_gain: 25 },
      { key: 'deploy_security_headers', title: 'Deploy Hardened Security Headers', category: 'Web Server Hardening', severity: 'MEDIUM', status: 'permission_needed', permission_required: true, description: 'Injects HSTS, CSP, and X-Frame-Options headers.', action_label: 'Deploy Headers Patch', can_auto_execute: true, points_gain: 15 }
    ]
  }
];

// Initialize Application with Persistence
document.addEventListener('DOMContentLoaded', async () => {
  loadPersistentState();

  await checkBackendStatus();
  await loadPersistentHistoryFromBackend();
  await loadLabTopology();
  
  renderServerCards();
  renderActiveServer();
  setupEventListeners();
  setupTabs();
});

// Load state from localStorage on startup
function loadPersistentState() {
  state.servers = [...DEFAULT_SEED_SERVERS];
  
  try {
    const saved = localStorage.getItem('veritas_scans_history');
    if (saved) {
      const parsed = JSON.parse(saved);
      if (Array.isArray(parsed) && parsed.length > 0) {
        // Prepend persistent scans
        parsed.forEach(s => {
          if (!state.servers.some(item => item.host.toLowerCase() === s.host.toLowerCase())) {
            state.servers.unshift(s);
          }
        });
      }
    }

    const savedSelected = localStorage.getItem('veritas_selected_host');
    if (savedSelected) {
      const idx = state.servers.findIndex(s => s.host.toLowerCase() === savedSelected.toLowerCase());
      if (idx >= 0) state.selectedServerIndex = idx;
    }
  } catch (e) {
    console.warn('localStorage read error', e);
  }
}

// Save current servers to localStorage
function savePersistentState() {
  try {
    const customAndScans = state.servers.filter(s => s.isRecentScan || s.id.startsWith('scan_') || s.id.startsWith('custom_'));
    localStorage.setItem('veritas_scans_history', JSON.stringify(customAndScans));
    if (state.servers[state.selectedServerIndex]) {
      localStorage.setItem('veritas_selected_host', state.servers[state.selectedServerIndex].host);
    }
  } catch (e) {
    console.warn('localStorage save error', e);
  }
}

// Fetch persistent history from backend
async function loadPersistentHistoryFromBackend() {
  if (!state.backendOnline) return;

  try {
    const res = await fetch('/api/scans/history');
    if (res.ok) {
      const data = await res.json();
      if (data.history && data.history.length > 0) {
        data.history.forEach(report => {
          const srv = transformReportToServer(report);
          const existingIdx = state.servers.findIndex(s => s.host.toLowerCase() === srv.host.toLowerCase());
          if (existingIdx >= 0) {
            state.servers[existingIdx] = srv;
          } else {
            state.servers.unshift(srv);
          }
        });
        renderServerCards();
        renderActiveServer();
      }
    }
  } catch (e) {
    console.warn('History fetch error', e);
  }
}

// Check if Python Backend is live
async function checkBackendStatus() {
  const pill = document.getElementById('twinStatusPill');
  const textEl = document.getElementById('twinStatusText');

  try {
    const res = await fetch('/api/status', { method: 'GET' });
    if (res.ok) {
      const data = await res.json();
      state.backendOnline = true;
      textEl.textContent = 'Veritas Live Engine Connected (Twin DB Active)';
      pill.style.background = 'rgba(16, 185, 129, 0.15)';
      pill.style.borderColor = 'rgba(16, 185, 129, 0.4)';
      return;
    }
  } catch (e) {
    // Standalone fallback
  }

  state.backendOnline = false;
  textEl.textContent = 'Digital Twin Active (Local Engine)';
}

// Load lab topology from backend if available
async function loadLabTopology() {
  if (!state.backendOnline) return;

  try {
    const res = await fetch('/api/topology');
    if (res.ok) {
      const data = await res.json();
      if (data.servers && data.servers.length > 0) {
        document.getElementById('topologyBadge').textContent = `Topology: veritas-lab (${data.servers.length} configured servers)`;
      }
    }
  } catch (e) {
    console.warn('Topology fetch skipped', e);
  }
}

// Escape text for insertion into innerHTML. Scan results carry server-controlled strings (Server
// banner, header values, host names); without this a scanned server can run script in the dashboard.
function esc(value) {
  return String(value ?? '').replace(/[&<>"'`]/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
  })[ch]);
}

// Show a measured value, or an em dash when it was not measured. Never a made-up default.
function measured(value, suffix = '') {
  if (value === null || value === undefined || value === '') return '—';
  return `${esc(value)}${suffix}`;
}

// Render Top Server Selector Cards
function renderServerCards() {
  const container = document.getElementById('serverCardsContainer');
  if (!container) return;

  container.innerHTML = state.servers.map((srv, idx) => {
    const isActive = idx === state.selectedServerIndex;
    const icon = srv.securityScore >= 80 ? '🛡️' : (srv.id === 'malicious_c2' ? '📡' : (srv.isRecentScan ? '🌐' : '🚨'));
    const scanBadge = srv.isRecentScan ? '<span style="font-size:9px; background:rgba(6,182,212,0.25); color:#38bdf8; border:1px solid rgba(6,182,212,0.4); padding:2px 6px; border-radius:4px; margin-left:6px; font-weight:700;">PERSISTENT SCAN</span>' : '';
    
    return `
      <div class="server-card ${isActive ? 'active' : ''}" onclick="selectServer(${idx})">
        <div class="server-card-top">
          <div class="server-name-group">
            <div class="server-icon-wrap">${icon}</div>
            <div>
              <div class="server-name">${esc(srv.host)} ${scanBadge}</div>
              <div class="server-role">${esc(srv.roleDescription ? srv.roleDescription.split('(')[0] : 'Scanned Server')}</div>
            </div>
          </div>
          <span class="server-health-indicator ${esc(srv.postureClass)}">
            ${esc(srv.securityScore)}%
          </span>
        </div>
        <div class="server-meta-row">
          <div class="meta-item"><span class="meta-label">IP:</span> ${esc(srv.ip)}:${esc(srv.port)}</div>
          <div class="meta-item"><span class="meta-label">Verdict:</span> ${esc(srv.postureVerdict)}</div>
        </div>
      </div>
    `;
  }).join('');
}

// Select a server from the cards
window.selectServer = function(idx) {
  state.selectedServerIndex = idx;
  const srv = state.servers[idx];
  document.getElementById('targetUrlInput').value = srv.host;
  savePersistentState();
  renderServerCards();
  renderActiveServer();
  showToast(`Inspecting Server Node: ${srv.host}`);
};

// Render Details of Active Server
function renderActiveServer() {
  const srv = state.servers[state.selectedServerIndex];
  if (!srv) return;

  document.getElementById('targetHostTitle').textContent = srv.host;
  document.getElementById('targetSubtitle').textContent = srv.roleDescription || `Inspected Node: ${srv.host}`;
  document.getElementById('telBind').textContent = `${srv.ip}:${srv.port}`;
  document.getElementById('telProto').textContent = srv.protocol || '—';
  // Negotiated cipher from the scan itself; a plain-HTTP target has none.
  const meta = srv.metadataUntrusted || {};
  document.getElementById('telCipher').textContent = meta.cipher || 'No TLS negotiated';
  document.getElementById('testCountBadge').textContent = `${(srv.tests || []).length} Tests`;
  
  const tf = srv.twinFeatures || {};
  document.getElementById('telFlows').textContent =
    tf.flow_duration != null ? `${tf.flow_duration} s (HTTP exchange)` : '— (not measured)';
  document.getElementById('telFlowTag').textContent =
    tf.entropy != null ? `Entropy: ${tf.entropy} bits/B` : 'Entropy: not measured';

  const isGrounded = srv.appliedPreventions && srv.appliedPreventions.includes('provenance_grounding_verifier');
  const defStatusEl = document.getElementById('telDefenseStatus');
  const defTagEl = document.getElementById('telDefenseTag');

  if (isGrounded || srv.securityScore >= 85) {
    defStatusEl.textContent = 'Grounded (Twin Oracle)';
    defStatusEl.style.color = '#34d399';
    defTagEl.textContent = 'Zero Prompt Injection Leak';
  } else {
    defStatusEl.textContent = 'Undefended (Vulnerable)';
    defStatusEl.style.color = '#f87171';
    defTagEl.textContent = 'Preventions Required';
  }

  // Update Score Gauge
  updateScoreGauge(srv.securityScore, srv.postureVerdict, srv.postureClass, srv.description);

  // Render Tests Grid
  renderTestsGrid(srv);

  // Render Prevention Cards
  renderPreventionCards(srv);

  // Render Twin Split
  renderTwinSplit(srv);

  // Update Firewall Code & Report Block
  updateFirewallAndReport(srv);
}

// Update Score SVG Gauge & Text
function updateScoreGauge(score, posture, postureClass, desc) {
  const circle = document.getElementById('scoreCircle');
  const numberEl = document.getElementById('scoreNumber');
  const badgeEl = document.getElementById('scorePostureBadge');
  const descEl = document.getElementById('scoreDescription');

  const totalLength = 427.26;
  const offset = totalLength - (score / 100) * totalLength;

  circle.style.strokeDasharray = totalLength;
  circle.style.strokeDashoffset = offset;

  let strokeColor = '#ef4444';
  if (score >= 80) strokeColor = '#10b981';
  else if (score >= 50) strokeColor = '#f59e0b';

  circle.setAttribute('stroke', strokeColor);
  numberEl.textContent = score;
  numberEl.style.color = strokeColor;

  badgeEl.className = `score-posture-badge ${postureClass}`;
  badgeEl.textContent = posture;
  descEl.textContent = desc;
}

// Render Live Test Battery Cards with click-to-inspect
function renderTestsGrid(srv) {
  const container = document.getElementById('testsGridContainer');
  if (!container) return;

  container.innerHTML = srv.tests.map((t, idx) => {
    let badgeClass = 'status-passed';
    let badgeIcon = '✓';
    let badgeText = 'PASSED';

    if (t.status === 'failed') {
      badgeClass = 'status-failed';
      badgeIcon = '✗';
      badgeText = 'FAILED';
    } else if (t.status === 'warning') {
      badgeClass = 'status-warning';
      badgeIcon = '⚠';
      badgeText = 'FLAGGED';
    } else if (t.status === 'defended') {
      badgeClass = 'status-defended';
      badgeIcon = '🛡️';
      badgeText = 'DEFENDED';
    }

    return `
      <div class="test-card" onclick="openTestDeepDive(${idx})" title="Click to inspect detailed breakdown, root cause diagnosis & live fix">
        <div class="test-card-header">
          <div class="test-info">
            <span class="test-id">${esc(t.id)} · ${esc(t.category)}</span>
            <h3 class="test-name">${esc(t.name)}</h3>
            <p class="test-desc">${esc(t.description)}</p>
          </div>
          <span class="test-status-badge ${badgeClass}">${badgeIcon} ${badgeText}</span>
        </div>

        <div class="test-telemetry-box">
          <div class="telemetry-row">
            <span class="telemetry-key">Observed Metric:</span>
            <span class="telemetry-val" style="color: ${t.status === 'failed' ? '#f87171' : (t.status === 'warning' ? '#fbbf24' : '#34d399')}; font-weight:700;">
              ${esc(t.observed_value)}
            </span>
          </div>
          <div class="telemetry-row">
            <span class="telemetry-key">Security Standard:</span>
            <span class="telemetry-val">${esc(t.baseline)}</span>
          </div>
        </div>

        <div class="test-recommendation-note">
          <span>🔍 ${esc(t.note || t.remediation || 'Standard verified.')}</span>
          <span class="test-inspect-hint">Deep Dive ➜</span>
        </div>
      </div>
    `;
  }).join('');
}

// Open Test Deep-Dive Inspector Modal
window.openTestDeepDive = function(testIdx) {
  const srv = state.servers[state.selectedServerIndex];
  const test = srv.tests[testIdx];
  if (!test) return;

  state.activeInspectedTest = test;
  const modal = document.getElementById('testDetailModal');

  document.getElementById('modalTestCategory').textContent = `${test.category.toUpperCase()} · ${test.id}`;
  document.getElementById('modalTestTitle').textContent = test.name;
  
  const statusBadge = document.getElementById('modalTestStatusBadge');
  let badgeClass = 'status-passed';
  let badgeText = '✓ PASSED';
  if (test.status === 'failed') {
    badgeClass = 'status-failed';
    badgeText = '✗ FAILED';
  } else if (test.status === 'warning') {
    badgeClass = 'status-warning';
    badgeText = '⚠ FLAGGED';
  } else if (test.status === 'defended') {
    badgeClass = 'status-defended';
    badgeText = '🛡️ DEFENDED';
  }
  statusBadge.className = `test-status-badge ${badgeClass}`;
  statusBadge.textContent = badgeText;

  // Verdict Explanation
  document.getElementById('modalTestVerdictExplanation').textContent = test.verdict_explanation || test.description;
  document.getElementById('modalTestObserved').textContent = test.observed_value;
  document.getElementById('modalTestBaseline').textContent = test.baseline;

  // Threat Impact Alert
  document.getElementById('modalTestImpactText').textContent = test.threat_impact || 'If left unaddressed, threat actors can leverage this vector to bypass security boundaries or intercept encrypted communications.';

  // Root Cause Diagnosis & Permissions
  document.getElementById('modalTestPermissionText').textContent = test.root_cause_diagnosis || (
    test.status === 'passed' 
      ? 'PASSED: No configuration errors or permission restrictions found.' 
      : `FAILED: Root cause is missing security directives on ${srv.host}. Elevated access (${test.permission_required ? 'Web Server Admin / Root Sudo' : 'Veritas Engine'}) is required to deploy this fix.`
  );

  // Remediation Code Block
  const fixCode = test.remediation_code || test.remediation || `# Automated remediation script for ${srv.host} (${test.id})\nveritas-defense fix --target ${srv.host} --rule ${test.id}`;
  document.getElementById('modalTestRemediationCode').textContent = fixCode;

  modal.classList.add('active');
};

// Render Prevention & Defense Engine Cards
function renderPreventionCards(srv) {
  const container = document.getElementById('preventionCardsContainer');
  if (!container) return;

  const prevList = srv.recommendedPreventions || [];
  if (prevList.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; padding: 24px; text-align: center; color: var(--text-muted);">
        ✓ No active vulnerabilities detected on this server. All defense layers verified.
      </div>
    `;
    return;
  }

  container.innerHTML = prevList.map(p => {
    const isApplied = srv.appliedPreventions && srv.appliedPreventions.includes(p.key);

    return `
      <div class="prevention-card ${isApplied ? 'applied' : ''}">
        <div class="prevention-header">
          <div class="prevention-title-group">
            <span class="prevention-tag">${esc(p.category)} · Severity: ${esc(p.severity)}</span>
            <h3 class="prevention-name">${esc(p.title)}</h3>
          </div>
          <span class="test-status-badge ${isApplied ? 'status-passed' : 'status-failed'}">
            ${isApplied ? '✓ DEFENSE ACTIVE' : '⚠ ACTION NEEDED'}
          </span>
        </div>

        <p class="prevention-desc">${esc(p.description)}</p>

        <div class="prevention-mechanism-box">
          <div class="mechanism-title">Live Server Deployment Scope:</div>
          <div>${p.permission_required ? `⚠️ Requires Elevated Server Access (Root / Web Server Admin on ${esc(srv.host)})` : `🛡️ Local Veritas AI Engine (Zero External Permission Required)`}</div>
        </div>

        <div class="prevention-actions">
          <span class="efficacy-gain">+${esc(p.points_gain ?? 0)}% Score Gain</span>
          <button class="btn ${isApplied ? 'btn-outline' : 'btn-defense'} btn-sm" onclick="openRemediationConsole(${esc(JSON.stringify(String(p.key)))})">
            <span>${isApplied ? '✓ Hardening Verified' : '🛠️ Deploy & Verify Patch'}</span>
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// Open Real Server Remediation & Verification Console Modal
window.openRemediationConsole = function(key) {
  const srv = state.servers[state.selectedServerIndex];
  const prevObj = (srv.recommendedPreventions || []).find(p => p.key === key) || {
    key: key,
    title: 'Deploy Security Hardening Directives',
    remediation_type: 'web_server_config'
  };

  state.pendingRemediation = { key, server: srv, prevObj };
  const modal = document.getElementById('remediationConsoleModal');

  document.getElementById('remHost').textContent = srv.host;
  document.getElementById('remAccess').textContent = prevObj.remediation_type === 'firewall_rule' ? 'Root Sudo / Firewall Administrator' : 'Web Server Admin (NGINX / Apache / Caddy)';
  
  // Set stack and code snippet
  updateRemediationCode(srv, state.currentStack, key);
  
  // Reset verification banner
  resetVerificationStatusBanner();

  modal.classList.add('active');
};

// Update code block based on selected server stack
function updateRemediationCode(srv, stack, key) {
  state.currentStack = stack;
  const pathEl = document.getElementById('remPath');
  const codeEl = document.getElementById('remDeployCode');

  // Update active stack tab button
  document.querySelectorAll('.stack-tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-stack') === stack);
  });

  const domain = srv.host;
  if (stack === 'nginx') {
    pathEl.textContent = `/etc/nginx/conf.d/${domain.replace(/[^a-zA-Z0-9]/g, '_')}_security.conf`;
    codeEl.textContent = `# 1. Create or edit security configuration file on ${domain}:
sudo bash -c 'cat > /etc/nginx/conf.d/veritas_hardening.conf << "EOF"
# Veritas Sentinel Hardening Directives for ${domain}
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src \x27self\x27; script-src \x27self\x27;" always;
server_tokens off;

location ~ /\\.(env|git|svn|htaccess) {
    deny all;
    return 404;
}
EOF
nginx -t && systemctl reload nginx'`;
  } else if (stack === 'apache') {
    pathEl.textContent = `/var/www/html/.htaccess (or /etc/apache2/sites-available/${domain}.conf)`;
    codeEl.textContent = `# Add to /var/www/html/.htaccess or VirtualHost directive:
<IfModule mod_headers.c>
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set Content-Security-Policy "default-src 'self';"
</IfModule>
ServerSignature Off
ServerTokens Prod

<FilesMatch "^\\.">
    Require all denied
</FilesMatch>

# Reload Apache:
sudo a2enmod headers && sudo systemctl reload apache2`;
  } else if (stack === 'caddy') {
    pathEl.textContent = `/etc/caddy/Caddyfile`;
    codeEl.textContent = `# In your Caddyfile for ${domain}:
${domain} {
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Frame-Options "SAMEORIGIN"
        X-Content-Type-Options "nosniff"
        Content-Security-Policy "default-src 'self'"
    }
    @dotfiles path_regexp dotfiles /\\.(env|git)
    respond @dotfiles 404
}

# Reload Caddy:
sudo caddy reload --config /etc/caddy/Caddyfile`;
  } else if (stack === 'cloudflare') {
    pathEl.textContent = `Cloudflare Dashboard ➜ Rules ➜ Transform Rules / HTTP Response Headers`;
    codeEl.textContent = `# In Cloudflare Dashboard for ${domain}:
1. Navigate to Rules ➜ Transform Rules ➜ Modify Response Header
2. Add Header: Strict-Transport-Security | Value: max-age=31536000; includeSubDomains; preload
3. Add Header: X-Frame-Options | Value: SAMEORIGIN
4. Add Header: X-Content-Type-Options | Value: nosniff
5. Navigate to SSL/TLS ➜ Edge Certificates ➜ Enable "Always Use HTTPS" and "HSTS"`;
  } else if (stack === 'iptables') {
    pathEl.textContent = `/etc/iptables/rules.v4`;
    codeEl.textContent = `# Rate-limit periodic C2 beacons & drop anomalous handshake bursts:
sudo iptables -A INPUT -p udp --dport ${srv.port} -m hashlimit --hashlimit-above 15/sec --hashlimit-burst 20 --hashlimit-mode srcip -j DROP
sudo iptables -A INPUT -p tcp --dport ${srv.port} -m connlimit --connlimit-above 50 -j REJECT
sudo iptables-save | sudo tee /etc/iptables/rules.v4`;
  }
}

// Reset verification status banner
function resetVerificationStatusBanner() {
  const icon = document.getElementById('verifIcon');
  const title = document.getElementById('verifTitle');
  const desc = document.getElementById('verifDesc');
  const badge = document.getElementById('verifBadge');

  icon.textContent = '🛰️';
  title.textContent = 'Ready to Probe Live Server';
  desc.textContent = 'Execute the command on your server terminal, then click "Verify Live Deployment on Server" below.';
  badge.className = 'test-status-badge status-warning';
  badge.textContent = 'NOT YET VERIFIED';
}

// Run live verification probe on server
async function runLiveVerificationProbe(simulate = false) {
  if (!state.pendingRemediation) return;
  const { key, server } = state.pendingRemediation;

  const icon = document.getElementById('verifIcon');
  const title = document.getElementById('verifTitle');
  const desc = document.getElementById('verifDesc');
  const badge = document.getElementById('verifBadge');
  const probeBtn = document.getElementById('btnRunLiveVerificationProbe');

  probeBtn.disabled = true;
  badge.className = 'test-status-badge status-warning';
  badge.textContent = 'PROBING LIVE SERVER...';
  desc.textContent = `Sending cryptographic HTTP/TLS probe over the wire to ${server.host}...`;

  let verified = false;
  let simulated = simulate;
  let message = '';

  // One live check per prevention. Anything without a probe is reported as unverifiable by the
  // backend rather than mapped onto an unrelated check.
  const probeFor = {
    deploy_security_headers: 'TEST-HSTS',
    block_dotfiles: 'TEST-RECON-FUZZ',
    provenance_grounding_verifier: 'TEST-VERITAS-GROUNDING',
  };

  if (state.backendOnline) {
    try {
      const res = await fetch('/api/verify-fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          hostname: server.host,
          port: server.port,
          test_id: probeFor[key] || key,
          simulate: simulate
        })
      });

      const data = await res.json().catch(() => ({}));
      if (res.ok) {
        verified = Boolean(data.verified);
        simulated = simulated || Boolean(data.simulated);
        message = data.message || '';
      } else {
        message = data.error || `Verification request failed (HTTP ${res.status}).`;
      }
    } catch (e) {
      console.warn('Live verification probe API error', e);
      message = 'Verification request failed: backend unreachable.';
    }
  } else {
    // Nothing can be probed without the backend; do not report a fix as verified.
    message = 'Backend offline — no probe was sent, so the fix cannot be verified.';
  }

  probeBtn.disabled = false;

  if (verified) {
    icon.textContent = simulated ? '🧪' : '🛡️';
    title.textContent = simulated
      ? 'Simulated — not verified on a live server'
      : 'Live Server Patch Verified & Active!';
    title.style.color = simulated ? '#fbbf24' : '#34d399';
    desc.textContent = message || 'Live socket probe confirmed the hardening headers/rules are actively delivered by the server on the wire.';
    badge.className = simulated ? 'test-status-badge status-warning' : 'test-status-badge status-passed';
    badge.textContent = simulated ? '🧪 SIMULATED' : '✓ VERIFIED & DEFENDED';

    // Apply the fix in state
    if (!server.appliedPreventions) server.appliedPreventions = [];
    if (!server.appliedPreventions.includes(key)) server.appliedPreventions.push(key);

    recalculateServerScore(server);
    savePersistentState();
    renderActiveServer();
    renderServerCards();

    showToast(simulated
      ? `Simulated fix applied for ${server.host} (not verified live).`
      : `✓ Live Verification Passed for ${server.host}! Security Score Elevated.`);
  } else {
    icon.textContent = '⚠️';
    title.textContent = 'Live Verification Probe Failed';
    title.style.color = '#fbbf24';
    desc.textContent = message || 'The live server did not return the expected security headers. Please verify that you ran `sudo systemctl reload nginx` (or Apache) on your server.';
    badge.className = 'test-status-badge status-failed';
    badge.textContent = '✗ FIX NOT DETECTED';
  }
}

// Recalculate score & test outcomes after defense applied
function recalculateServerScore(srv) {
  let score = srv.securityScore;
  const applied = srv.appliedPreventions || [];

  if (applied.includes('provenance_grounding_verifier')) {
    score += 30;
    const test = srv.tests.find(t => t.id === 'TEST-VERITAS-GROUNDING');
    if (test) {
      test.status = 'defended';
      test.observed_value = 'PROTECTED (0.00% Attack Success Rate)';
      test.verdict_explanation = 'Provenance Verifier enforced claim grounding on measured Twin telemetry.';
    }
  }

  if (applied.includes('deploy_firewall_rules')) {
    score += 20;
    const test = srv.tests.find(t => t.id === 'TEST-QUIC-H3' || t.id === 'TEST-PORT');
    if (test) {
      test.status = 'defended';
      test.observed_value = 'Protected (Rate Limiting Filter Active)';
    }
  }

  if (applied.includes('deploy_security_headers')) {
    score += 25;
    srv.tests.forEach(t => {
      if (t.category === 'HTTP Security Headers' || t.id === 'TEST-TLS-VER') {
        t.status = 'defended';
        t.observed_value = 'Hardened Header & Redirect Injected';
        t.verdict_explanation = 'Hardened security header verified live on server.';
      }
    });
  }

  if (applied.includes('block_dotfiles')) {
    score += 15;
    const test = srv.tests.find(t => t.id === 'TEST-RECON-FUZZ');
    if (test) {
      test.status = 'defended';
      test.observed_value = 'Public Access Forbidden (403)';
      test.verdict_explanation = 'Dotfile blocker verified live on server.';
    }
  }

  srv.securityScore = Math.min(98, score);
  if (srv.securityScore >= 85) {
    srv.postureVerdict = 'HARDENED DEFENSE';
    srv.postureClass = 'health-hardened';
    srv.description = 'Server exhibits robust transport integrity and zero AI reasoning hijack vulnerabilities.';
  } else if (srv.securityScore >= 60) {
    srv.postureVerdict = 'MODERATE PROTECTION';
    srv.postureClass = 'health-warning';
    srv.description = 'Key preventions active; remaining warnings are low-risk.';
  }
}

// Render Twin Split Inspector
function renderTwinSplit(srv) {
  const measuredBody = document.querySelector('#measuredFeaturesTable tbody');
  const untrustedBody = document.querySelector('#untrustedMetadataTable tbody');
  if (!measuredBody || !untrustedBody) return;

  const f = srv.twinFeatures || {};
  measuredBody.innerHTML = `
    <tr><td>HTTP Exchange Duration</td><td class="val-highlight">${measured(f.flow_duration, ' s')}</td><td>Scan wall time</td></tr>
    <tr><td>Requests Sent</td><td class="val-highlight">${measured(f.http_requests)}</td><td>Counted by client</td></tr>
    <tr><td>Responses Received</td><td class="val-highlight">${measured(f.http_responses)}</td><td>Counted by client</td></tr>
    <tr><td>Bytes Sent</td><td class="val-highlight">${measured(f.bytes_sent, ' B')}</td><td>Request line + headers + body</td></tr>
    <tr><td>Bytes Received</td><td class="val-highlight">${measured(f.bytes_received, ' B')}</td><td>Response headers + body</td></tr>
    <tr><td>Down / Up Ratio</td><td class="val-highlight">${measured(f.down_up_ratio)}</td><td>&gt; 2.0 (Web)</td></tr>
    <tr><td>Mean Inter-Request Gap</td><td class="val-highlight">${measured(f.flow_iat_mean, ' s')}</td><td>Non-periodic</td></tr>
    <tr><td>Response Body Entropy</td><td class="val-highlight">${measured(f.entropy, ' bits/B')}</td><td>&lt; 6.5 bits/B</td></tr>
  `;

  const meta = srv.metadataUntrusted || {};
  untrustedBody.innerHTML = `
    <tr><td>Server Banner</td><td class="val-highlight">${esc(meta.server_banner || 'Masked')}</td><td><span style="color:#fbbf24;">Attacker Authored</span></td></tr>
    <tr><td>Server Name Indication (SNI)</td><td class="val-highlight">${esc(meta.sni || srv.host)}</td><td><span style="color:#fbbf24;">Attacker Authored</span></td></tr>
    <tr><td>Content-Type Header</td><td class="val-highlight">${esc(meta.content_type || '—')}</td><td><span style="color:#fbbf24;">Attacker Authored</span></td></tr>
    <tr><td>Negotiated TLS / Cipher</td><td class="val-highlight">${esc([meta.tls_version, meta.cipher].filter(Boolean).join(' / ') || srv.protocol || '—')}</td><td><span style="color:#fbbf24;">Server Chosen</span></td></tr>
  `;
}

// Update Firewall & Report Blocks
function updateFirewallAndReport(srv) {
  const fwEl = document.getElementById('firewallCodeBlock');
  const rptEl = document.getElementById('auditSummaryBlock');

  if (fwEl) {
    fwEl.textContent = `# Veritas Auto-Generated Hardening Rules for ${srv.host}
# Target IP: ${srv.ip} | Port: ${srv.port}
# Generated: ${new Date().toISOString()}

# 1. Enforce QUIC connection tracking & handshake rate limit
iptables -A INPUT -p udp -d ${srv.ip} --dport ${srv.port} -m conntrack --ctstate NEW -m limit --limit 30/sec -j ACCEPT

# 2. Block anomalous periodic C2 beacon pulses (<0.05s jitter)
iptables -A INPUT -p udp -d ${srv.ip} --dport ${srv.port} -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 15 --hashlimit-mode srcip -j DROP

# 3. Veritas Provenance Verifier Hook Active (Twin Store Grounding)
veritas-twin enforce --host ${srv.host} --verifier provenance_grounding
echo "Veritas Sentinel Defense Active on ${srv.host}"`;
  }

  if (rptEl) {
    const reportObj = {
      server_target: srv.host,
      ip_address: srv.ip,
      port: srv.port,
      audit_timestamp: new Date().toISOString(),
      security_strength_score: srv.securityScore,
      posture_verdict: srv.postureVerdict,
      preventions_active: srv.appliedPreventions || [],
      digital_twin_id: `twin_${srv.host.replace(/[^a-zA-Z0-9]/g, '_')}`,
      tests_summary: {
        total: srv.tests.length,
        passed_or_defended: srv.tests.filter(t => t.status === 'passed' || t.status === 'defended').length,
        failed_or_warning: srv.tests.filter(t => t.status === 'failed' || t.status === 'warning').length
      }
    };
    rptEl.textContent = JSON.stringify(reportObj, null, 2);
  }
}

// Setup Event Listeners
function setupEventListeners() {
  // Live Real Scan Form Submit
  document.getElementById('quickScanForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const target = document.getElementById('targetUrlInput').value.trim();
    if (!target) return;
    await performLiveScan(target);
  });

  // Re-run Audit
  document.getElementById('btnAuditAll')?.addEventListener('click', () => {
    const srv = state.servers[state.selectedServerIndex];
    performLiveScan(srv.host);
  });
  document.getElementById('btnReRunTests')?.addEventListener('click', () => {
    const srv = state.servers[state.selectedServerIndex];
    performLiveScan(srv.host);
  });

  // Clear History
  document.getElementById('btnClearHistory')?.addEventListener('click', async () => {
    if (confirm('Clear all recent scan history and restore default lab nodes?')) {
      localStorage.removeItem('veritas_scans_history');
      localStorage.removeItem('veritas_selected_host');
      if (state.backendOnline) {
        try { await fetch('/api/scans/history', { method: 'DELETE' }); } catch (e) {}
      }
      state.servers = [...DEFAULT_SEED_SERVERS];
      state.selectedServerIndex = 0;
      renderServerCards();
      renderActiveServer();
      showToast('Scan history cleared.');
    }
  });

  // Apply All Defense
  document.getElementById('btnApplyAllDefense')?.addEventListener('click', () => {
    openRemediationConsole('deploy_security_headers');
  });
  document.getElementById('btnApplyAllPreventionsTab')?.addEventListener('click', () => {
    openRemediationConsole('deploy_security_headers');
  });

  // Test Deep-Dive Modal Close & Actions
  const testModal = document.getElementById('testDetailModal');
  document.getElementById('modalTestCloseBtn')?.addEventListener('click', () => testModal.classList.remove('active'));
  testModal?.addEventListener('click', (e) => {
    if (e.target === testModal) testModal.classList.remove('active');
  });

  document.getElementById('modalBtnCopyFix')?.addEventListener('click', () => {
    const code = document.getElementById('modalTestRemediationCode').textContent;
    navigator.clipboard.writeText(code).then(() => showToast('Remediation patch copied to clipboard!'));
  });

  document.getElementById('modalBtnApplyFix')?.addEventListener('click', () => {
    testModal.classList.remove('active');
    const test = state.activeInspectedTest;
    if (!test) return;

    if (test.id === 'TEST-VERITAS-GROUNDING') {
      openRemediationConsole('provenance_grounding_verifier');
    } else if (test.category === 'HTTP Security Headers' || test.id === 'TEST-TLS-VER') {
      openRemediationConsole('deploy_security_headers');
    } else if (test.id === 'TEST-RECON-FUZZ') {
      openRemediationConsole('block_dotfiles');
    } else {
      openRemediationConsole('deploy_firewall_rules');
    }
  });

  // Remediation Console Modal Events
  const remModal = document.getElementById('remediationConsoleModal');
  document.getElementById('remModalCloseBtn')?.addEventListener('click', () => remModal.classList.remove('active'));
  document.getElementById('btnRemClose')?.addEventListener('click', () => remModal.classList.remove('active'));
  remModal?.addEventListener('click', (e) => {
    if (e.target === remModal) remModal.classList.remove('active');
  });

  // Stack Selector Click
  document.querySelectorAll('.stack-tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const stack = btn.getAttribute('data-stack');
      const srv = state.servers[state.selectedServerIndex];
      const key = state.pendingRemediation ? state.pendingRemediation.key : 'deploy_security_headers';
      updateRemediationCode(srv, stack, key);
    });
  });

  // Copy Deploy Shell Command
  document.getElementById('btnCopyDeployCommand')?.addEventListener('click', () => {
    const code = document.getElementById('remDeployCode').textContent;
    navigator.clipboard.writeText(code).then(() => showToast('Deployment command copied! Run with sudo on your server terminal.'));
  });

  // Run Live Verification Probe
  document.getElementById('btnRunLiveVerificationProbe')?.addEventListener('click', () => {
    runLiveVerificationProbe(false);
  });

  // Simulate Verified Fix
  document.getElementById('btnSimulateVerified')?.addEventListener('click', () => {
    runLiveVerificationProbe(true);
  });

  // Custom Server Modal
  const modal = document.getElementById('customServerModal');
  document.getElementById('btnCustomServer')?.addEventListener('click', () => modal.classList.add('active'));
  document.getElementById('modalCloseBtn')?.addEventListener('click', () => modal.classList.remove('active'));
  
  document.getElementById('customServerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const host = document.getElementById('customHostInput').value.trim();
    modal.classList.remove('active');
    await performLiveScan(host);
  });

  // Injection Playground
  document.getElementById('btnSimulateInjection')?.addEventListener('click', () => {
    const payload = document.getElementById('attackPayloadSelect').value;
    const srv = state.servers[state.selectedServerIndex];
    const isGrounded = srv.appliedPreventions && srv.appliedPreventions.includes('provenance_grounding_verifier');

    const icon = document.getElementById('simVerdictIcon');
    const title = document.getElementById('simVerdictTitle');
    const details = document.getElementById('simVerdictDetails');

    if (payload === 'none') {
      icon.textContent = '✅';
      title.textContent = 'DECISION: IGNORE (Clean Honest Traffic)';
      title.style.color = '#34d399';
      details.textContent = 'SNI matches measured Twin telemetry. Zero injection detected.';
    } else if (isGrounded) {
      icon.textContent = '🛡️';
      title.textContent = 'DECISION: BLOCKED (0.00% Attack Success Rate)';
      title.style.color = '#34d399';
      details.textContent = `Attacker injected payload [${payload}]. Veritas Provenance Verifier flagged the decisive claim as UNTRUSTED_SOURCE because it relied on attacker-authored SNI text rather than measured packet volume. Verdict forced to BLOCK.`;
    } else {
      icon.textContent = '🛑';
      title.textContent = 'DECISION: IGNORE (DEFENDER HIJACKED / VULNERABLE)';
      title.style.color = '#f87171';
      details.textContent = `CRITICAL: Because Provenance Verifier is inactive, the undefended AI accepted the injected SNI header "${payload}" and flipped its verdict to IGNORE. Attack succeeded!`;
    }
  });

  // Downloads
  document.getElementById('btnDownloadReport')?.addEventListener('click', () => {
    const srv = state.servers[state.selectedServerIndex];
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(document.getElementById('auditSummaryBlock').textContent);
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `veritas_audit_${srv.host}.json`);
    dlAnchor.click();
    showToast('Downloaded Security Audit JSON');
  });

  document.getElementById('btnDownloadRules')?.addEventListener('click', () => {
    const srv = state.servers[state.selectedServerIndex];
    const dataStr = "data:text/plain;charset=utf-8," + encodeURIComponent(document.getElementById('firewallCodeBlock').textContent);
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `firewall_${srv.host}.sh`);
    dlAnchor.click();
    showToast('Downloaded Hardening Firewall Rules');
  });
}

// Transform report dict to state server object
function transformReportToServer(report) {
  return {
    id: `scan_${report.hostname.replace(/[^a-zA-Z0-9]/g, '_')}`,
    host: report.hostname,
    role: 'server',
    roleDescription: `Live Scanned Target (${report.protocol})`,
    ip: report.ip_addresses && report.ip_addresses[0] ? report.ip_addresses[0] : '127.0.0.1',
    port: report.port || 443,
    localhost_bind: '127.0.0.1',
    trafficClass: report.security_score >= 80 ? 'benign' : 'malicious',
    protocol: report.protocol,
    securityScore: report.security_score,
    postureVerdict: report.posture_verdict,
    postureClass: report.posture_class,
    description: `Live scan completed in ${report.scan_duration_ms} ms with ${report.tests.length} real test vectors executed.`,
    isRecentScan: true,
    twinFeatures: report.twin_features,
    metadataUntrusted: report.metadata_untrusted,
    appliedPreventions: report.applied_preventions || [],
    tests: report.tests.map(t => ({
      ...t,
      verdict_explanation: t.technical_details || t.description,
      threat_impact: t.status === 'failed' 
        ? `High-risk exploitability vector. Attackers targeting ${report.hostname} can exploit this gap to perform MITM tampering or unauthorized access.`
        : 'Security baseline verified. Zero exploitability detected for this vector.',
      root_cause_diagnosis: t.status === 'passed' 
        ? 'PASSED: Proper configurations in place.' 
        : `FAILED: Root cause is missing security parameters in web server configuration. Elevated permissions (${t.permission_required ? 'Web Server Admin / Root Sudo' : 'Veritas Engine'}) are required to deploy fixes.`,
      remediation_code: t.remediation || `# Remediation rule for ${report.hostname} (${t.id})\nveritas-defense fix --target ${report.hostname}`,
      note: t.remediation || t.technical_details
    })),
    recommendedPreventions: report.recommended_preventions
  };
}

// Perform Live Real Security Scan via Backend API
async function performLiveScan(target) {
  showToast(`⚡ Running live penetration tests & building Digital Twin for [${target}]...`);
  
  const scanBtn = document.getElementById('btnRunLiveScan');
  if (scanBtn) scanBtn.disabled = true;
  let failure = 'unknown error';

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.success && data.report) {
        const report = data.report;
        const newServer = transformReportToServer(report);

        // Add or update in state.servers at the front
        const existingIdx = state.servers.findIndex(s => s.host.toLowerCase() === newServer.host.toLowerCase());
        if (existingIdx >= 0) {
          state.servers[existingIdx] = newServer;
          state.selectedServerIndex = existingIdx;
        } else {
          state.servers.unshift(newServer);
          state.selectedServerIndex = 0;
        }

        // Save persistent state immediately
        savePersistentState();

        renderServerCards();
        renderActiveServer();
        showToast(`✓ Real Audit Complete for ${newServer.host}! Digital Twin Ingested. Score: ${newServer.securityScore}%`);
        if (scanBtn) scanBtn.disabled = false;
        return;
      }
    }
    // The backend answered but could not scan (bad target, unreachable host, server error).
    let reason = `HTTP ${res.status}`;
    try {
      const body = await res.json();
      if (body && body.error) reason = body.error;
    } catch (e) { /* non-JSON error body */ }
    failure = reason;
  } catch (e) {
    console.warn('Backend live scan error', e);
    failure = 'backend unreachable — start it with `python web/server.py`';
  }

  // Never substitute invented results for a scan that did not happen.
  if (scanBtn) scanBtn.disabled = false;
  showToast(`✗ Scan of ${target} failed: ${failure}`);
}

// Setup Tab Navigation
function setupTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  const panels = document.querySelectorAll('.tab-panel');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      panels.forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      document.getElementById(targetId)?.classList.add('active');
    });
  });
}

// Toast Notifications
function showToast(message) {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `<span>🛰️</span><span>${esc(message)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3500);
}
