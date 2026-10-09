from typing import Dict, Any

CVE_LOCAL_CACHE = {
    "CVE-2021-44228": {
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "description": "Apache Log4j2 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://github.com/advisories/GHSA-j2ge-4vdv-vq5u"]
    },
    "CVE-2021-23017": {
        "cvss_score": 8.1,
        "severity": "HIGH",
        "description": "A 1-byte memory overwrite vulnerability in NGINX DNS resolver allows a remote attacker to cause worker process crash or execute arbitrary code.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017", "https://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html"]
    },
    "CVE-2020-15778": {
        "cvss_score": 7.8,
        "severity": "HIGH",
        "description": "OpenSSH scp command injection via backtick or shell character evaluation when copying files to/from remote system.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-15778"]
    },
    "CVE-2022-22965": {
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "description": "Spring Framework RCE via data binding on JDK 9+ allowing remote code execution via class loader manipulation (Spring4Shell).",
        "references": ["https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"]
    },
    "CVE-2023-38606": {
        "cvss_score": 7.5,
        "severity": "HIGH",
        "description": "Apple Kernel hardware memory-mapped I/O page tables validation bypass allowing unauthorized page table modifications.",
        "references": ["https://support.apple.com/en-us/HT213841"]
    }
}

MITRE_TECHNIQUES_DB = {
    "T1190": {
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit a weakness in an Internet-facing computer or program using software, system, or service bugs.",
        "mitigation": "Apply application patches, use Web Application Firewalls (WAF), enforce input validation, and segment network DMZs."
    },
    "T1059": {
        "technique_name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters to execute arbitrary commands, scripts, or binaries.",
        "mitigation": "Disable unnecessary scripting environments, restrict script execution via AppLocker/WDAC, and log command-line activity."
    },
    "T1078": {
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.",
        "mitigation": "Enforce Multi-Factor Authentication (MFA), rotate compromised credentials, audit inactive accounts, and implement least privilege."
    },
    "T1055": {
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "mitigation": "Enable endpoint detection and response (EDR) solutions and configure memory protection policies."
    },
    "T1046": {
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts to identify vulnerable services.",
        "mitigation": "Minimize exposed ports, close unused network services, and implement network intrusion detection systems."
    },
    "T1110": {
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords are unknown.",
        "mitigation": "Set account lockout thresholds, enforce strong password policies, and implement rate limiting with CAPTCHA."
    },
    "T1566": {
        "technique_name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems via spearphishing links or attachments.",
        "mitigation": "Deploy SPF, DKIM, DMARC, implement automated email link sandboxing, and conduct employee security awareness training."
    },
    "T1068": {
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges from low-privilege to SYSTEM/root.",
        "mitigation": "Regularly patch kernel and system binaries, employ least privilege, and use kernel security modules (SELinux/AppArmor)."
    },
    "T1552": {
        "technique_name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "description": "Adversaries may search compromised systems to find and obtain insecurely stored credentials in files, git repositories, or configs.",
        "mitigation": "Use secrets management services (e.g. HashiCorp Vault), avoid hardcoding credentials, and encrypt credential files at rest."
    },
    "T1499": {
        "technique_name": "Endpoint Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform endpoint denial of service attacks to degrade or block the availability of targeted services.",
        "mitigation": "Deploy rate limiting, web application firewalls, auto-scaling server architecture, and DDoS mitigation providers."
    }
}


# -----------------------------------------------------------------------------
