-- AttackGen SAMPLE seed data (SIMULATED, SAFE, PLACEHOLDER ONLY).
--
-- This is NOT the real command pool. The command-database teammate owns the
-- large, curated pool. This file exists only so a developer can spin up a local
-- PostgreSQL instance and run the composer end-to-end for the sample_request.
--
-- Every command_line below is inert text used for the detection exercise. None
-- of it is executed, and it contains no real hosts, credentials, or secrets.
-- The series index (g) only varies file/host/job names so rows are distinct.

TRUNCATE command_lines RESTART IDENTITY;

-- ---------------------------------------------------------------------------
-- Benign categories (operational noise)
-- ---------------------------------------------------------------------------

-- linux_admin
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['systemctl','journalctl','ss','df'])[1 + (g % 4)],
    (ARRAY[
        format('systemctl status app-worker@%s.service', g),
        format('journalctl -u sshd --since "today" -n %s', 50 + g),
        format('ss -tnp state established sport = :%s', 8000 + g),
        format('df -h /var/lib/volume-%s', g)
    ])[1 + (g % 4)],
    'benign', 'linux_admin', 'linux', ARRAY['ransomware','persistence'], 1
FROM generate_series(1, 60) g;

-- devops
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['kubectl','helm','terraform','ansible-playbook'])[1 + (g % 4)],
    (ARRAY[
        format('kubectl rollout restart deployment/api-%s -n prod', g),
        format('helm upgrade release-%s ./chart --install', g),
        format('terraform apply -auto-approve -target=module.svc_%s', g),
        format('ansible-playbook deploy.yml --limit batch-%s', g)
    ])[1 + (g % 4)],
    'benign', 'devops', 'linux', ARRAY['lateral_movement','reverse_shell'], 1
FROM generate_series(1, 50) g;

-- logs
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['logrotate','rsync','grep','gzip'])[1 + (g % 4)],
    (ARRAY[
        format('logrotate -f /etc/logrotate.d/app-%s', g),
        format('rsync -az /var/log/app-%s/ logarchive:/logs/app-%s/', g, g),
        format('grep -c "ERROR" /var/log/service-%s.log', g),
        format('gzip /var/log/archive/run-%s.log', g)
    ])[1 + (g % 4)],
    'benign', 'logs', 'linux', ARRAY['data_exfiltration','defense_evasion'], 1
FROM generate_series(1, 50) g;

-- backup
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['tar','restic','pg_dump','rclone'])[1 + (g % 4)],
    (ARRAY[
        format('tar -czf /var/backups/app-%s.tar.gz /srv/app/data', g),
        format('restic backup /srv/data --tag nightly-%s', g),
        format('pg_dump -Fc appdb > /var/backups/appdb-%s.dump', g),
        format('rclone sync /var/backups remote:bucket/backup-%s', g)
    ])[1 + (g % 4)],
    'benign', 'backup', 'linux', ARRAY['ransomware','data_exfiltration'], 1
FROM generate_series(1, 60) g;

-- app_runtime
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['node','python3','java','gunicorn'])[1 + (g % 4)],
    (ARRAY[
        format('node /srv/app/server.js --port %s', 3000 + g),
        format('python3 -m worker --queue jobs-%s', g),
        format('java -jar /opt/app/service-%s.jar', g),
        format('gunicorn app:app --workers %s', 2 + (g % 8))
    ])[1 + (g % 4)],
    'benign', 'app_runtime', 'linux', ARRAY['crypto_miner'], 1
FROM generate_series(1, 40) g;

-- package_management
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['apt-get','pip3','npm','dpkg'])[1 + (g % 4)],
    (ARRAY[
        format('apt-get install -y --no-install-recommends pkg-%s', g),
        format('pip3 install internal-lib==1.%s.0', g),
        format('npm ci --prefix /srv/app/module-%s', g),
        format('dpkg -i /tmp/cache/build-%s.deb', g)
    ])[1 + (g % 4)],
    'benign', 'package_management', 'linux', ARRAY['persistence'], 1
FROM generate_series(1, 40) g;

-- ---------------------------------------------------------------------------
-- Malicious categories (simulated attacker activity, still inert text)
-- ---------------------------------------------------------------------------

-- discovery
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['bash','find','cat'])[1 + (g % 3)],
    (ARRAY[
        format('bash -c "id; uname -a; cat /etc/os-release # probe-%s"', g),
        format('find / -perm -4000 -type f 2>/dev/null | head -%s', 20 + g),
        format('cat /etc/passwd /etc/group # enum-%s', g)
    ])[1 + (g % 3)],
    'malicious', 'discovery', 'linux', ARRAY['ransomware','lateral_movement'], 3
FROM generate_series(1, 12) g;

-- staging
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['tar','cp','mkdir'])[1 + (g % 3)],
    (ARRAY[
        format('tar -czf /tmp/.cache/stage-%s.tar.gz /home /srv/app/data', g),
        format('cp -r /srv/app/secrets /tmp/.staging-%s', g),
        format('mkdir -p /dev/shm/.work-%s && cp /var/data/* /dev/shm/.work-%s', g, g)
    ])[1 + (g % 3)],
    'malicious', 'staging', 'linux', ARRAY['ransomware','data_exfiltration'], 3
FROM generate_series(1, 12) g;

-- persistence
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['crontab','systemctl','bash'])[1 + (g % 3)],
    (ARRAY[
        format('(crontab -l; echo "@reboot /tmp/.svc/update-%s") | crontab -', g),
        format('systemctl enable app-update-%s.timer', g),
        format('bash -c "echo ''/tmp/.init-%s &'' >> ~/.bashrc"', g)
    ])[1 + (g % 3)],
    'malicious', 'persistence', 'linux', ARRAY['persistence'], 2
FROM generate_series(1, 12) g;

-- execution
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['bash','python3','sh'])[1 + (g % 3)],
    (ARRAY[
        format('bash -c "$(printf ''ZWNobyBydW4tJXM='' | base64 -d)" # job-%s', g),
        format('python3 -c "import os;os.system(''/tmp/.svc/run-%s'')"', g),
        format('sh -c "nohup /tmp/.cache/worker-%s >/dev/null 2>&1 &"', g)
    ])[1 + (g % 3)],
    'malicious', 'execution', 'linux', ARRAY['reverse_shell','crypto_miner'], 3
FROM generate_series(1, 12) g;

-- cleanup
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['shred','rm','bash'])[1 + (g % 3)],
    (ARRAY[
        format('shred -u /var/log/auth.log.%s', g),
        format('rm -rf /tmp/.staging-%s /dev/shm/.work-%s', g, g),
        format('bash -c "history -c; > ~/.bash_history # wipe-%s"', g)
    ])[1 + (g % 3)],
    'malicious', 'cleanup', 'linux', ARRAY['defense_evasion'], 3
FROM generate_series(1, 12) g;

-- impact
INSERT INTO command_lines (process_name, command_line, label, category, os_profile, scenario_tags, stealth_level)
SELECT
    (ARRAY['openssl','find','bash'])[1 + (g % 3)],
    (ARRAY[
        format('openssl enc -aes-256-cbc -salt -in /srv/data/file-%s -out /srv/data/file-%s.enc', g, g),
        format('find /srv/app/data -type f -name "*.db" -exec gpg -c {} \; # run-%s', g),
        format('bash -c "for f in /var/data/*; do openssl enc -aes-256-cbc -in $f -out $f.locked-%s; done"', g)
    ])[1 + (g % 3)],
    'malicious', 'impact', 'linux', ARRAY['ransomware'], 2
FROM generate_series(1, 12) g;
