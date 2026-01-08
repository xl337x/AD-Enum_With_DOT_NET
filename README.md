# AD Recon Toolkit - Quick Reference

## ADRecon.ps1 - One-Liners

```powershell
# Load and run full recon
.\ADRecon.ps1 -Mode recon

# Quick wins
.\ADRecon.ps1 -Mode kerberoast                           # Get SPNs for roasting
.\ADRecon.ps1 -Mode asreproast                           # No preauth accounts
.\ADRecon.ps1 -Mode passwords                            # Passwords in descriptions
.\ADRecon.ps1 -Mode laps                                 # Readable LAPS passwords
.\ADRecon.ps1 -Mode priv                                 # All privileged users

# Delegation abuse
.\ADRecon.ps1 -Mode unconstrained                        # Unconstrained delegation
.\ADRecon.ps1 -Mode constrained                          # Constrained delegation
.\ADRecon.ps1 -Mode rbcd                                 # Resource-based constrained

# Search & enumeration
.\ADRecon.ps1 -Mode users -Query admin                   # Find users matching "admin"
.\ADRecon.ps1 -Mode groups -Query sql                    # Find groups matching "sql"
.\ADRecon.ps1 -Mode members -Query "Domain Admins"       # Group members
.\ADRecon.ps1 -Mode search -Query svc                    # Universal search

# Detailed info
.\ADRecon.ps1 -Mode userinfo -Query targetuser           # Full user details
.\ADRecon.ps1 -Mode compinfo -Query DC01                 # Full computer details

# Export results
.\ADRecon.ps1 -Mode kerberoast -Output csv -OutFile spns.csv
.\ADRecon.ps1 -Mode users -Output json -OutFile users.json

# Custom LDAP
.\ADRecon.ps1 -Mode ldap -Query "(adminCount=1)"
.\ADRecon.ps1 -Mode ldap -Query "(&(objectClass=user)(pwdLastSet>=132500000000000000))"
```

## ACLAnalyzer.ps1 - Attack Paths

```powershell
# Full ACL audit
.\ACLAnalyzer.ps1 -Mode audit

# Specific checks
.\ACLAnalyzer.ps1 -Mode dcsync                           # Who can DCSync?
.\ACLAnalyzer.ps1 -Mode owners                           # Non-standard object owners
.\ACLAnalyzer.ps1 -Mode gpo                              # GPO modification rights
.\ACLAnalyzer.ps1 -Mode shadow                           # Shadow credentials

# Scan for exploitable ACLs
.\ACLAnalyzer.ps1 -Mode findacl -ObjectType user         # On users
.\ACLAnalyzer.ps1 -Mode findacl -ObjectType group        # On groups

# Check specific object
.\ACLAnalyzer.ps1 -Mode acl -Target "Domain Admins"
.\ACLAnalyzer.ps1 -Mode acl -Target administrator

# Find what a principal can attack
.\ACLAnalyzer.ps1 -Mode rights -Principal "DOMAIN\compromised_user"
```

## Interactive Mode Examples

```powershell
# ADRecon interactive
.\ADRecon.ps1
> kerberoast
> users admin
> user jeff
> group "IT Admins"
> ldap (servicePrincipalName=*sql*)
> q

# ACLAnalyzer interactive  
.\ACLAnalyzer.ps1
> dcsync
> acl "Enterprise Admins"
> rights CORP\svc_backup
> q
```

## Common Attack Chains

### Kerberoasting
```powershell
.\ADRecon.ps1 -Mode kerberoast
# Then: GetUserSPNs.py / Rubeus kerberoast
```

### ASREPRoasting
```powershell
.\ADRecon.ps1 -Mode asreproast
# Then: GetNPUsers.py / Rubeus asreproast
```

### DCSync Check
```powershell
.\ACLAnalyzer.ps1 -Mode dcsync
# If user has rights: secretsdump.py / mimikatz dcsync
```

### GenericAll/Write Abuse
```powershell
.\ACLAnalyzer.ps1 -Mode acl -Target targetuser
# GenericAll on user → Reset password, targeted kerberoast, shadow credentials
# GenericWrite on user → Targeted kerberoast, shadow credentials
# GenericAll on group → Add yourself to group
```

### WriteDACL Abuse
```powershell
.\ACLAnalyzer.ps1 -Mode findacl -ObjectType group
# WriteDACL → Grant yourself GenericAll, then abuse
```

### RBCD Attack
```powershell
.\ADRecon.ps1 -Mode rbcd                                 # Find existing
.\ACLAnalyzer.ps1 -Mode findacl -ObjectType computer    # Find computers you can configure
# If GenericWrite on computer → Add RBCD, impersonate
```

## Useful LDAP Filters

```powershell
# Users with SPN (kerberoastable)
(&(samAccountType=805306368)(servicePrincipalName=*))

# No preauth required (ASREPRoastable)
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Unconstrained delegation (non-DCs)
(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))

# Constrained delegation
(msDS-AllowedToDelegateTo=*)

# AdminCount=1 users
(&(samAccountType=805306368)(adminCount=1))

# Disabled accounts
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Password never expires
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Password not required
(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32))

# Recently changed passwords (last 30 days)
(&(objectClass=user)(pwdLastSet>=TIMESTAMP))

# Users with email
(&(samAccountType=805306368)(mail=*))

# Servers
(&(objectClass=computer)(operatingSystem=*server*))

# Domain Controllers
(userAccountControl:1.2.840.113556.1.4.803:=8192)
```

## Output Flags

| Flag | Description |
|------|-------------|
| `[ADMIN]` | AdminCount=1 (protected user) |
| `[SPN]` | Has servicePrincipalName (kerberoastable) |
| `[NOPREAUTH]` | No Kerberos preauth (ASREPRoastable) |
| `[DISABLED]` | Account disabled |
| `[NOPWDEXPIRE]` | Password never expires |
| `[NOPWDREQUIRED]` | Password not required |
| `[HIGH-VALUE]` | Privileged target |
| `[PROTOCOL TRANSITION]` | Constrained deleg with protocol transition |
| `[KERBEROS ONLY]` | Constrained deleg Kerberos only |
