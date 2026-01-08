
<#
.SYNOPSIS
    AD ACL & Attack Path Analysis - Find privilege escalation paths
.DESCRIPTION
    Focused on finding exploitable ACLs, attack paths, and misconfigurations
#>

param(
    [string]$Mode = "interactive",
    [string]$Target = "",
    [string]$Principal = "",
    [switch]$Help
)

#region Core
$script:PDC = $null
$script:DN = $null

function Init-AD {
    if($script:PDC) { return $true }
    try {
        $dom = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $script:PDC = $dom.PdcRoleOwner.Name
        $script:DN = ([adsi]'').distinguishedName
        return $true
    } catch { return $false }
}

function LDAP {
    param([string]$Filter, [string[]]$Props = @(), [string]$Base = "")
    if(-not (Init-AD)) { return @() }
    $searchBase = if($Base) { $Base } else { $script:DN }
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$searchBase")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de, $Filter)
    $ds.PageSize = 1000
    if($Props.Count -gt 0) { $Props | ForEach-Object { $ds.PropertiesToLoad.Add($_) | Out-Null } }
    try { return $ds.FindAll() } catch { return @() }
}

function Get-ObjectDN {
    param([string]$Identity)
    $result = LDAP -Filter "(|(samaccountname=$Identity)(distinguishedname=$Identity))" -Props @("distinguishedname")
    if($result) { return $result[0].Properties['distinguishedname'][0] }
    return $null
}

function Resolve-SID {
    param([string]$sid)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        return $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $sid }
}

# Extended Rights GUIDs
$script:ExtendedRights = @{
    "00299570-246d-11d0-a768-00aa006e0529" = "User-Force-Change-Password"
    "ab721a54-1e2f-11d0-9819-00aa0040529b" = "Send-As"
    "ab721a56-1e2f-11d0-9819-00aa0040529b" = "Receive-As"
    "00000000-0000-0000-0000-000000000000" = "All-Extended-Rights"
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
    "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
}

# Schema attribute GUIDs for property writes
$script:SchemaAttribs = @{
    "bf9679c0-0de6-11d0-a285-00aa003049e2" = "member"
    "f30e3bc1-9ff0-11d1-b603-0000f80367c1" = "ms-DS-KeyCredentialLink"
    "bf9679a8-0de6-11d0-a285-00aa003049e2" = "servicePrincipalName"
    "bf967953-0de6-11d0-a285-00aa003049e2" = "displayName"
    "bf9679e5-0de6-11d0-a285-00aa003049e2" = "msDS-AllowedToDelegateTo"
    "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79" = "msDS-AllowedToActOnBehalfOfOtherIdentity"
}

$script:DangerousRights = @(
    "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl", 
    "Self", "AllExtendedRights", "ForceChangePassword", 
    "User-Force-Change-Password", "WriteProperty"
)
#endregion

#region ACL Functions
function Get-ObjectACL {
    param(
        [string]$Identity,
        [switch]$ResolveGUIDs,
        [switch]$DangerousOnly
    )
    
    $dn = Get-ObjectDN -Identity $Identity
    if(-not $dn) { Write-Host "[-] Object not found: $Identity" -ForegroundColor Red; return }
    
    Write-Host "`n[*] ACLs for: $Identity" -ForegroundColor Cyan
    
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
    $acl = $de.ObjectSecurity
    
    $results = @()
    
    foreach($ace in $acl.Access) {
        $principal = $ace.IdentityReference.Value
        $rights = $ace.ActiveDirectoryRights.ToString()
        $type = $ace.AccessControlType.ToString()
        $inherited = $ace.IsInherited
        $objectType = $ace.ObjectType.ToString()
        $inheritedType = $ace.InheritedObjectType.ToString()
        
        # Resolve GUIDs
        $rightName = $rights
        if($ResolveGUIDs -and $objectType -ne "00000000-0000-0000-0000-000000000000") {
            if($script:ExtendedRights.ContainsKey($objectType)) {
                $rightName = "$rights [$($script:ExtendedRights[$objectType])]"
            } elseif($script:SchemaAttribs.ContainsKey($objectType)) {
                $rightName = "$rights [$($script:SchemaAttribs[$objectType])]"
            } else {
                $rightName = "$rights [GUID:$objectType]"
            }
        }
        
        $isDangerous = $false
        foreach($dr in $script:DangerousRights) {
            if($rights -match $dr) { $isDangerous = $true; break }
        }
        
        if($DangerousOnly -and -not $isDangerous) { continue }
        if($type -eq "Deny") { continue }
        
        $results += [PSCustomObject]@{
            Principal = $principal
            Rights = $rightName
            ObjectType = $objectType
            Type = $type
            Inherited = $inherited
            Dangerous = $isDangerous
        }
    }
    
    if($results.Count -eq 0) {
        Write-Host "[-] No ACEs found (or none matching filter)" -ForegroundColor Yellow
        return
    }
    
    # Group by principal
    $grouped = $results | Group-Object Principal
    
    foreach($g in $grouped) {
        $color = if($g.Group | Where-Object { $_.Dangerous }) { "Red" } else { "Gray" }
        Write-Host "`n  $($g.Name)" -ForegroundColor $color
        
        foreach($ace in $g.Group) {
            $rcolor = if($ace.Dangerous) { "Yellow" } else { "White" }
            $inh = if($ace.Inherited) { "(inherited)" } else { "" }
            Write-Host "    $($ace.Rights) $inh" -ForegroundColor $rcolor
        }
    }
    
    return $results
}

function Find-InterestingACLs {
    param(
        [string]$PrincipalFilter = "",
        [string]$ObjectType = "user",
        [int]$Limit = 100
    )
    
    Write-Host "`n[*] Scanning for interesting ACLs on $ObjectType objects..." -ForegroundColor Cyan
    
    $filter = switch($ObjectType) {
        "user" { "(samAccountType=805306368)" }
        "group" { "(objectClass=group)" }
        "computer" { "(objectClass=computer)" }
        "gpo" { "(objectClass=groupPolicyContainer)" }
        "ou" { "(objectClass=organizationalUnit)" }
        default { "(objectClass=*)" }
    }
    
    $objects = LDAP -Filter $filter -Props @("samaccountname","distinguishedname","cn")
    
    if($Limit -gt 0 -and $objects.Count -gt $Limit) {
        Write-Host "[!] Limiting to first $Limit objects (found $($objects.Count))" -ForegroundColor Yellow
        $objects = $objects | Select-Object -First $Limit
    }
    
    $findings = @()
    $counter = 0
    
    foreach($obj in $objects) {
        $counter++
        if($counter % 50 -eq 0) { Write-Host "[*] Processed $counter/$($objects.Count)..." -ForegroundColor Gray }
        
        $dn = $obj.Properties['distinguishedname'][0]
        $name = if($obj.Properties['samaccountname']) { $obj.Properties['samaccountname'][0] } else { $obj.Properties['cn'][0] }
        
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
            $acl = $de.ObjectSecurity
            
            foreach($ace in $acl.Access) {
                if($ace.AccessControlType -ne "Allow") { continue }
                if($ace.IsInherited) { continue }  # Focus on explicit ACEs
                
                $principal = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()
                $objectTypeGuid = $ace.ObjectType.ToString()
                
                # Skip well-known safe principals
                if($principal -match "NT AUTHORITY|BUILTIN|SYSTEM|SELF|Creator Owner") { continue }
                if($PrincipalFilter -and $principal -notmatch $PrincipalFilter) { continue }
                
                # Check for dangerous rights
                $isDangerous = $false
                $attackType = ""
                
                if($rights -match "GenericAll") { $isDangerous = $true; $attackType = "Full Control" }
                elseif($rights -match "GenericWrite") { $isDangerous = $true; $attackType = "GenericWrite" }
                elseif($rights -match "WriteOwner") { $isDangerous = $true; $attackType = "WriteOwner" }
                elseif($rights -match "WriteDacl") { $isDangerous = $true; $attackType = "WriteDacl" }
                elseif($rights -match "WriteProperty") {
                    # Check specific property
                    if($objectTypeGuid -eq "00000000-0000-0000-0000-000000000000") {
                        $isDangerous = $true; $attackType = "WriteAllProperties"
                    } elseif($script:SchemaAttribs.ContainsKey($objectTypeGuid)) {
                        $prop = $script:SchemaAttribs[$objectTypeGuid]
                        if($prop -in @("member","servicePrincipalName","msDS-AllowedToActOnBehalfOfOtherIdentity","ms-DS-KeyCredentialLink")) {
                            $isDangerous = $true; $attackType = "Write-$prop"
                        }
                    }
                }
                elseif($rights -match "ExtendedRight" -or $rights -match "Self") {
                    if($objectTypeGuid -eq "00000000-0000-0000-0000-000000000000") {
                        $isDangerous = $true; $attackType = "AllExtendedRights"
                    } elseif($script:ExtendedRights.ContainsKey($objectTypeGuid)) {
                        $isDangerous = $true; $attackType = $script:ExtendedRights[$objectTypeGuid]
                    }
                }
                
                if($isDangerous) {
                    $findings += [PSCustomObject]@{
                        Target = $name
                        TargetDN = $dn
                        Principal = $principal
                        Rights = $rights
                        AttackType = $attackType
                        ObjectTypeGuid = $objectTypeGuid
                    }
                }
            }
        } catch { continue }
    }
    
    if($findings.Count -eq 0) {
        Write-Host "[-] No interesting ACLs found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n[+] Found $($findings.Count) interesting ACL(s)!`n" -ForegroundColor Green
    
    # Group by attack type
    $grouped = $findings | Group-Object AttackType
    
    foreach($g in $grouped) {
        Write-Host "  === $($g.Name) ===" -ForegroundColor Yellow
        foreach($f in $g.Group) {
            Write-Host "    $($f.Principal) -> $($f.Target)" -ForegroundColor White
        }
        Write-Host ""
    }
    
    return $findings
}

function Find-DCSync {
    Write-Host "`n[*] Checking for DCSync rights..." -ForegroundColor Cyan
    
    $domainDN = $script:DN
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$domainDN")
    $acl = $de.ObjectSecurity
    
    $dcSyncGUIDs = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
        "89e95b76-444d-4c62-991a-0facbeda640c"   # DS-Replication-Get-Changes-In-Filtered-Set
    )
    
    $findings = @{}
    
    foreach($ace in $acl.Access) {
        if($ace.AccessControlType -ne "Allow") { continue }
        
        $principal = $ace.IdentityReference.Value
        $objectType = $ace.ObjectType.ToString()
        
        # Skip expected DCs
        if($principal -match "Domain Controllers|Enterprise Domain Controllers") { continue }
        
        if($objectType -in $dcSyncGUIDs -or $ace.ActiveDirectoryRights -match "GenericAll") {
            if(-not $findings.ContainsKey($principal)) {
                $findings[$principal] = @()
            }
            $findings[$principal] += $script:ExtendedRights[$objectType]
        }
    }
    
    # Filter to principals with all required rights
    $dcSyncCapable = @()
    foreach($p in $findings.Keys) {
        $rights = $findings[$p]
        if(($rights -contains "DS-Replication-Get-Changes" -and $rights -contains "DS-Replication-Get-Changes-All") -or
           ($ace.ActiveDirectoryRights -match "GenericAll")) {
            $dcSyncCapable += $p
        }
    }
    
    if($dcSyncCapable.Count -eq 0) {
        Write-Host "[-] No unexpected DCSync principals found" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Found $($dcSyncCapable.Count) principal(s) with DCSync rights!`n" -ForegroundColor Red
        foreach($p in $dcSyncCapable) {
            Write-Host "  [!] $p" -ForegroundColor Red
            Write-Host "      Rights: $($findings[$p] -join ', ')" -ForegroundColor Yellow
        }
    }
}

function Find-OwnerAbuse {
    param([string]$ObjectType = "user")
    
    Write-Host "`n[*] Finding objects owned by non-standard principals..." -ForegroundColor Cyan
    
    $filter = switch($ObjectType) {
        "user" { "(&(samAccountType=805306368)(adminCount=1))" }  # Focus on privileged users
        "group" { "(&(objectClass=group)(adminCount=1))" }
        "computer" { "(objectClass=computer)" }
        default { "(objectClass=*)" }
    }
    
    $objects = LDAP -Filter $filter -Props @("samaccountname","distinguishedname","cn")
    
    $findings = @()
    
    foreach($obj in $objects) {
        $dn = $obj.Properties['distinguishedname'][0]
        $name = if($obj.Properties['samaccountname']) { $obj.Properties['samaccountname'][0] } else { $obj.Properties['cn'][0] }
        
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
            $owner = $de.ObjectSecurity.Owner
            
            # Skip expected owners
            if($owner -match "Domain Admins|Enterprise Admins|BUILTIN\\Administrators|NT AUTHORITY\\SYSTEM|Administrator$") {
                continue
            }
            
            $findings += [PSCustomObject]@{
                Object = $name
                Owner = $owner
                DN = $dn
            }
        } catch { continue }
    }
    
    if($findings.Count -eq 0) {
        Write-Host "[-] No unexpected ownership found" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Found $($findings.Count) object(s) with non-standard owners!`n" -ForegroundColor Green
        foreach($f in $findings) {
            Write-Host "  $($f.Object)" -ForegroundColor Yellow
            Write-Host "    Owner: $($f.Owner)" -ForegroundColor Red
        }
    }
    
    return $findings
}

function Find-ShadowCredentials {
    Write-Host "`n[*] Checking for Shadow Credentials (msDS-KeyCredentialLink)..." -ForegroundColor Cyan
    
    $results = LDAP -Filter "(msDS-KeyCredentialLink=*)" -Props @("samaccountname","msds-keycredentiallink","distinguishedname")
    
    if($results.Count -eq 0) {
        Write-Host "[-] No objects with KeyCredentialLink found" -ForegroundColor Yellow
        return
    }
    
    Write-Host "[+] Found $($results.Count) object(s) with KeyCredentialLink!`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['samaccountname'][0])" -ForegroundColor Yellow
        Write-Host "    Has shadow credentials configured" -ForegroundColor Gray
    }
}

function Check-GPOPermissions {
    Write-Host "`n[*] Checking GPO modification rights..." -ForegroundColor Cyan
    
    $gpos = LDAP -Filter "(objectClass=groupPolicyContainer)" -Props @("displayname","distinguishedname","gpcfilesyspath")
    
    $findings = @()
    
    foreach($gpo in $gpos) {
        $dn = $gpo.Properties['distinguishedname'][0]
        $name = $gpo.Properties['displayname'][0]
        
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
            $acl = $de.ObjectSecurity
            
            foreach($ace in $acl.Access) {
                if($ace.AccessControlType -ne "Allow") { continue }
                if($ace.IsInherited) { continue }
                
                $principal = $ace.IdentityReference.Value
                $rights = $ace.ActiveDirectoryRights.ToString()
                
                if($principal -match "NT AUTHORITY|BUILTIN|Domain Admins|Enterprise Admins|SYSTEM") { continue }
                
                if($rights -match "GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner") {
                    $findings += [PSCustomObject]@{
                        GPO = $name
                        Principal = $principal
                        Rights = $rights
                        Path = $gpo.Properties['gpcfilesyspath'][0]
                    }
                }
            }
        } catch { continue }
    }
    
    if($findings.Count -eq 0) {
        Write-Host "[-] No interesting GPO permissions found" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Found $($findings.Count) interesting GPO permission(s)!`n" -ForegroundColor Green
        foreach($f in $findings | Group-Object GPO) {
            Write-Host "  $($f.Name)" -ForegroundColor Yellow
            foreach($entry in $f.Group) {
                Write-Host "    $($entry.Principal): $($entry.Rights)" -ForegroundColor White
            }
        }
    }
    
    return $findings
}

function Find-PrincipalRights {
    param([string]$Principal)
    
    if(-not $Principal) { Write-Host "[-] Specify principal with -Principal" -ForegroundColor Red; return }
    
    Write-Host "`n[*] Finding rights for: $Principal" -ForegroundColor Cyan
    
    # Get all objects and check ACLs - expensive but thorough
    $types = @(
        @{Name="Users";Filter="(samAccountType=805306368)"},
        @{Name="Groups";Filter="(objectClass=group)"},
        @{Name="Computers";Filter="(objectClass=computer)"},
        @{Name="GPOs";Filter="(objectClass=groupPolicyContainer)"}
    )
    
    $findings = @()
    
    foreach($type in $types) {
        Write-Host "[*] Scanning $($type.Name)..." -ForegroundColor Gray
        $objects = LDAP -Filter $type.Filter -Props @("samaccountname","distinguishedname","cn","displayname")
        
        foreach($obj in $objects) {
            $dn = $obj.Properties['distinguishedname'][0]
            $name = if($obj.Properties['samaccountname']) { $obj.Properties['samaccountname'][0] } 
                    elseif($obj.Properties['displayname']) { $obj.Properties['displayname'][0] }
                    else { $obj.Properties['cn'][0] }
            
            try {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
                $acl = $de.ObjectSecurity
                
                foreach($ace in $acl.Access) {
                    if($ace.AccessControlType -ne "Allow") { continue }
                    if($ace.IdentityReference.Value -notmatch [regex]::Escape($Principal)) { continue }
                    
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    $objectType = $ace.ObjectType.ToString()
                    
                    $attackType = ""
                    if($rights -match "GenericAll") { $attackType = "Full Control" }
                    elseif($rights -match "GenericWrite") { $attackType = "GenericWrite" }
                    elseif($rights -match "WriteOwner") { $attackType = "WriteOwner" }
                    elseif($rights -match "WriteDacl") { $attackType = "WriteDacl" }
                    elseif($rights -match "WriteProperty") {
                        if($script:SchemaAttribs.ContainsKey($objectType)) {
                            $attackType = "Write-$($script:SchemaAttribs[$objectType])"
                        } else { $attackType = "WriteProperty" }
                    }
                    elseif($rights -match "ExtendedRight") {
                        if($script:ExtendedRights.ContainsKey($objectType)) {
                            $attackType = $script:ExtendedRights[$objectType]
                        } else { $attackType = "ExtendedRight" }
                    }
                    
                    if($attackType) {
                        $findings += [PSCustomObject]@{
                            Target = $name
                            Type = $type.Name
                            AttackType = $attackType
                            Rights = $rights
                        }
                    }
                }
            } catch { continue }
        }
    }
    
    if($findings.Count -eq 0) {
        Write-Host "[-] No rights found for $Principal" -ForegroundColor Yellow
    } else {
        Write-Host "`n[+] Found $($findings.Count) right(s) for $Principal!`n" -ForegroundColor Green
        
        $grouped = $findings | Group-Object Type
        foreach($g in $grouped) {
            Write-Host "  === $($g.Name) ===" -ForegroundColor Yellow
            foreach($f in $g.Group) {
                Write-Host "    $($f.Target): $($f.AttackType)" -ForegroundColor White
            }
        }
    }
    
    return $findings
}

function Run-ACLAudit {
    Write-Host "`n[*] Running Full ACL Audit..." -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor DarkGray
    
    Find-DCSync
    Find-OwnerAbuse -ObjectType "user"
    Check-GPOPermissions
    Find-ShadowCredentials
    Find-InterestingACLs -ObjectType "user" -Limit 50
    Find-InterestingACLs -ObjectType "group" -Limit 50
    
    Write-Host "`n[+] ACL Audit Complete!" -ForegroundColor Green
}
#endregion

#region Main
if($Help) {
    @"
AD ACL & Attack Path Analyzer

MODES:
  interactive     Interactive mode (default)
  audit           Full ACL audit
  acl             Get ACLs on specific object
  dcsync          Check DCSync permissions
  owners          Find non-standard object owners
  gpo             Check GPO permissions
  shadow          Find shadow credentials
  findacl         Scan for interesting ACLs
  rights          Find all rights for a principal

OPTIONS:
  -Target         Target object for ACL analysis
  -Principal      Principal to find rights for
  -ObjectType     Object type for scanning (user/group/computer/gpo)

EXAMPLES:
  .\ACLAnalyzer.ps1 -Mode audit
  .\ACLAnalyzer.ps1 -Mode acl -Target "Domain Admins"
  .\ACLAnalyzer.ps1 -Mode rights -Principal "DOMAIN\\user"
  .\ACLAnalyzer.ps1 -Mode findacl -ObjectType group
"@
    return
}

if(-not (Init-AD)) {
    Write-Host "[-] Failed to connect to AD" -ForegroundColor Red
    return
}

$modeMap = @{
    "audit" = { Run-ACLAudit }
    "acl" = { Get-ObjectACL -Identity $Target -ResolveGUIDs -DangerousOnly }
    "dcsync" = { Find-DCSync }
    "owners" = { Find-OwnerAbuse }
    "gpo" = { Check-GPOPermissions }
    "shadow" = { Find-ShadowCredentials }
    "findacl" = { Find-InterestingACLs -ObjectType $ObjectType }
    "rights" = { Find-PrincipalRights -Principal $Principal }
}

if($Mode -ne "interactive" -and $modeMap.ContainsKey($Mode)) {
    & $modeMap[$Mode]
    return
}

# Interactive
while($true) {
    Write-Host "`n[?] Mode (audit/acl/dcsync/owners/gpo/shadow/findacl/rights/q): " -ForegroundColor Green -NoNewline
    $cmd = Read-Host
    
    if($cmd -eq 'q') { break }
    if($cmd -eq '') { continue }
    
    $parts = $cmd -split '\s+', 2
    $action = $parts[0].ToLower()
    $arg = if($parts.Count -gt 1) { $parts[1] } else { "" }
    
    switch($action) {
        "audit" { Run-ACLAudit }
        "acl" { Get-ObjectACL -Identity $arg -ResolveGUIDs -DangerousOnly }
        "dcsync" { Find-DCSync }
        "owners" { Find-OwnerAbuse }
        "gpo" { Check-GPOPermissions }
        "shadow" { Find-ShadowCredentials }
        "findacl" { Find-InterestingACLs -ObjectType $(if($arg){$arg}else{"user"}) }
        "rights" { Find-PrincipalRights -Principal $arg }
        default { Write-Host "[-] Unknown: $action" -ForegroundColor Red }
    }
}
#endregion
