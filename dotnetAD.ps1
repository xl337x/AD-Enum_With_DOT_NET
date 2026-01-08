<#
.SYNOPSIS
    AD Recon Swiss Army Knife - Minimal footprint AD enumeration
.DESCRIPTION
    Pure LDAP enumeration without AD module dependency. Built for pentesters.
.PARAMETER Mode
    Operation mode: interactive, or specific function name
.PARAMETER Query
    Search query or target for the selected mode
.PARAMETER Output
    Output format: table (default), csv, json, raw
.PARAMETER OutFile
    Export results to file
.EXAMPLE
    .\ADRecon.ps1                           # Interactive mode
    .\ADRecon.ps1 -Mode kerberoast          # Find kerberoastable accounts
    .\ADRecon.ps1 -Mode user -Query "admin" # Search users matching "admin"
    .\ADRecon.ps1 -Mode privusers -Output csv -OutFile priv.csv
#>

param(
    [string]$Mode = "interactive",
    [string]$Query = "",
    [string]$Output = "table",
    [string]$OutFile = "",
    [string]$SearchBase = "",
    [switch]$Quick,
    [switch]$Help
)

#region Core Functions
$script:PDC = $null
$script:DN = $null
$script:Domain = $null

function Init-AD {
    if($script:PDC) { return $true }
    try {
        $script:Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        $script:PDC = $script:Domain.PdcRoleOwner.Name
        $script:DN = ([adsi]'').distinguishedName
        return $true
    } catch {
        Write-Host "[-] Failed to connect to AD: $_" -ForegroundColor Red
        return $false
    }
}

function LDAP {
    param(
        [string]$Filter,
        [string[]]$Properties = @(),
        [string]$Base = "",
        [int]$Limit = 0
    )
    
    if(-not (Init-AD)) { return @() }
    
    $searchBase = if($Base) { $Base } elseif($script:SearchBase) { $script:SearchBase } else { $script:DN }
    $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$searchBase")
    $ds = New-Object System.DirectoryServices.DirectorySearcher($de, $Filter)
    $ds.PageSize = 1000
    
    if($Limit -gt 0) { $ds.SizeLimit = $Limit }
    if($Properties.Count -gt 0) { $Properties | ForEach-Object { $ds.PropertiesToLoad.Add($_) | Out-Null } }
    
    try { return $ds.FindAll() } catch { return @() }
}

function Convert-LDAPTime {
    param($t)
    if(-not $t -or $t -eq 0 -or $t -eq 9223372036854775807) { return "Never" }
    try { return [DateTime]::FromFileTime($t).ToString("yyyy-MM-dd HH:mm") } catch { return $t }
}

function Convert-UAC {
    param([int]$uac)
    $flags = @{
        1 = "SCRIPT"; 2 = "ACCOUNTDISABLE"; 8 = "HOMEDIR_REQUIRED"
        16 = "LOCKOUT"; 32 = "PASSWD_NOTREQD"; 64 = "PASSWD_CANT_CHANGE"
        128 = "ENCRYPTED_TEXT_PWD_ALLOWED"; 512 = "NORMAL_ACCOUNT"
        2048 = "INTERDOMAIN_TRUST"; 4096 = "WORKSTATION_TRUST"
        8192 = "SERVER_TRUST"; 65536 = "DONT_EXPIRE_PASSWORD"
        131072 = "MNS_LOGON_ACCOUNT"; 262144 = "SMARTCARD_REQUIRED"
        524288 = "TRUSTED_FOR_DELEGATION"; 1048576 = "NOT_DELEGATED"
        2097152 = "USE_DES_KEY_ONLY"; 4194304 = "DONT_REQ_PREAUTH"
        8388608 = "PASSWORD_EXPIRED"; 16777216 = "TRUSTED_TO_AUTH_FOR_DELEGATION"
        67108864 = "PARTIAL_SECRETS_ACCOUNT"
    }
    $active = @()
    foreach($f in $flags.Keys) { if($uac -band $f) { $active += $flags[$f] } }
    return $active -join ", "
}

function Resolve-SID {
    param([string]$sid)
    try {
        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
        return $objSID.Translate([System.Security.Principal.NTAccount]).Value
    } catch { return $sid }
}

function Format-Output {
    param($Results, [string]$Type)
    
    if(-not $Results -or $Results.Count -eq 0) {
        Write-Host "[-] No results" -ForegroundColor Yellow
        return
    }
    
    $data = @()
    foreach($r in $Results) {
        $obj = [ordered]@{}
        foreach($p in $r.Properties.PropertyNames) {
            $val = $r.Properties[$p]
            if($val.Count -eq 1) { $obj[$p] = $val[0] }
            else { $obj[$p] = $val -join "; " }
        }
        $data += [PSCustomObject]$obj
    }
    
    switch($Output) {
        "csv" { 
            if($OutFile) { $data | Export-Csv -Path $OutFile -NoTypeInformation; Write-Host "[+] Exported to $OutFile" -ForegroundColor Green }
            else { $data | ConvertTo-Csv -NoTypeInformation }
        }
        "json" {
            if($OutFile) { $data | ConvertTo-Json -Depth 10 | Out-File $OutFile; Write-Host "[+] Exported to $OutFile" -ForegroundColor Green }
            else { $data | ConvertTo-Json -Depth 10 }
        }
        "raw" { return $data }
        default { return $data }
    }
}
#endregion

#region Enumeration Functions
function Get-DomainInfo {
    Write-Host "`n[*] Domain Information" -ForegroundColor Cyan
    if(-not (Init-AD)) { return }
    
    $info = @{
        "Domain" = $script:Domain.Name
        "Forest" = $script:Domain.Forest.Name
        "PDC" = $script:PDC
        "Domain SID" = (New-Object System.Security.Principal.NTAccount($script:Domain.Name, "Domain Admins")).Translate([System.Security.Principal.SecurityIdentifier]).AccountDomainSid.Value
        "Functional Level" = $script:Domain.DomainMode
        "Domain Controllers" = ($script:Domain.DomainControllers | ForEach-Object { $_.Name }) -join ", "
    }
    
    $info.GetEnumerator() | ForEach-Object { 
        Write-Host "  $($_.Key): " -NoNewline -ForegroundColor Yellow
        Write-Host $_.Value -ForegroundColor White
    }
    
    # Password Policy
    Write-Host "`n[*] Password Policy" -ForegroundColor Cyan
    $policy = LDAP -Filter "(objectClass=domain)" -Properties @("minPwdLength","maxPwdAge","minPwdAge","pwdHistoryLength","lockoutThreshold","lockoutDuration","lockoutObservationWindow")
    if($policy) {
        $p = $policy[0].Properties
        Write-Host "  Min Length: $($p['minpwdlength'][0])" -ForegroundColor White
        Write-Host "  Max Age: $([math]::Abs([int64]$p['maxpwdage'][0] / 864000000000)) days" -ForegroundColor White
        Write-Host "  History: $($p['pwdhistorylength'][0]) passwords" -ForegroundColor White
        Write-Host "  Lockout Threshold: $($p['lockoutthreshold'][0])" -ForegroundColor White
    }
}

function Get-Kerberoastable {
    Write-Host "`n[*] Kerberoastable Accounts (Users with SPNs)" -ForegroundColor Cyan
    $results = LDAP -Filter "(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))" -Properties @("samaccountname","serviceprincipalname","memberof","pwdlastset","lastlogon","admincount","description")
    
    if($results.Count -eq 0) { Write-Host "[-] No kerberoastable accounts found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) kerberoastable account(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $name = $p['samaccountname'][0]
        $spns = $p['serviceprincipalname'] -join ", "
        $admin = if($p['admincount']) { "[HIGH-VALUE]" } else { "" }
        $pwdAge = if($p['pwdlastset']) { 
            $days = ((Get-Date) - [DateTime]::FromFileTime($p['pwdlastset'][0])).Days
            "$days days"
        } else { "Never" }
        
        Write-Host "  $name $admin" -ForegroundColor $(if($admin){"Red"}else{"White"})
        Write-Host "    SPN: $spns" -ForegroundColor Gray
        Write-Host "    Password Age: $pwdAge" -ForegroundColor Gray
        if($p['description']) { Write-Host "    Desc: $($p['description'][0])" -ForegroundColor Gray }
        Write-Host ""
    }
    
    Format-Output -Results $results -Type "kerberoast"
}

function Get-ASREPRoastable {
    Write-Host "`n[*] ASREPRoastable Accounts (No PreAuth Required)" -ForegroundColor Cyan
    $results = LDAP -Filter "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties @("samaccountname","memberof","pwdlastset","description","admincount")
    
    if($results.Count -eq 0) { Write-Host "[-] No ASREPRoastable accounts found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) ASREPRoastable account(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $name = $p['samaccountname'][0]
        $admin = if($p['admincount']) { "[HIGH-VALUE]" } else { "" }
        
        Write-Host "  $name $admin" -ForegroundColor $(if($admin){"Red"}else{"White"})
        if($p['description']) { Write-Host "    Desc: $($p['description'][0])" -ForegroundColor Gray }
    }
    
    Format-Output -Results $results -Type "asreproast"
}

function Get-UnconstrainedDelegation {
    Write-Host "`n[*] Unconstrained Delegation (Excluding DCs)" -ForegroundColor Cyan
    $results = LDAP -Filter "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(primaryGroupID=516)))" -Properties @("samaccountname","dnshostname","operatingsystem","description")
    
    if($results.Count -eq 0) { Write-Host "[-] No unconstrained delegation found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) object(s) with unconstrained delegation`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['samaccountname'][0])" -ForegroundColor Red
        if($p['dnshostname']) { Write-Host "    Host: $($p['dnshostname'][0])" -ForegroundColor Gray }
        if($p['operatingsystem']) { Write-Host "    OS: $($p['operatingsystem'][0])" -ForegroundColor Gray }
    }
    
    Format-Output -Results $results -Type "unconstrained"
}

function Get-ConstrainedDelegation {
    Write-Host "`n[*] Constrained Delegation" -ForegroundColor Cyan
    $results = LDAP -Filter "(msDS-AllowedToDelegateTo=*)" -Properties @("samaccountname","msds-allowedtodelegateto","useraccountcontrol","dnshostname")
    
    if($results.Count -eq 0) { Write-Host "[-] No constrained delegation found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) object(s) with constrained delegation`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $uac = [int]$p['useraccountcontrol'][0]
        $protocol = if($uac -band 16777216) { "[PROTOCOL TRANSITION]" } else { "[KERBEROS ONLY]" }
        
        Write-Host "  $($p['samaccountname'][0]) $protocol" -ForegroundColor Yellow
        Write-Host "    Can delegate to:" -ForegroundColor Gray
        foreach($t in $p['msds-allowedtodelegateto']) {
            Write-Host "      - $t" -ForegroundColor White
        }
    }
    
    Format-Output -Results $results -Type "constrained"
}

function Get-RBCD {
    Write-Host "`n[*] Resource-Based Constrained Delegation" -ForegroundColor Cyan
    $results = LDAP -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" -Properties @("samaccountname","msds-allowedtoactonbehalfofotheridentity","dnshostname")
    
    if($results.Count -eq 0) { Write-Host "[-] No RBCD found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) object(s) with RBCD configured`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['samaccountname'][0])" -ForegroundColor Yellow
        
        # Parse the security descriptor to find who can delegate
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm($p['msds-allowedtoactonbehalfofotheridentity'][0])
        Write-Host "    Principals allowed to delegate:" -ForegroundColor Gray
        foreach($ace in $sd.Access) {
            Write-Host "      - $($ace.IdentityReference)" -ForegroundColor White
        }
    }
    
    Format-Output -Results $results -Type "rbcd"
}

function Get-PrivilegedUsers {
    Write-Host "`n[*] Privileged Users & Groups" -ForegroundColor Cyan
    
    $privGroups = @(
        "Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins",
        "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
        "DnsAdmins", "DHCP Administrators", "Cert Publishers"
    )
    
    foreach($group in $privGroups) {
        $grpResults = LDAP -Filter "(&(objectClass=group)(cn=$group))" -Properties @("member","distinguishedname")
        if($grpResults -and $grpResults.Count -gt 0) {
            $members = $grpResults[0].Properties['member']
            if($members) {
                Write-Host "`n  $group ($($members.Count) members)" -ForegroundColor Yellow
                foreach($m in $members) {
                    $memberName = ($m -split ',')[0] -replace 'CN=',''
                    Write-Host "    - $memberName" -ForegroundColor White
                }
            }
        }
    }
    
    # AdminCount users
    Write-Host "`n[*] All AdminCount=1 Users" -ForegroundColor Cyan
    $admins = LDAP -Filter "(&(samAccountType=805306368)(adminCount=1))" -Properties @("samaccountname","memberof","description","pwdlastset")
    
    if($admins.Count -gt 0) {
        Write-Host "[+] Found $($admins.Count) user(s) with AdminCount=1`n" -ForegroundColor Green
        foreach($a in $admins) {
            $p = $a.Properties
            Write-Host "  $($p['samaccountname'][0])" -ForegroundColor White
        }
    }
    
    Format-Output -Results $admins -Type "priv"
}

function Get-DomainComputers {
    param([string]$Filter = "")
    
    Write-Host "`n[*] Domain Computers" -ForegroundColor Cyan
    
    $ldapFilter = if($Filter) { "(&(objectClass=computer)(samaccountname=*$Filter*))" } else { "(objectClass=computer)" }
    $results = LDAP -Filter $ldapFilter -Properties @("samaccountname","dnshostname","operatingsystem","operatingsystemversion","lastlogon","description","useraccountcontrol")
    
    if($results.Count -eq 0) { Write-Host "[-] No computers found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) computer(s)`n" -ForegroundColor Green
    
    $servers = @()
    $workstations = @()
    $dcs = @()
    
    foreach($r in $results) {
        $p = $r.Properties
        $name = $p['samaccountname'][0]
        $os = if($p['operatingsystem']) { $p['operatingsystem'][0] } else { "Unknown" }
        $lastLogon = Convert-LDAPTime $p['lastlogon'][0]
        
        $obj = [PSCustomObject]@{
            Name = $name
            DNS = $p['dnshostname'][0]
            OS = $os
            LastLogon = $lastLogon
        }
        
        if($os -match "Server") { 
            if($os -match "Domain Controller" -or ($p['useraccountcontrol'][0] -band 8192)) { $dcs += $obj }
            else { $servers += $obj }
        } else { $workstations += $obj }
    }
    
    if($dcs.Count -gt 0) {
        Write-Host "  Domain Controllers ($($dcs.Count)):" -ForegroundColor Red
        $dcs | ForEach-Object { Write-Host "    $($_.Name) - $($_.OS)" -ForegroundColor White }
    }
    
    if($servers.Count -gt 0) {
        Write-Host "`n  Servers ($($servers.Count)):" -ForegroundColor Yellow
        if($Quick) { $servers | Select-Object -First 10 | ForEach-Object { Write-Host "    $($_.Name) - $($_.OS)" -ForegroundColor White } }
        else { $servers | ForEach-Object { Write-Host "    $($_.Name) - $($_.OS)" -ForegroundColor White } }
    }
    
    if($workstations.Count -gt 0) {
        Write-Host "`n  Workstations ($($workstations.Count)):" -ForegroundColor Gray
        if($Quick) { Write-Host "    (Use -Mode computers without -Quick to list all)" -ForegroundColor DarkGray }
        else { $workstations | ForEach-Object { Write-Host "    $($_.Name) - $($_.OS)" -ForegroundColor White } }
    }
    
    Format-Output -Results $results -Type "computers"
}

function Get-DomainUsers {
    param([string]$Filter = "")
    
    Write-Host "`n[*] Domain Users" -ForegroundColor Cyan
    
    $ldapFilter = if($Filter) { "(&(samAccountType=805306368)(|(samaccountname=*$Filter*)(cn=*$Filter*)(description=*$Filter*)))" } else { "(samAccountType=805306368)" }
    $results = LDAP -Filter $ldapFilter -Properties @("samaccountname","cn","memberof","pwdlastset","lastlogon","useraccountcontrol","description","admincount","serviceprincipalname")
    
    if($results.Count -eq 0) { Write-Host "[-] No users found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) user(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $name = $p['samaccountname'][0]
        $uac = [int]$p['useraccountcontrol'][0]
        
        $flags = @()
        if($p['admincount'] -and $p['admincount'][0] -eq 1) { $flags += "ADMIN" }
        if($p['serviceprincipalname']) { $flags += "SPN" }
        if($uac -band 2) { $flags += "DISABLED" }
        if($uac -band 4194304) { $flags += "NOPREAUTH" }
        if($uac -band 65536) { $flags += "NOPWDEXPIRE" }
        if($uac -band 32) { $flags += "NOPWDREQUIRED" }
        
        $flagStr = if($flags) { " [" + ($flags -join ",") + "]" } else { "" }
        $color = if("ADMIN" -in $flags) { "Red" } elseif("SPN" -in $flags -or "NOPREAUTH" -in $flags) { "Yellow" } else { "White" }
        
        Write-Host "  $name$flagStr" -ForegroundColor $color
        if($p['description'] -and -not $Quick) { Write-Host "    $($p['description'][0])" -ForegroundColor Gray }
    }
    
    Format-Output -Results $results -Type "users"
}

function Get-DomainGroups {
    param([string]$Filter = "")
    
    Write-Host "`n[*] Domain Groups" -ForegroundColor Cyan
    
    $ldapFilter = if($Filter) { "(&(objectClass=group)(|(samaccountname=*$Filter*)(cn=*$Filter*)(description=*$Filter*)))" } else { "(objectClass=group)" }
    $results = LDAP -Filter $ldapFilter -Properties @("samaccountname","cn","member","memberof","description","admincount")
    
    if($results.Count -eq 0) { Write-Host "[-] No groups found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) group(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $name = $p['samaccountname'][0]
        $memberCount = if($p['member']) { $p['member'].Count } else { 0 }
        $admin = if($p['admincount'] -and $p['admincount'][0] -eq 1) { "[PRIVILEGED]" } else { "" }
        
        Write-Host "  $name ($memberCount members) $admin" -ForegroundColor $(if($admin){"Yellow"}else{"White"})
    }
    
    Format-Output -Results $results -Type "groups"
}

function Get-GroupMembers {
    param([string]$GroupName, [switch]$Recursive)
    
    if(-not $GroupName) {
        Write-Host "[-] Specify group name with -Query" -ForegroundColor Red
        return
    }
    
    Write-Host "`n[*] Members of '$GroupName'" -ForegroundColor Cyan
    
    $group = LDAP -Filter "(&(objectClass=group)(|(samaccountname=$GroupName)(cn=$GroupName)))" -Properties @("member","distinguishedname")
    
    if(-not $group -or $group.Count -eq 0) { Write-Host "[-] Group not found" -ForegroundColor Red; return }
    
    $members = $group[0].Properties['member']
    if(-not $members) { Write-Host "[-] No members" -ForegroundColor Yellow; return }
    
    Write-Host "[+] $($members.Count) direct member(s)`n" -ForegroundColor Green
    
    $allMembers = @{}
    
    function Resolve-Members {
        param($MemberDNs, [int]$Depth = 0)
        
        foreach($dn in $MemberDNs) {
            if($allMembers.ContainsKey($dn)) { continue }
            
            $obj = LDAP -Filter "(distinguishedName=$dn)" -Properties @("samaccountname","objectclass","member")
            if(-not $obj) { continue }
            
            $p = $obj[0].Properties
            $name = $p['samaccountname'][0]
            $type = $p['objectclass'][-1]
            
            $allMembers[$dn] = [PSCustomObject]@{
                Name = $name
                Type = $type
                Depth = $Depth
            }
            
            if($Recursive -and $type -eq "group" -and $p['member']) {
                Resolve-Members -MemberDNs $p['member'] -Depth ($Depth + 1)
            }
        }
    }
    
    Resolve-Members -MemberDNs $members
    
    foreach($m in $allMembers.Values | Sort-Object Depth, Type, Name) {
        $indent = "  " * ($m.Depth + 1)
        $typeColor = switch($m.Type) { "group" { "Yellow" } "computer" { "Cyan" } default { "White" } }
        Write-Host "$indent$($m.Name) ($($m.Type))" -ForegroundColor $typeColor
    }
}

function Get-UserInfo {
    param([string]$Username)
    
    if(-not $Username) {
        $Username = $env:USERNAME
        Write-Host "[*] No user specified, using current user: $Username" -ForegroundColor Gray
    }
    
    Write-Host "`n[*] User Information: $Username" -ForegroundColor Cyan
    
    $user = LDAP -Filter "(samaccountname=$Username)" -Properties @("*")
    
    if(-not $user -or $user.Count -eq 0) { Write-Host "[-] User not found" -ForegroundColor Red; return }
    
    $p = $user[0].Properties
    
    $keyProps = @(
        @{N="SAM Account";V=$p['samaccountname']},
        @{N="Display Name";V=$p['displayname']},
        @{N="Distinguished Name";V=$p['distinguishedname']},
        @{N="SID";V=$p['objectsid'] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_,0)).Value }},
        @{N="Description";V=$p['description']},
        @{N="Created";V=$p['whencreated']},
        @{N="Password Last Set";V=(Convert-LDAPTime $p['pwdlastset'][0])},
        @{N="Last Logon";V=(Convert-LDAPTime $p['lastlogon'][0])},
        @{N="Logon Count";V=$p['logoncount']},
        @{N="Bad Pwd Count";V=$p['badpwdcount']},
        @{N="Admin Count";V=$p['admincount']},
        @{N="UAC";V=(Convert-UAC $p['useraccountcontrol'][0])},
        @{N="Service Principal Names";V=($p['serviceprincipalname'] -join "`n                      ")}
    )
    
    foreach($prop in $keyProps) {
        if($prop.V) {
            Write-Host "  $($prop.N): " -NoNewline -ForegroundColor Yellow
            Write-Host "$($prop.V)" -ForegroundColor White
        }
    }
    
    # Group memberships
    if($p['memberof']) {
        Write-Host "`n  Group Memberships:" -ForegroundColor Yellow
        foreach($g in $p['memberof']) {
            $gname = ($g -split ',')[0] -replace 'CN=',''
            Write-Host "    - $gname" -ForegroundColor White
        }
    }
    
    Format-Output -Results $user -Type "userinfo"
}

function Get-ComputerInfo {
    param([string]$ComputerName)
    
    if(-not $ComputerName) { Write-Host "[-] Specify computer with -Query" -ForegroundColor Red; return }
    
    # Add $ if not present
    if(-not $ComputerName.EndsWith('$')) { $ComputerName = "$ComputerName$" }
    
    Write-Host "`n[*] Computer Information: $ComputerName" -ForegroundColor Cyan
    
    $comp = LDAP -Filter "(samaccountname=$ComputerName)" -Properties @("*")
    
    if(-not $comp -or $comp.Count -eq 0) { Write-Host "[-] Computer not found" -ForegroundColor Red; return }
    
    $p = $comp[0].Properties
    
    $keyProps = @(
        @{N="SAM Account";V=$p['samaccountname']},
        @{N="DNS Hostname";V=$p['dnshostname']},
        @{N="Operating System";V=$p['operatingsystem']},
        @{N="OS Version";V=$p['operatingsystemversion']},
        @{N="Description";V=$p['description']},
        @{N="Created";V=$p['whencreated']},
        @{N="Last Logon";V=(Convert-LDAPTime $p['lastlogon'][0])},
        @{N="UAC";V=(Convert-UAC $p['useraccountcontrol'][0])},
        @{N="Service Principal Names";V=($p['serviceprincipalname'] -join "`n                      ")},
        @{N="Allowed To Delegate";V=($p['msds-allowedtodelegateto'] -join "`n                      ")}
    )
    
    foreach($prop in $keyProps) {
        if($prop.V) {
            Write-Host "  $($prop.N): " -NoNewline -ForegroundColor Yellow
            Write-Host "$($prop.V)" -ForegroundColor White
        }
    }
    
    # Check LAPS
    if($p['ms-mcs-admpwd']) {
        Write-Host "`n  [!] LAPS Password: " -NoNewline -ForegroundColor Red
        Write-Host "$($p['ms-mcs-admpwd'][0])" -ForegroundColor Green
    }
    
    Format-Output -Results $comp -Type "compinfo"
}

function Get-LAPS {
    Write-Host "`n[*] Checking LAPS Passwords (requires read access)" -ForegroundColor Cyan
    $results = LDAP -Filter "(&(objectClass=computer)(ms-mcs-admpwd=*))" -Properties @("samaccountname","dnshostname","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime")
    
    if($results.Count -eq 0) { Write-Host "[-] No LAPS passwords readable" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) readable LAPS password(s)!`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['samaccountname'][0])" -ForegroundColor Yellow
        Write-Host "    Password: $($p['ms-mcs-admpwd'][0])" -ForegroundColor Green
        if($p['ms-mcs-admpwdexpirationtime']) {
            Write-Host "    Expires: $(Convert-LDAPTime $p['ms-mcs-admpwdexpirationtime'][0])" -ForegroundColor Gray
        }
    }
    
    Format-Output -Results $results -Type "laps"
}

function Get-GPOs {
    Write-Host "`n[*] Group Policy Objects" -ForegroundColor Cyan
    $results = LDAP -Filter "(objectClass=groupPolicyContainer)" -Properties @("displayname","gpcfilesyspath","versionnumber","whencreated","whenchanged")
    
    if($results.Count -eq 0) { Write-Host "[-] No GPOs found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) GPO(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['displayname'][0])" -ForegroundColor Yellow
        Write-Host "    Path: $($p['gpcfilesyspath'][0])" -ForegroundColor Gray
    }
    
    Format-Output -Results $results -Type "gpos"
}

function Get-Trusts {
    Write-Host "`n[*] Domain Trusts" -ForegroundColor Cyan
    $results = LDAP -Filter "(objectClass=trustedDomain)" -Properties @("name","trustpartner","trustdirection","trusttype","trustattributes")
    
    if($results.Count -eq 0) { Write-Host "[-] No trusts found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) trust(s)`n" -ForegroundColor Green
    
    $trustDir = @{0="Disabled";1="Inbound";2="Outbound";3="Bidirectional"}
    $trustType = @{1="Windows NT";2="Active Directory";3="MIT Kerberos";4="DCE"}
    
    foreach($r in $results) {
        $p = $r.Properties
        $dir = $trustDir[[int]$p['trustdirection'][0]]
        $type = $trustType[[int]$p['trusttype'][0]]
        
        Write-Host "  $($p['trustpartner'][0])" -ForegroundColor Yellow
        Write-Host "    Direction: $dir | Type: $type" -ForegroundColor Gray
    }
    
    Format-Output -Results $results -Type "trusts"
}

function Get-PasswordInDescription {
    Write-Host "`n[*] Searching for passwords in descriptions" -ForegroundColor Cyan
    $results = LDAP -Filter "(description=*)" -Properties @("samaccountname","objectclass","description")
    
    $keywords = @('pass','pwd','cred','secret','key','pw=','pw:')
    $matches = @()
    
    foreach($r in $results) {
        $desc = $r.Properties['description'][0].ToLower()
        foreach($kw in $keywords) {
            if($desc -like "*$kw*") {
                $matches += $r
                break
            }
        }
    }
    
    if($matches.Count -eq 0) { Write-Host "[-] No potential passwords in descriptions" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($matches.Count) potential password(s) in descriptions!`n" -ForegroundColor Green
    
    foreach($m in $matches) {
        $p = $m.Properties
        $type = $p['objectclass'][-1]
        Write-Host "  $($p['samaccountname'][0]) ($type)" -ForegroundColor Yellow
        Write-Host "    $($p['description'][0])" -ForegroundColor Red
    }
}

function Find-Object {
    param([string]$SearchTerm)
    
    if(-not $SearchTerm) { Write-Host "[-] Specify search term with -Query" -ForegroundColor Red; return }
    
    Write-Host "`n[*] Searching for: '$SearchTerm'" -ForegroundColor Cyan
    
    # Search across multiple attributes
    $ldapFilter = "(|(samaccountname=*$SearchTerm*)(cn=*$SearchTerm*)(description=*$SearchTerm*)(displayname=*$SearchTerm*)(mail=*$SearchTerm*))"
    $results = LDAP -Filter $ldapFilter -Properties @("samaccountname","cn","objectclass","description","distinguishedname")
    
    if($results.Count -eq 0) { Write-Host "[-] No results" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) object(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        $type = $p['objectclass'][-1]
        $name = if($p['samaccountname']) { $p['samaccountname'][0] } else { $p['cn'][0] }
        
        $typeColor = switch($type) { "user" { "White" } "group" { "Yellow" } "computer" { "Cyan" } default { "Gray" } }
        Write-Host "  [$type] $name" -ForegroundColor $typeColor
        if($p['description'] -and -not $Quick) { Write-Host "    $($p['description'][0])" -ForegroundColor Gray }
    }
    
    Format-Output -Results $results -Type "search"
}

function Get-DCHosts {
    Write-Host "`n[*] Domain Controllers" -ForegroundColor Cyan
    $results = LDAP -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("samaccountname","dnshostname","operatingsystem","operatingsystemversion")
    
    if($results.Count -eq 0) { Write-Host "[-] No DCs found" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) DC(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        $p = $r.Properties
        Write-Host "  $($p['samaccountname'][0])" -ForegroundColor Red
        Write-Host "    DNS: $($p['dnshostname'][0])" -ForegroundColor Gray
        Write-Host "    OS: $($p['operatingsystem'][0]) $($p['operatingsystemversion'][0])" -ForegroundColor Gray
    }
    
    Format-Output -Results $results -Type "dcs"
}

function Custom-LDAP {
    param([string]$Filter)
    
    if(-not $Filter) {
        Write-Host "[-] Specify LDAP filter with -Query" -ForegroundColor Red
        return
    }
    
    Write-Host "`n[*] Custom LDAP: $Filter" -ForegroundColor Cyan
    $results = LDAP -Filter $Filter
    
    if($results.Count -eq 0) { Write-Host "[-] No results" -ForegroundColor Yellow; return }
    
    Write-Host "[+] Found $($results.Count) object(s)`n" -ForegroundColor Green
    
    foreach($r in $results) {
        Write-Host "  ---" -ForegroundColor Gray
        foreach($prop in $r.Properties.PropertyNames | Sort-Object) {
            $val = $r.Properties[$prop]
            if($val.Count -eq 1) { $displayVal = $val[0] }
            else { $displayVal = "[$($val -join ', ')]" }
            
            Write-Host "  $prop = $displayVal" -ForegroundColor White
        }
    }
    
    Format-Output -Results $results -Type "custom"
}

function Run-Recon {
    Write-Host "`n[*] Running Full AD Recon..." -ForegroundColor Cyan
    Write-Host "=" * 50 -ForegroundColor DarkGray
    
    Get-DomainInfo
    Get-DCHosts
    Get-Trusts
    Get-PrivilegedUsers
    Get-Kerberoastable
    Get-ASREPRoastable
    Get-UnconstrainedDelegation
    Get-ConstrainedDelegation
    Get-RBCD
    Get-PasswordInDescription
    Get-LAPS
    Get-GPOs
    
    Write-Host "`n[+] Recon Complete!" -ForegroundColor Green
}
#endregion

#region Main
if($Help) {
    @"
AD Recon Swiss Army Knife

MODES:
  interactive      Interactive menu (default)
  recon           Full automated recon
  info            Domain information
  dcs             Domain Controllers
  users           List/search users
  groups          List/search groups
  computers       List/search computers
  members         Group membership (use -Query)
  userinfo        User details (use -Query)
  compinfo        Computer details (use -Query)
  kerberoast      Kerberoastable accounts
  asreproast      ASREPRoastable accounts
  unconstrained   Unconstrained delegation
  constrained     Constrained delegation
  rbcd            Resource-based constrained delegation
  priv            Privileged users/groups
  laps            Readable LAPS passwords
  gpos            Group Policy Objects
  trusts          Domain trusts
  passwords       Passwords in descriptions
  search          Universal search (use -Query)
  ldap            Custom LDAP (use -Query)

OPTIONS:
  -Query          Search term or LDAP filter
  -Output         Output format: table, csv, json, raw
  -OutFile        Export to file
  -Quick          Abbreviated output
  -SearchBase     Custom search base DN

EXAMPLES:
  .\ADRecon.ps1 -Mode recon
  .\ADRecon.ps1 -Mode kerberoast -Output csv -OutFile spns.csv
  .\ADRecon.ps1 -Mode users -Query admin
  .\ADRecon.ps1 -Mode members -Query "Domain Admins"
  .\ADRecon.ps1 -Mode ldap -Query "(adminCount=1)"
"@
    return
}

$modeMap = @{
    "recon" = { Run-Recon }
    "info" = { Get-DomainInfo }
    "dcs" = { Get-DCHosts }
    "users" = { Get-DomainUsers -Filter $Query }
    "groups" = { Get-DomainGroups -Filter $Query }
    "computers" = { Get-DomainComputers -Filter $Query }
    "members" = { Get-GroupMembers -GroupName $Query -Recursive:$Recursive }
    "userinfo" = { Get-UserInfo -Username $Query }
    "compinfo" = { Get-ComputerInfo -ComputerName $Query }
    "kerberoast" = { Get-Kerberoastable }
    "asreproast" = { Get-ASREPRoastable }
    "unconstrained" = { Get-UnconstrainedDelegation }
    "constrained" = { Get-ConstrainedDelegation }
    "rbcd" = { Get-RBCD }
    "priv" = { Get-PrivilegedUsers }
    "laps" = { Get-LAPS }
    "gpos" = { Get-GPOs }
    "trusts" = { Get-Trusts }
    "passwords" = { Get-PasswordInDescription }
    "search" = { Find-Object -SearchTerm $Query }
    "ldap" = { Custom-LDAP -Filter $Query }
}

if($Mode -ne "interactive" -and $modeMap.ContainsKey($Mode)) {
    & $modeMap[$Mode]
    return
}

# Interactive Mode
while($true) {
    Write-Host "`n[?] Mode (recon/kerberoast/asreproast/users/groups/computers/priv/search/ldap/help/q): " -ForegroundColor Green -NoNewline
    $cmd = Read-Host
    
    if($cmd -eq 'q' -or $cmd -eq 'exit') { break }
    if($cmd -eq 'help' -or $cmd -eq '?') { & $modeMap['recon']; continue }
    if($cmd -eq '') { continue }
    
    $parts = $cmd -split '\s+', 2
    $action = $parts[0].ToLower()
    $arg = if($parts.Count -gt 1) { $parts[1] } else { "" }
    
    switch($action) {
        "recon" { Run-Recon }
        "info" { Get-DomainInfo }
        "dcs" { Get-DCHosts }
        "users" { Get-DomainUsers -Filter $arg }
        "user" { Get-UserInfo -Username $arg }
        "groups" { Get-DomainGroups -Filter $arg }
        "group" { Get-GroupMembers -GroupName $arg }
        "computers" { Get-DomainComputers -Filter $arg }
        "computer" { Get-ComputerInfo -ComputerName $arg }
        "kerberoast" { Get-Kerberoastable }
        "asreproast" { Get-ASREPRoastable }
        "unconstrained" { Get-UnconstrainedDelegation }
        "constrained" { Get-ConstrainedDelegation }
        "rbcd" { Get-RBCD }
        "priv" { Get-PrivilegedUsers }
        "laps" { Get-LAPS }
        "gpos" { Get-GPOs }
        "trusts" { Get-Trusts }
        "passwords" { Get-PasswordInDescription }
        "search" { Find-Object -SearchTerm $arg }
        "ldap" { Custom-LDAP -Filter $arg }
        "find" { Find-Object -SearchTerm $arg }
        default { Write-Host "[-] Unknown: $action (try 'help')" -ForegroundColor Red }
    }
}
#endregion
