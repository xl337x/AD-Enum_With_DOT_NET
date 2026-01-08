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
#region Interactive Listing System
function Show-ListMenu {
    Write-Host "`n[LIST] What do you want to browse?" -ForegroundColor Cyan
    Write-Host "  [1] Users" -ForegroundColor Yellow
    Write-Host "  [2] Groups" -ForegroundColor Yellow
    Write-Host "  [3] Computers" -ForegroundColor Yellow
    Write-Host "  [4] OUs (Organizational Units)" -ForegroundColor Yellow
    Write-Host "  [5] GPOs (Group Policy Objects)" -ForegroundColor Yellow
    Write-Host "  [6] Domain Controllers" -ForegroundColor Yellow
    Write-Host "  [7] Service Accounts (SPNs)" -ForegroundColor Yellow
    Write-Host "  [8] Privileged Users (AdminCount=1)" -ForegroundColor Yellow
    Write-Host "  [9] Disabled Accounts" -ForegroundColor Yellow
    Write-Host "  [10] Trusts" -ForegroundColor Yellow
    Write-Host "  [0] Back" -ForegroundColor Gray
    Write-Host "`n[?] Choice: " -ForegroundColor Green -NoNewline
    return Read-Host
}

function List-AndSelect {
    param(
        [array]$Items,
        [string]$DisplayProperty,
        [string]$Title,
        [scriptblock]$DetailFunction
    )
    
    if($Items.Count -eq 0) {
        Write-Host "[-] No items found" -ForegroundColor Yellow
        return
    }
    
    $pageSize = 20
    $currentPage = 0
    $totalPages = [math]::Ceiling($Items.Count / $pageSize)
    
    while($true) {
        Clear-Host
        Write-Host "`n[LIST] $Title ($($Items.Count) total)" -ForegroundColor Cyan
        Write-Host "Page $($currentPage + 1)/$totalPages" -ForegroundColor Gray
        Write-Host ("-" * 50) -ForegroundColor DarkGray
        
        $startIdx = $currentPage * $pageSize
        $endIdx = [math]::Min($startIdx + $pageSize - 1, $Items.Count - 1)
        
        for($i = $startIdx; $i -le $endIdx; $i++) {
            $item = $Items[$i]
            $displayName = if($item -is [PSCustomObject] -or $item -is [hashtable]) {
                $item.$DisplayProperty
            } elseif($item.Properties) {
                $item.Properties[$DisplayProperty][0]
            } else {
                $item.ToString()
            }
            
            $num = $i + 1
            $color = "White"
            
            # Color coding based on properties
            if($item.Properties) {
                if($item.Properties['admincount'] -and $item.Properties['admincount'][0] -eq 1) { $color = "Red" }
                elseif($item.Properties['serviceprincipalname']) { $color = "Yellow" }
                elseif($item.Properties['useraccountcontrol']) {
                    $uac = [int]$item.Properties['useraccountcontrol'][0]
                    if($uac -band 2) { $color = "DarkGray" }  # Disabled
                }
            }
            
            Write-Host "  [$num] $displayName" -ForegroundColor $color
        }
        
        Write-Host ("-" * 50) -ForegroundColor DarkGray
        Write-Host "[n]ext [p]rev [f]ilter [#]select [0]back: " -ForegroundColor Green -NoNewline
        $choice = Read-Host
        
        switch($choice.ToLower()) {
            'n' { if($currentPage -lt $totalPages - 1) { $currentPage++ } }
            'p' { if($currentPage -gt 0) { $currentPage-- } }
            '0' { return }
            'f' {
                Write-Host "[?] Filter term: " -ForegroundColor Yellow -NoNewline
                $filterTerm = Read-Host
                if($filterTerm) {
                    $filtered = $Items | Where-Object {
                        $val = if($_.Properties) { $_.Properties[$DisplayProperty][0] } else { $_.$DisplayProperty }
                        $val -like "*$filterTerm*"
                    }
                    if($filtered.Count -gt 0) {
                        List-AndSelect -Items $filtered -DisplayProperty $DisplayProperty -Title "$Title (filtered: $filterTerm)" -DetailFunction $DetailFunction
                    } else {
                        Write-Host "[-] No matches for '$filterTerm'" -ForegroundColor Red
                        Start-Sleep -Seconds 1
                    }
                }
            }
            default {
                if($choice -match '^\d+$') {
                    $idx = [int]$choice - 1
                    if($idx -ge 0 -and $idx -lt $Items.Count) {
                        $selected = $Items[$idx]
                        if($DetailFunction) {
                            & $DetailFunction $selected
                            Write-Host "`n[Press Enter to continue]" -ForegroundColor Gray -NoNewline
                            Read-Host
                        }
                    }
                }
            }
        }
    }
}

function Browse-Users {
    Write-Host "`n[*] Loading users..." -ForegroundColor Gray
    $users = LDAP -Filter "(samAccountType=805306368)" -Properties @("samaccountname","cn","description","memberof","admincount","serviceprincipalname","useraccountcontrol","pwdlastset","lastlogon")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-UserDetail -Username $name
    }
    
    List-AndSelect -Items $users -DisplayProperty "samaccountname" -Title "Domain Users" -DetailFunction $detailFunc
}

function Browse-Groups {
    Write-Host "`n[*] Loading groups..." -ForegroundColor Gray
    $groups = LDAP -Filter "(objectClass=group)" -Properties @("samaccountname","cn","description","member","memberof","admincount","grouptype")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        if(-not $name) { $name = $obj.Properties['cn'][0] }
        Show-GroupDetail -GroupName $name
    }
    
    List-AndSelect -Items $groups -DisplayProperty "samaccountname" -Title "Domain Groups" -DetailFunction $detailFunc
}

function Browse-Computers {
    Write-Host "`n[*] Loading computers..." -ForegroundColor Gray
    $computers = LDAP -Filter "(objectClass=computer)" -Properties @("samaccountname","dnshostname","operatingsystem","operatingsystemversion","lastlogon","description")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-ComputerDetail -ComputerName $name
    }
    
    List-AndSelect -Items $computers -DisplayProperty "samaccountname" -Title "Domain Computers" -DetailFunction $detailFunc
}

function Browse-OUs {
    Write-Host "`n[*] Loading OUs..." -ForegroundColor Gray
    $ous = LDAP -Filter "(objectClass=organizationalUnit)" -Properties @("name","distinguishedname","description","whencreated")
    
    $detailFunc = {
        param($obj)
        $dn = $obj.Properties['distinguishedname'][0]
        $name = $obj.Properties['name'][0]
        Show-OUDetail -OUDN $dn -OUName $name
    }
    
    List-AndSelect -Items $ous -DisplayProperty "name" -Title "Organizational Units" -DetailFunction $detailFunc
}

function Browse-GPOs {
    Write-Host "`n[*] Loading GPOs..." -ForegroundColor Gray
    $gpos = LDAP -Filter "(objectClass=groupPolicyContainer)" -Properties @("displayname","distinguishedname","gpcfilesyspath","whencreated","whenchanged")
    
    $detailFunc = {
        param($obj)
        Show-GPODetail -GPOObj $obj
    }
    
    List-AndSelect -Items $gpos -DisplayProperty "displayname" -Title "Group Policy Objects" -DetailFunction $detailFunc
}

function Browse-DCs {
    Write-Host "`n[*] Loading Domain Controllers..." -ForegroundColor Gray
    $dcs = LDAP -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" -Properties @("samaccountname","dnshostname","operatingsystem","operatingsystemversion","lastlogon")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-ComputerDetail -ComputerName $name
    }
    
    List-AndSelect -Items $dcs -DisplayProperty "samaccountname" -Title "Domain Controllers" -DetailFunction $detailFunc
}

function Browse-ServiceAccounts {
    Write-Host "`n[*] Loading service accounts (users with SPNs)..." -ForegroundColor Gray
    $spns = LDAP -Filter "(&(samAccountType=805306368)(servicePrincipalName=*))" -Properties @("samaccountname","serviceprincipalname","description","pwdlastset","admincount","memberof")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-UserDetail -Username $name
    }
    
    List-AndSelect -Items $spns -DisplayProperty "samaccountname" -Title "Service Accounts (Kerberoastable)" -DetailFunction $detailFunc
}

function Browse-PrivilegedUsers {
    Write-Host "`n[*] Loading privileged users (AdminCount=1)..." -ForegroundColor Gray
    $admins = LDAP -Filter "(&(samAccountType=805306368)(adminCount=1))" -Properties @("samaccountname","description","memberof","pwdlastset","lastlogon","serviceprincipalname")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-UserDetail -Username $name
    }
    
    List-AndSelect -Items $admins -DisplayProperty "samaccountname" -Title "Privileged Users (AdminCount=1)" -DetailFunction $detailFunc
}

function Browse-DisabledAccounts {
    Write-Host "`n[*] Loading disabled accounts..." -ForegroundColor Gray
    $disabled = LDAP -Filter "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties @("samaccountname","description","memberof","pwdlastset","whencreated")
    
    $detailFunc = {
        param($obj)
        $name = $obj.Properties['samaccountname'][0]
        Show-UserDetail -Username $name
    }
    
    List-AndSelect -Items $disabled -DisplayProperty "samaccountname" -Title "Disabled Accounts" -DetailFunction $detailFunc
}

function Browse-Trusts {
    Write-Host "`n[*] Loading domain trusts..." -ForegroundColor Gray
    $trusts = LDAP -Filter "(objectClass=trustedDomain)" -Properties @("name","trustpartner","trustdirection","trusttype","trustattributes","whencreated")
    
    $detailFunc = {
        param($obj)
        Show-TrustDetail -TrustObj $obj
    }
    
    List-AndSelect -Items $trusts -DisplayProperty "name" -Title "Domain Trusts" -DetailFunction $detailFunc
}

# Detail display functions
function Show-UserDetail {
    param([string]$Username)
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[USER] $Username" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $user = LDAP -Filter "(samaccountname=$Username)" -Properties @("*")
    if(-not $user) { Write-Host "[-] User not found" -ForegroundColor Red; return }
    
    $p = $user[0].Properties
    
    # Basic Info
    Write-Host "`n[Basic Information]" -ForegroundColor Yellow
    @("samaccountname","cn","displayname","description","mail","title","department","company") | ForEach-Object {
        if($p[$_]) { Write-Host "  $_`: $($p[$_][0])" -ForegroundColor White }
    }
    
    # Security Info
    Write-Host "`n[Security]" -ForegroundColor Yellow
    if($p['useraccountcontrol']) {
        $uac = [int]$p['useraccountcontrol'][0]
        $flags = @()
        if($uac -band 2) { $flags += "DISABLED" }
        if($uac -band 32) { $flags += "PASSWD_NOTREQD" }
        if($uac -band 65536) { $flags += "DONT_EXPIRE_PASSWORD" }
        if($uac -band 4194304) { $flags += "DONT_REQ_PREAUTH" }
        if($uac -band 524288) { $flags += "TRUSTED_FOR_DELEGATION" }
        if($flags) { Write-Host "  UAC Flags: $($flags -join ', ')" -ForegroundColor $(if($flags -contains "DISABLED"){"DarkGray"}else{"Red"}) }
    }
    if($p['admincount'] -and $p['admincount'][0] -eq 1) { Write-Host "  AdminCount: 1 [PRIVILEGED]" -ForegroundColor Red }
    Write-Host "  Password Last Set: $(Convert-LDAPTime $p['pwdlastset'][0])" -ForegroundColor White
    Write-Host "  Last Logon: $(Convert-LDAPTime $p['lastlogon'][0])" -ForegroundColor White
    if($p['badpwdcount']) { Write-Host "  Bad Password Count: $($p['badpwdcount'][0])" -ForegroundColor White }
    if($p['logoncount']) { Write-Host "  Logon Count: $($p['logoncount'][0])" -ForegroundColor White }
    
    # SPNs
    if($p['serviceprincipalname']) {
        Write-Host "`n[Service Principal Names] - KERBEROASTABLE" -ForegroundColor Red
        foreach($spn in $p['serviceprincipalname']) {
            Write-Host "  $spn" -ForegroundColor Yellow
        }
    }
    
    # Group Memberships
    if($p['memberof']) {
        Write-Host "`n[Group Memberships]" -ForegroundColor Yellow
        foreach($g in $p['memberof']) {
            $gname = ($g -split ',')[0] -replace 'CN=',''
            $color = if($gname -match "Admin|Domain|Enterprise|Schema|Backup|Server Operators") { "Red" } else { "White" }
            Write-Host "  $gname" -ForegroundColor $color
        }
    }
    
    # Actions
    Write-Host "`n[Actions]" -ForegroundColor Cyan
    Write-Host "  [1] Show all properties" -ForegroundColor Gray
    Write-Host "  [2] Check ACLs on this user" -ForegroundColor Gray
    Write-Host "  [3] Copy DN to clipboard" -ForegroundColor Gray
    Write-Host "  [0] Back" -ForegroundColor Gray
    Write-Host "[?] Action: " -ForegroundColor Green -NoNewline
    $action = Read-Host
    
    switch($action) {
        '1' {
            Write-Host "`n[All Properties]" -ForegroundColor Cyan
            foreach($prop in $p.PropertyNames | Sort-Object) {
                $val = $p[$prop]
                if($val.Count -eq 1) { Write-Host "  $prop`: $($val[0])" -ForegroundColor White }
                else { Write-Host "  $prop`: [$($val -join ', ')]" -ForegroundColor White }
            }
        }
        '2' {
            Write-Host "`n[ACLs - Dangerous permissions highlighted]" -ForegroundColor Cyan
            # Quick ACL check
            $dn = $p['distinguishedname'][0]
            try {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
                $acl = $de.ObjectSecurity
                foreach($ace in $acl.Access) {
                    if($ace.AccessControlType -ne "Allow") { continue }
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    if($rights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl|WriteProperty|ExtendedRight") {
                        if($ace.IdentityReference -notmatch "NT AUTHORITY|BUILTIN|SELF|S-1-5-10") {
                            Write-Host "  $($ace.IdentityReference): $rights" -ForegroundColor Yellow
                        }
                    }
                }
            } catch { Write-Host "  [-] Unable to read ACLs" -ForegroundColor Red }
        }
        '3' {
            $p['distinguishedname'][0] | Set-Clipboard
            Write-Host "[+] DN copied to clipboard" -ForegroundColor Green
        }
    }
}

function Show-GroupDetail {
    param([string]$GroupName)
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[GROUP] $GroupName" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $group = LDAP -Filter "(|(samaccountname=$GroupName)(cn=$GroupName))" -Properties @("*")
    if(-not $group) { Write-Host "[-] Group not found" -ForegroundColor Red; return }
    
    $p = $group[0].Properties
    
    # Basic Info
    Write-Host "`n[Basic Information]" -ForegroundColor Yellow
    @("samaccountname","cn","description","whencreated") | ForEach-Object {
        if($p[$_]) { Write-Host "  $_`: $($p[$_][0])" -ForegroundColor White }
    }
    
    if($p['admincount'] -and $p['admincount'][0] -eq 1) { 
        Write-Host "  AdminCount: 1 [PRIVILEGED GROUP]" -ForegroundColor Red 
    }
    
    # Group Type
    if($p['grouptype']) {
        $gt = [int]$p['grouptype'][0]
        $scope = switch($gt -band 0x0000000F) { 2 { "Global" } 4 { "Domain Local" } 8 { "Universal" } default { "Unknown" } }
        $type = if($gt -band 0x80000000) { "Security" } else { "Distribution" }
        Write-Host "  Type: $type $scope" -ForegroundColor White
    }
    
    # Members
    $members = $p['member']
    if($members) {
        Write-Host "`n[Members] ($($members.Count) total)" -ForegroundColor Yellow
        $memberLimit = 20
        $shown = 0
        foreach($m in $members) {
            if($shown -ge $memberLimit) { 
                Write-Host "  ... and $($members.Count - $memberLimit) more" -ForegroundColor DarkGray
                break 
            }
            $mname = ($m -split ',')[0] -replace 'CN=',''
            Write-Host "  $mname" -ForegroundColor White
            $shown++
        }
    } else {
        Write-Host "`n[Members] None" -ForegroundColor Yellow
    }
    
    # Member Of
    if($p['memberof']) {
        Write-Host "`n[Member Of]" -ForegroundColor Yellow
        foreach($g in $p['memberof']) {
            $gname = ($g -split ',')[0] -replace 'CN=',''
            Write-Host "  $gname" -ForegroundColor White
        }
    }
    
    # Actions
    Write-Host "`n[Actions]" -ForegroundColor Cyan
    Write-Host "  [1] List all members (detailed)" -ForegroundColor Gray
    Write-Host "  [2] List all members (recursive)" -ForegroundColor Gray
    Write-Host "  [3] Check ACLs on this group" -ForegroundColor Gray
    Write-Host "  [4] Browse members interactively" -ForegroundColor Gray
    Write-Host "  [0] Back" -ForegroundColor Gray
    Write-Host "[?] Action: " -ForegroundColor Green -NoNewline
    $action = Read-Host
    
    switch($action) {
        '1' {
            Write-Host "`n[All Members - Detailed]" -ForegroundColor Cyan
            foreach($m in $members) {
                $mObj = LDAP -Filter "(distinguishedName=$m)" -Properties @("samaccountname","objectclass","description")
                if($mObj) {
                    $mp = $mObj[0].Properties
                    $mtype = $mp['objectclass'][-1]
                    Write-Host "  [$mtype] $($mp['samaccountname'][0])" -ForegroundColor $(if($mtype -eq "group"){"Yellow"}else{"White"})
                }
            }
        }
        '2' {
            Write-Host "`n[Recursive Members]" -ForegroundColor Cyan
            Get-GroupMembers -GroupName $GroupName -Recursive
        }
        '3' {
            Write-Host "`n[ACLs - Dangerous permissions]" -ForegroundColor Cyan
            $dn = $p['distinguishedname'][0]
            try {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($script:PDC)/$dn")
                $acl = $de.ObjectSecurity
                foreach($ace in $acl.Access) {
                    if($ace.AccessControlType -ne "Allow") { continue }
                    $rights = $ace.ActiveDirectoryRights.ToString()
                    if($rights -match "GenericAll|GenericWrite|WriteOwner|WriteDacl|WriteProperty|Self") {
                        if($ace.IdentityReference -notmatch "NT AUTHORITY|BUILTIN|SELF|S-1-5-10") {
                            Write-Host "  $($ace.IdentityReference): $rights" -ForegroundColor Yellow
                        }
                    }
                }
            } catch { Write-Host "  [-] Unable to read ACLs" -ForegroundColor Red }
        }
        '4' {
            if($members) {
                $memberObjs = @()
                foreach($m in $members) {
                    $mObj = LDAP -Filter "(distinguishedName=$m)" -Properties @("samaccountname","objectclass","description","admincount")
                    if($mObj) { $memberObjs += $mObj[0] }
                }
                List-AndSelect -Items $memberObjs -DisplayProperty "samaccountname" -Title "Members of $GroupName" -DetailFunction {
                    param($obj)
                    $type = $obj.Properties['objectclass'][-1]
                    $name = $obj.Properties['samaccountname'][0]
                    if($type -eq "user") { Show-UserDetail -Username $name }
                    elseif($type -eq "group") { Show-GroupDetail -GroupName $name }
                    elseif($type -eq "computer") { Show-ComputerDetail -ComputerName $name }
                }
            }
        }
    }
}

function Show-ComputerDetail {
    param([string]$ComputerName)
    
    if(-not $ComputerName.EndsWith('$')) { $ComputerName = "$ComputerName$" }
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[COMPUTER] $ComputerName" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $comp = LDAP -Filter "(samaccountname=$ComputerName)" -Properties @("*")
    if(-not $comp) { Write-Host "[-] Computer not found" -ForegroundColor Red; return }
    
    $p = $comp[0].Properties
    
    # Basic Info
    Write-Host "`n[Basic Information]" -ForegroundColor Yellow
    @("samaccountname","dnshostname","description","operatingsystem","operatingsystemversion","operatingsystemservicepack") | ForEach-Object {
        if($p[$_]) { Write-Host "  $_`: $($p[$_][0])" -ForegroundColor White }
    }
    Write-Host "  Last Logon: $(Convert-LDAPTime $p['lastlogon'][0])" -ForegroundColor White
    Write-Host "  Created: $($p['whencreated'][0])" -ForegroundColor White
    
    # Security Info
    Write-Host "`n[Security]" -ForegroundColor Yellow
    if($p['useraccountcontrol']) {
        $uac = [int]$p['useraccountcontrol'][0]
        $flags = @()
        if($uac -band 8192) { $flags += "SERVER_TRUST_ACCOUNT (DC)" }
        if($uac -band 524288) { $flags += "TRUSTED_FOR_DELEGATION (UNCONSTRAINED!)" }
        if($uac -band 16777216) { $flags += "TRUSTED_TO_AUTH_FOR_DELEGATION" }
        if($flags) { 
            foreach($f in $flags) {
                $color = if($f -match "UNCONSTRAINED") { "Red" } else { "Yellow" }
                Write-Host "  $f" -ForegroundColor $color
            }
        }
    }
    
    # Delegation
    if($p['msds-allowedtodelegateto']) {
        Write-Host "`n[Constrained Delegation Targets]" -ForegroundColor Red
        foreach($t in $p['msds-allowedtodelegateto']) {
            Write-Host "  $t" -ForegroundColor Yellow
        }
    }
    
    if($p['msds-allowedtoactonbehalfofotheridentity']) {
        Write-Host "`n[RBCD Configured]" -ForegroundColor Red
        Write-Host "  This computer has resource-based constrained delegation!" -ForegroundColor Yellow
    }
    
    # SPNs
    if($p['serviceprincipalname']) {
        Write-Host "`n[Service Principal Names]" -ForegroundColor Yellow
        foreach($spn in $p['serviceprincipalname'] | Select-Object -First 10) {
            Write-Host "  $spn" -ForegroundColor White
        }
        if($p['serviceprincipalname'].Count -gt 10) {
            Write-Host "  ... and $($p['serviceprincipalname'].Count - 10) more" -ForegroundColor DarkGray
        }
    }
    
    # LAPS
    if($p['ms-mcs-admpwd']) {
        Write-Host "`n[LAPS PASSWORD READABLE!]" -ForegroundColor Green
        Write-Host "  Password: $($p['ms-mcs-admpwd'][0])" -ForegroundColor Green
        if($p['ms-mcs-admpwdexpirationtime']) {
            Write-Host "  Expires: $(Convert-LDAPTime $p['ms-mcs-admpwdexpirationtime'][0])" -ForegroundColor Green
        }
    }
    
    # Group Memberships
    if($p['memberof']) {
        Write-Host "`n[Group Memberships]" -ForegroundColor Yellow
        foreach($g in $p['memberof']) {
            $gname = ($g -split ',')[0] -replace 'CN=',''
            Write-Host "  $gname" -ForegroundColor White
        }
    }
}

function Show-OUDetail {
    param([string]$OUDN, [string]$OUName)
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[OU] $OUName" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $ou = LDAP -Filter "(distinguishedName=$OUDN)" -Properties @("*")
    if(-not $ou) { Write-Host "[-] OU not found" -ForegroundColor Red; return }
    
    $p = $ou[0].Properties
    
    Write-Host "`n[Information]" -ForegroundColor Yellow
    Write-Host "  Name: $($p['name'][0])" -ForegroundColor White
    Write-Host "  DN: $OUDN" -ForegroundColor White
    if($p['description']) { Write-Host "  Description: $($p['description'][0])" -ForegroundColor White }
    Write-Host "  Created: $($p['whencreated'][0])" -ForegroundColor White
    
    # Count objects in OU
    $users = LDAP -Filter "(objectClass=user)" -Base $OUDN -Props @("samaccountname")
    $computers = LDAP -Filter "(objectClass=computer)" -Base $OUDN -Props @("samaccountname")
    $groups = LDAP -Filter "(objectClass=group)" -Base $OUDN -Props @("samaccountname")
    
    Write-Host "`n[Contents]" -ForegroundColor Yellow
    Write-Host "  Users: $($users.Count)" -ForegroundColor White
    Write-Host "  Computers: $($computers.Count)" -ForegroundColor White
    Write-Host "  Groups: $($groups.Count)" -ForegroundColor White
    
    # Linked GPOs
    if($p['gplink']) {
        Write-Host "`n[Linked GPOs]" -ForegroundColor Yellow
        $gplinks = $p['gplink'][0] -split '\]\[' | ForEach-Object { $_ -replace '^\[|;.*$','' }
        foreach($gp in $gplinks) {
            if($gp) {
                $gpoObj = LDAP -Filter "(distinguishedName=$gp)" -Props @("displayname")
                if($gpoObj) { Write-Host "  $($gpoObj[0].Properties['displayname'][0])" -ForegroundColor White }
            }
        }
    }
    
    # Actions
    Write-Host "`n[Actions]" -ForegroundColor Cyan
    Write-Host "  [1] Browse users in this OU" -ForegroundColor Gray
    Write-Host "  [2] Browse computers in this OU" -ForegroundColor Gray
    Write-Host "  [3] Browse groups in this OU" -ForegroundColor Gray
    Write-Host "  [0] Back" -ForegroundColor Gray
    Write-Host "[?] Action: " -ForegroundColor Green -NoNewline
    $action = Read-Host
    
    switch($action) {
        '1' {
            if($users.Count -gt 0) {
                List-AndSelect -Items $users -DisplayProperty "samaccountname" -Title "Users in $OUName" -DetailFunction {
                    param($obj)
                    Show-UserDetail -Username $obj.Properties['samaccountname'][0]
                }
            }
        }
        '2' {
            if($computers.Count -gt 0) {
                List-AndSelect -Items $computers -DisplayProperty "samaccountname" -Title "Computers in $OUName" -DetailFunction {
                    param($obj)
                    Show-ComputerDetail -ComputerName $obj.Properties['samaccountname'][0]
                }
            }
        }
        '3' {
            if($groups.Count -gt 0) {
                List-AndSelect -Items $groups -DisplayProperty "samaccountname" -Title "Groups in $OUName" -DetailFunction {
                    param($obj)
                    Show-GroupDetail -GroupName $obj.Properties['samaccountname'][0]
                }
            }
        }
    }
}

function Show-GPODetail {
    param($GPOObj)
    
    $p = $GPOObj.Properties
    $name = $p['displayname'][0]
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[GPO] $name" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    Write-Host "`n[Information]" -ForegroundColor Yellow
    Write-Host "  Display Name: $name" -ForegroundColor White
    Write-Host "  DN: $($p['distinguishedname'][0])" -ForegroundColor White
    Write-Host "  SYSVOL Path: $($p['gpcfilesyspath'][0])" -ForegroundColor White
    Write-Host "  Created: $($p['whencreated'][0])" -ForegroundColor White
    Write-Host "  Modified: $($p['whenchanged'][0])" -ForegroundColor White
    
    # Find where it's linked
    Write-Host "`n[Linked To]" -ForegroundColor Yellow
    $gpoDN = $p['distinguishedname'][0]
    $linkedOUs = LDAP -Filter "(gplink=*$gpoDN*)" -Props @("distinguishedname","name")
    if($linkedOUs.Count -gt 0) {
        foreach($ou in $linkedOUs) {
            Write-Host "  $($ou.Properties['distinguishedname'][0])" -ForegroundColor White
        }
    } else {
        Write-Host "  Not linked to any OUs" -ForegroundColor DarkGray
    }
}

function Show-TrustDetail {
    param($TrustObj)
    
    $p = $TrustObj.Properties
    $name = $p['name'][0]
    
    Write-Host "`n" + ("=" * 60) -ForegroundColor Cyan
    Write-Host "[TRUST] $name" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    
    $trustDir = @{0="Disabled";1="Inbound";2="Outbound";3="Bidirectional"}
    $trustType = @{1="Windows NT";2="Active Directory";3="MIT Kerberos";4="DCE"}
    
    Write-Host "`n[Information]" -ForegroundColor Yellow
    Write-Host "  Trust Partner: $($p['trustpartner'][0])" -ForegroundColor White
    Write-Host "  Direction: $($trustDir[[int]$p['trustdirection'][0]])" -ForegroundColor White
    Write-Host "  Type: $($trustType[[int]$p['trusttype'][0]])" -ForegroundColor White
    Write-Host "  Created: $($p['whencreated'][0])" -ForegroundColor White
    
    $attrs = [int]$p['trustattributes'][0]
    $attrFlags = @()
    if($attrs -band 1) { $attrFlags += "NON_TRANSITIVE" }
    if($attrs -band 2) { $attrFlags += "UPLEVEL_ONLY" }
    if($attrs -band 4) { $attrFlags += "QUARANTINED" }
    if($attrs -band 8) { $attrFlags += "FOREST_TRANSITIVE" }
    if($attrs -band 16) { $attrFlags += "CROSS_ORGANIZATION" }
    if($attrs -band 32) { $attrFlags += "WITHIN_FOREST" }
    if($attrs -band 64) { $attrFlags += "TREAT_AS_EXTERNAL" }
    
    if($attrFlags) {
        Write-Host "  Attributes: $($attrFlags -join ', ')" -ForegroundColor Yellow
    }
}

function Start-ListBrowser {
    while($true) {
        $choice = Show-ListMenu
        
        switch($choice) {
            '1' { Browse-Users }
            '2' { Browse-Groups }
            '3' { Browse-Computers }
            '4' { Browse-OUs }
            '5' { Browse-GPOs }
            '6' { Browse-DCs }
            '7' { Browse-ServiceAccounts }
            '8' { Browse-PrivilegedUsers }
            '9' { Browse-DisabledAccounts }
            '10' { Browse-Trusts }
            '0' { return }
            default { Write-Host "[-] Invalid choice" -ForegroundColor Red }
        }
    }
}
#endregion

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
  list            Interactive browser - browse and drill down into AD objects
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

LIST BROWSER:
  The 'list' mode opens an interactive browser where you can:
  - Browse Users, Groups, Computers, OUs, GPOs, DCs, Trusts
  - Browse Service Accounts (SPNs), Privileged Users, Disabled Accounts
  - Paginate through large result sets
  - Filter results by name
  - Select any object to see detailed info
  - Drill down (e.g., select a group -> see members -> select a member)
  - Check ACLs on selected objects
  - View recursive group memberships

OPTIONS:
  -Query          Search term or LDAP filter
  -Output         Output format: table, csv, json, raw
  -OutFile        Export to file
  -Quick          Abbreviated output
  -SearchBase     Custom search base DN

EXAMPLES:
  .\ADRecon.ps1 -Mode recon
  .\ADRecon.ps1 -Mode list                                    # Interactive browser
  .\ADRecon.ps1 -Mode kerberoast -Output csv -OutFile spns.csv
  .\ADRecon.ps1 -Mode users -Query admin
  .\ADRecon.ps1 -Mode members -Query "Domain Admins"
  .\ADRecon.ps1 -Mode ldap -Query "(adminCount=1)"

INTERACTIVE COMMANDS:
  list            Open the interactive browser
  users [filter]  List users (optional filter)
  user <name>     Show user details
  groups [filter] List groups (optional filter)
  group <name>    Show group members
  computers       List computers
  computer <name> Show computer details
  kerberoast      Find kerberoastable accounts
  asreproast      Find ASREPRoastable accounts
  priv            Show privileged users
  search <term>   Search everywhere
  ldap <filter>   Custom LDAP query
  q               Quit
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
    "list" = { Start-ListBrowser }
}

if($Mode -ne "interactive" -and $modeMap.ContainsKey($Mode)) {
    & $modeMap[$Mode]
    return
}

# Interactive Mode
while($true) {
    Write-Host "`n[?] Mode (recon/list/kerberoast/asreproast/users/groups/computers/priv/search/ldap/help/q): " -ForegroundColor Green -NoNewline
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
        "list" { Start-ListBrowser }
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
        default { Write-Host "[-] Unknown: $action (try 'help' or 'list')" -ForegroundColor Red }
    }
}
#endregion
