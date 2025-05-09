# FSMO Role Transfer Script
# Safely checks and optionally transfers all FSMO roles (standard + hidden)
# Requires: Domain Admin permissions, must be run from a domain controller

Import-Module ActiveDirectory

$dcName = $env:COMPUTERNAME

# Confirm this machine is a domain controller
try {
    $thisDC = Get-ADDomainController -Identity $dcName -ErrorAction Stop
} catch {
    Write-Warning "🚫 This machine is not a domain controller. Exiting."
    return
}

# Fetch local DC's NTDS object path for FSMO ownership transfers
$ntdsDN = $thisDC.NTDSSettingsObjectDN
$domain = Get-ADDomain
$forest = Get-ADForest
$domainDN = $domain.DistinguishedName
$forestDN = ($forest.Name.Split('.') | ForEach-Object { "DC=$_" }) -join ','

# Construct hidden FSMO DNs
$forestDnsZones  = "CN=Infrastructure,DC=ForestDnsZones,$forestDN"
$domainDnsZones  = "CN=Infrastructure,DC=DomainDnsZones,$domainDN"

# === Standard FSMO Roles ===
$rolesToTransfer = @{}
$roleMap = @{
    SchemaMaster         = $forest.SchemaMaster
    DomainNamingMaster   = $forest.DomainNamingMaster
    RIDMaster            = $domain.RIDMaster
    PDCEmulator          = $domain.PDCEmulator
    InfrastructureMaster = $domain.InfrastructureMaster
}
$roleNumbers = @{
    SchemaMaster         = 0
    DomainNamingMaster   = 1
    RIDMaster            = 2
    PDCEmulator          = 3
    InfrastructureMaster = 4
}

Write-Host "`n===== Standard FSMO Role Check =====" -ForegroundColor Cyan

foreach ($role in $roleMap.Keys) {
    $currentHolder = ($roleMap[$role] -split '\\.')[0]
    if ($currentHolder -ieq $dcName) {
        Write-Host "✔ $role is already held by this server." -ForegroundColor Green
    } else {
        Write-Warning "$role is currently held by $currentHolder"
        $confirm = Read-Host "Do you want to transfer $role to this server? (Y/N)"
        if ($confirm -match '^y') {
            $rolesToTransfer[$role] = $roleNumbers[$role]
        }
    }
}

if ($rolesToTransfer.Count -gt 0) {
    $roleIds = $rolesToTransfer.Values
    Move-ADDirectoryServerOperationMasterRole -Identity $dcName -OperationMasterRole $roleIds -Confirm:$true
} else {
    Write-Host "No standard FSMO roles need transferring." -ForegroundColor Yellow
}

# === Hidden FSMO Roles ===
Write-Host "`n===== Hidden FSMO Role Check =====" -ForegroundColor Cyan

function Check-And-TransferHiddenFSMO {
    param (
        [string]$name,
        [string]$dn
    )

    try {
        $obj = Get-ADObject -Identity $dn -Properties fSMORoleOwner -ErrorAction Stop
    } catch {
        Write-Host "⏭ $name not found. Skipping (likely not created in this forest)." -ForegroundColor DarkYellow
        return
    }

    $fSMORoleOwner = $obj.fSMORoleOwner

    # Detect tombstoned (orphaned) owner
    $isTombstoned = $fSMORoleOwner -match '\\0ADEL:' -or $fSMORoleOwner -match '\\0ADEL:'

    if ($isTombstoned) {
        Write-Warning "$name is currently assigned to a deleted server object (orphaned)."
        $confirm = Read-Host "Do you want to seize $name to this server? (Y/N)"
        if ($confirm -match '^y') {
            Set-ADObject -Identity $dn -Replace @{fSMORoleOwner = $ntdsDN}
            Write-Host "$name seized by $dcName." -ForegroundColor Green
        } else {
            Write-Host "Skipped seizing $name." -ForegroundColor Yellow
        }
    }
    else {
        $currentDC = ($fSMORoleOwner -split ',')[1] -replace '^CN=', ''
        if ($currentDC -ieq $dcName) {
            Write-Host "✔ $name is already held by this server." -ForegroundColor Green
        } else {
            Write-Warning "$name is currently held by $currentDC"
            $confirm = Read-Host "Do you want to transfer $name to this server? (Y/N)"
            if ($confirm -match '^y') {
                Set-ADObject -Identity $dn -Replace @{fSMORoleOwner = $ntdsDN}
                Write-Host "$name transferred to $dcName." -ForegroundColor Green
            } else {
                Write-Host "Skipped transferring $name." -ForegroundColor Yellow
            }
        }
    }
}

Check-And-TransferHiddenFSMO -name "ForestDnsZones" -dn $forestDnsZones
Check-And-TransferHiddenFSMO -name "DomainDnsZones" -dn $domainDnsZones

# === Final Report ===
Write-Host "`n===== Final FSMO Role Holders =====" -ForegroundColor Cyan
$domain = Get-ADDomain
$forest = Get-ADForest
$forestDns = Get-ADObject -Identity $forestDnsZones -Partition "DC=ForestDnsZones,$forestDN" -Properties fSMORoleOwner -ErrorAction SilentlyContinue
$domainDns = Get-ADObject -Identity $domainDnsZones -Properties fSMORoleOwner -ErrorAction SilentlyContinue

function ShortName($dn) {
    if ($dn -and $dn -like '*CN=*') {
        return ($dn -split ',')[1] -replace '^CN=', ''
    } elseif ($dn -like '*\\0ADEL:*') {
        return '[Orphaned]'
    } else {
        return '[Unknown]'
    }
}

$summary = [PSCustomObject]@{
    SchemaMaster         = ($forest.SchemaMaster -split '\\.')[0]
    DomainNamingMaster   = ($forest.DomainNamingMaster -split '\\.')[0]
    RIDMaster            = ($domain.RIDMaster -split '\\.')[0]
    PDCEmulator          = ($domain.PDCEmulator -split '\\.')[0]
    InfrastructureMaster = ($domain.InfrastructureMaster -split '\\.')[0]
    ForestDnsZones       = ShortName($forestDns.fSMORoleOwner)
    DomainDnsZones       = ShortName($domainDns.fSMORoleOwner)
}

$summary | Format-List

Write-Host "`n✅ FSMO role check and transfer complete." -ForegroundColor Cyan
