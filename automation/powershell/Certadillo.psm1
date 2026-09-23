<#
.SYNOPSIS
  PowerShell client for the Certadillo API (Windows servers, IIS, AD CS migrations).

.EXAMPLE
  Import-Module ./Certadillo.psm1
  Connect-Certadillo -Server https://pki.bank.internal -ApiKey $env:CERTADILLO_API_KEY
  Get-CertadilloCertificate -Status active | Where-Object days_left -lt 14
  Invoke-CertadilloRevoke -Id 42 -Reason superseded -ChangeRef CHG0012345
#>

$script:Server = $null
$script:Headers = @{}

function Connect-Certadillo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Server,
        [Parameter(Mandatory)] [string] $ApiKey
    )
    $script:Server = $Server.TrimEnd('/')
    $script:Headers = @{ 'X-API-Key' = $ApiKey }
    Invoke-CertadilloApi -Method Get -Path '/api/v1/me'
}

function Invoke-CertadilloApi {
    [CmdletBinding()]
    param(
        [ValidateSet('Get', 'Post')] [string] $Method = 'Get',
        [Parameter(Mandatory)] [string] $Path,
        [object] $Body
    )
    if (-not $script:Server) { throw 'Run Connect-Certadillo first.' }
    $params = @{ Method = $Method; Uri = "$($script:Server)$Path"; Headers = $script:Headers; ContentType = 'application/json' }
    if ($PSBoundParameters.ContainsKey('Body')) { $params.Body = ($Body | ConvertTo-Json -Depth 6) }
    Invoke-RestMethod @params
}

function Get-CertadilloCertificate {
    [CmdletBinding()]
    param(
        [ValidateSet('active', 'revoked', 'superseded')] [string] $Status,
        [ValidateSet('issued', 'discovered', 'imported')] [string] $Source,
        [int] $ExpiringWithinDays,
        [int] $Id
    )
    if ($Id) { return Invoke-CertadilloApi -Path "/api/v1/certificates/$Id" }
    $q = @()
    if ($Status) { $q += "status=$Status" }
    if ($Source) { $q += "source=$Source" }
    if ($PSBoundParameters.ContainsKey('ExpiringWithinDays')) { $q += "expiring_within_days=$ExpiringWithinDays" }
    $qs = if ($q) { '?' + ($q -join '&') } else { '' }
    Invoke-CertadilloApi -Path "/api/v1/certificates$qs"
}

function New-CertadilloCertificate {
    <#
      .SYNOPSIS Submit a PEM CSR (for example from certreq or New-SelfSignedCertificate -CertStoreLocation ... -KeyExportPolicy NonExportable).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $CsrPath,
        [int] $AppId,
        [int] $ValidityDays
    )
    $body = @{ csr_pem = (Get-Content -Raw -Path $CsrPath) }
    if ($AppId) { $body.app_id = $AppId }
    if ($ValidityDays) { $body.validity_days = $ValidityDays }
    Invoke-CertadilloApi -Method Post -Path '/api/v1/certificates' -Body $body
}

function Invoke-CertadilloRenew {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [int] $Id, [Parameter(Mandatory)] [string] $CsrPath)
    Invoke-CertadilloApi -Method Post -Path "/api/v1/certificates/$Id/renew" -Body @{ csr_pem = (Get-Content -Raw -Path $CsrPath) }
}

function Invoke-CertadilloRevoke {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [int] $Id,
        [ValidateSet('unspecified', 'key_compromise', 'affiliation_changed', 'superseded', 'cessation_of_operation')]
        [string] $Reason = 'superseded',
        [string] $ChangeRef
    )
    if ($PSCmdlet.ShouldProcess("certificate $Id", "revoke ($Reason)")) {
        Invoke-CertadilloApi -Method Post -Path "/api/v1/certificates/$Id/revoke" -Body @{ reason = $Reason; change_ref = $ChangeRef }
    }
}

function Import-CertadilloInventory {
    <#
      .SYNOPSIS Push certificates from a Windows certificate store into the Certadillo inventory
      (for example LocalMachine\My on every IIS host, or an AD CS database export).
    #>
    [CmdletBinding()]
    param(
        [string] $StorePath = 'Cert:\LocalMachine\My',
        [string] $Location = $env:COMPUTERNAME
    )
    $pem = foreach ($c in Get-ChildItem -Path $StorePath) {
        "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
    }
    if (-not $pem) { Write-Warning "No certificates in $StorePath"; return }
    Invoke-CertadilloApi -Method Post -Path '/api/v1/inventory/import' -Body @{ pem = ($pem -join ''); location = "${Location}:${StorePath}" }
}

function Get-CertadilloAlert {
    [CmdletBinding()] param()
    Invoke-CertadilloApi -Path '/api/v1/alerts'
}

Export-ModuleMember -Function Connect-Certadillo, Invoke-CertadilloApi, Get-CertadilloCertificate, New-CertadilloCertificate,
    Invoke-CertadilloRenew, Invoke-CertadilloRevoke, Import-CertadilloInventory, Get-CertadilloAlert
