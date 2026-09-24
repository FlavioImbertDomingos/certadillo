<#
.SYNOPSIS
  Export AD CS certificate templates and CA configuration for a Certadillo
  template security audit.

.DESCRIPTION
  Reads the AD Configuration naming context over ADSI (templates, issuance-
  policy OIDs and their group links, enrollment services, NTAuth) and, for
  each reachable CA, the policy EditFlags and interface flags with certutil.
  Writes a JSON document that Certadillo audits with:

      certadillo adcs audit --json adcs-export.json
      # or POST the document to /api/v1/adcs/audit/import

  Read-only. Needs only default domain read access; run as any domain user.
  The CA registry read (certutil -getreg) works remotely when the caller can
  reach the CA, and is skipped with a note when it cannot.

.EXAMPLE
  .\Export-CertadilloAdcsTemplates.ps1 -Path adcs-export.json
#>
[CmdletBinding()]
param(
    [string] $Path = "adcs-export.json"
)

$ErrorActionPreference = "Stop"

function Get-ConfigNC {
    ([ADSI]"LDAP://RootDSE").configurationNamingContext
}

function Convert-SdToBase64 {
    param($entry)
    # nTSecurityDescriptor comes back as a byte[] in the ADSI property.
    $sd = $entry.Properties["nTSecurityDescriptor"]
    if ($null -eq $sd -or $sd.Count -eq 0) { return $null }
    [Convert]::ToBase64String([byte[]] $sd[0])
}

function Get-MultiString {
    param($entry, [string] $name)
    $vals = $entry.Properties[$name]
    if ($null -eq $vals) { return @() }
    @($vals | ForEach-Object { "$_" })
}

$configNC = Get-ConfigNC
$pkiBase = "CN=Public Key Services,CN=Services,$configNC"

# ------------------------------------------------------------------ OID group links
$oidLinks = @{}
$oidContainer = [ADSI]"LDAP://CN=OID,$pkiBase"
foreach ($oid in $oidContainer.Children) {
    if ($oid.SchemaClassName -ne "msPKI-Enterprise-Oid") { continue }
    $oidValue = "$($oid.Properties['msPKI-Cert-Template-OID'][0])"
    $groupLink = $oid.Properties["msDS-OIDToGroupLink"]
    if ($oidValue -and $groupLink -and $groupLink.Count -gt 0) {
        $oidLinks[$oidValue] = "$($groupLink[0])"
    }
}

# ------------------------------------------------------------------ templates
$templates = @()
$templateContainer = [ADSI]"LDAP://CN=Certificate Templates,$pkiBase"
foreach ($t in $templateContainer.Children) {
    if ($t.SchemaClassName -ne "pKICertificateTemplate") { continue }
    $templates += [ordered]@{
        name                  = "$($t.Properties['cn'][0])"
        display_name          = "$($t.Properties['displayName'][0])"
        schema_version        = [int]("$($t.Properties['msPKI-Template-Schema-Version'][0])" -as [int])
        name_flags            = [int]("$($t.Properties['msPKI-Certificate-Name-Flag'][0])" -as [int])
        enrollment_flags      = [int]("$($t.Properties['msPKI-Enrollment-Flag'][0])" -as [int])
        ra_signatures         = [int]("$($t.Properties['msPKI-RA-Signature'][0])" -as [int])
        ekus                  = Get-MultiString $t "pKIExtendedKeyUsage"
        application_policies  = Get-MultiString $t "msPKI-RA-Application-Policies"
        certificate_policies  = Get-MultiString $t "msPKI-Certificate-Policy"
        security_descriptor   = Convert-SdToBase64 $t
    }
}

# ------------------------------------------------------------------ NTAuth thumbprints
$ntauth = @()
try {
    $ntAuthEntry = [ADSI]"LDAP://CN=NTAuthCertificates,$pkiBase"
    foreach ($cert in $ntAuthEntry.Properties["cACertificate"]) {
        $x = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, [byte[]] $cert)
        $ntauth += $x.Thumbprint.ToLower()
    }
} catch {
    Write-Warning "Could not read NTAuthCertificates: $_"
}

# ------------------------------------------------------------------ CAs (enrollment services + registry)
function Get-CaEditFlags {
    param([string] $configString)
    # certutil -getreg reports the policy EditFlags and the interface flags.
    try {
        $edit = (& certutil -config $configString -getreg "Policy\EditFlags") 2>$null | Out-String
        $iface = (& certutil -config $configString -getreg "CA\InterfaceFlags") 2>$null | Out-String
        $disabled = (& certutil -config $configString -getreg "Policy\DisableExtensionList") 2>$null | Out-String
        $editVal = 0
        if ($edit -match "0x([0-9a-fA-F]+)") { $editVal = [Convert]::ToInt64($Matches[1], 16) }
        $ifaceVal = 0
        if ($iface -match "0x([0-9a-fA-F]+)") { $ifaceVal = [Convert]::ToInt64($Matches[1], 16) }
        $disabledList = @()
        foreach ($line in ($disabled -split "`n")) {
            if ($line -match "([0-9]+(\.[0-9]+)+)") { $disabledList += $Matches[1] }
        }
        # IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
        $enforceEncrypt = [bool]($ifaceVal -band 0x00000200)
        return @{ edit_flags = $editVal; enforce_encrypt_request = $enforceEncrypt; disabled_extensions = $disabledList; ok = $true }
    } catch {
        return @{ ok = $false }
    }
}

$cas = @()
$enrollContainer = [ADSI]"LDAP://CN=Enrollment Services,$pkiBase"
foreach ($ca in $enrollContainer.Children) {
    if ($ca.SchemaClassName -ne "pKIEnrollmentService") { continue }
    $caName = "$($ca.Properties['cn'][0])"
    $dns = "$($ca.Properties['dNSHostName'][0])"
    $entry = [ordered]@{
        name                 = $caName
        dns                  = $dns
        request_disposition  = "issue"
        edit_flags           = 0
        disabled_extensions  = @()
        enforce_encrypt_request = $null
        web_enrollment_http  = $false
        web_enrollment_https = $false
    }
    $reg = Get-CaEditFlags "$dns\$caName"
    if ($reg.ok) {
        $entry.edit_flags = $reg.edit_flags
        $entry.enforce_encrypt_request = $reg.enforce_encrypt_request
        $entry.disabled_extensions = $reg.disabled_extensions
    } else {
        Write-Warning "Could not read registry flags for $caName; ESC6/11/16 not evaluated for it."
    }
    $cas += $entry
}

$doc = [ordered]@{
    generated        = (Get-Date).ToUniversalTime().ToString("o")
    forest           = $configNC
    templates        = $templates
    cas              = $cas
    oid_group_links  = $oidLinks
    ntauth_thumbprints = $ntauth
}

$doc | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding utf8
Write-Host "Wrote $Path : $($templates.Count) templates, $($cas.Count) CAs, $($oidLinks.Count) OID links."
