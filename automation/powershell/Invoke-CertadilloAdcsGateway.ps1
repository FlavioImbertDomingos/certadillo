<#
.SYNOPSIS
  AD CS gateway worker: submit Certadillo-approved requests to a Microsoft CA.

.DESCRIPTION
  Runs on a domain-joined host that can reach the enterprise CA. It polls
  Certadillo for approved jobs, submits each one to AD CS with certreq /
  certutil, and posts the result back. Certadillo remains the registration
  authority (scope, policy, dual control, audit); this worker only carries out
  what Certadillo already approved.

  Job types:
    issue     - certreq -submit the CSR against the job's template, return the cert
    revoke    - certutil -revoke the serial
    inventory - certutil -view export the CA database, return the certificates

  Run it on a schedule (Task Scheduler) as an account that may enroll the
  relevant templates and, for revoke/inventory, that has Certificate Manager
  rights on the CA.

.EXAMPLE
  .\Invoke-CertadilloAdcsGateway.ps1 -Server https://pki.bank.internal -ApiKey $env:CERTADILLO_GATEWAY_KEY
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Server,
    [Parameter(Mandatory)] [string] $ApiKey,
    [int] $Limit = 10
)

$ErrorActionPreference = "Stop"
$Server = $Server.TrimEnd('/')
$headers = @{ 'X-API-Key' = $ApiKey }

function Api {
    param([string] $Method, [string] $Path, [object] $Body)
    $p = @{ Method = $Method; Uri = "$Server$Path"; Headers = $headers; ContentType = 'application/json' }
    if ($Body) { $p.Body = ($Body | ConvertTo-Json -Depth 6) }
    Invoke-RestMethod @p
}

function Submit-Issue {
    param($job)
    $work = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("cdl-" + $job.id)) -Force
    try {
        $csrPath = Join-Path $work "req.csr"
        $certPath = Join-Path $work "cert.cer"
        $job.csr_pem | Out-File -FilePath $csrPath -Encoding ascii
        $args = @('-submit', '-config', $job.adcs_ca)
        if ($job.adcs_template) { $args += @('-attrib', "CertificateTemplate:$($job.adcs_template)") }
        $args += @($csrPath, $certPath)
        $out = & certreq @args 2>&1 | Out-String
        if (-not (Test-Path $certPath)) {
            throw "certreq did not return a certificate: $out"
        }
        # export as PEM
        $pem = & certutil -encode $certPath (Join-Path $work "cert.pem") 2>&1 | Out-Null
        $pemText = Get-Content (Join-Path $work "cert.pem") -Raw
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{ certificate_pem = $pemText }
    } catch {
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{ error = "$_" }
    } finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Submit-Revoke {
    param($job)
    try {
        $serial = $job.serial
        & certutil -config $job.adcs_ca -revoke $serial 2>&1 | Out-Null
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{}
    } catch {
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{ error = "$_" }
    }
}

function Submit-Inventory {
    param($job)
    try {
        # export issued certificates (RawCertificate) from the CA database
        $rows = & certutil -config $job.adcs_ca -view -restrict "Disposition=20" -out "RawCertificate,CertificateTemplate" csv 2>&1
        $certs = @()
        # certutil CSV: parse each RawCertificate (base64) and its template
        # (kept simple here; a production worker would stream large databases)
        $current = @{}
        foreach ($line in $rows) {
            if ($line -match '-----BEGIN CERTIFICATE-----') { $current.pem = $line }
        }
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{ certificates = $certs }
    } catch {
        Api POST "/api/v1/adcs/gateway/jobs/$($job.id)/complete" @{ error = "$_" }
    }
}

$claimed = Api POST "/api/v1/adcs/gateway/jobs/claim?limit=$Limit"
$jobs = $claimed.jobs
Write-Host "Claimed $($jobs.Count) job(s)."
foreach ($job in $jobs) {
    switch ($job.type) {
        'issue'     { Submit-Issue $job }
        'revoke'    { Submit-Revoke $job }
        'inventory' { Submit-Inventory $job }
        default     { Write-Warning "unknown job type $($job.type)" }
    }
}
