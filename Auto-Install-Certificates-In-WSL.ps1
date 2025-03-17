<#
.SYNOPSIS
    This script searches for certificates with a specific description pattern, exports them, installs them in WSL, and checks the response using curl.

.DESCRIPTION
    The script searches for certificates with a specific description pattern. It exports each certificate, installs them in WSL, and checks the response using curl. If the response is not correct, it tries the next certificate from the results. If the list is exhausted and WSL still responds with an incorrect answer, it throws an error.

.PARAMETER DescriptionPattern
    The pattern to search for in the certificate description. Default is "CA".

.PARAMETER ExcludeIssuers
    An array of issuer names to exclude from the results. Default is an array of common built-in certificate issuers.

.PARAMETER WSLDistro
    The WSL distribution to install the certificate in. Default is "Ubuntu".

.PARAMETER UpdateCommand
    The command to update the CA certificates. Default is the value from the $wslDistros array.

.PARAMETER Verbose
    Enables verbose output.

.EXAMPLE
    .\Auto-Install-CertificatesInWSL.ps1 -Verbose

.EXAMPLE
    .\Auto-Install-CertificatesInWSL.ps1 -DescriptionPattern "CA" -ExcludeIssuers @("DigiCert", "thawte") -WSLDistro "Ubuntu" -Verbose

.LINK
    Related topic: https://github.com/microsoft/WSL/issues/3161

.LINK
    Source of "$wslDistros" array: https://stackoverflow.com/a/77672453
#>

param (
    [string]$DescriptionPattern = "CA",
    [string[]]$ExcludeIssuers = @(
        "DigiCert",
        "thawte",
        "Digital Signature Trust Co.",
        "GlobalSign",
        "Microsoft",
        "SSL.com",
        "Entrust",
        "COMODO",
        "Starfield",
        "VeriSign",
        "Go Daddy",
        "USERTrust",
        "IdenTrust",
        "QuoVadis",
        "Certum",
        "AAA Certificate Services",
        "AddTrust",
        "Sectigo",
        "Symantec",
        "Hotspot 2.0 Trust Root CA",
        "WFA Hotspot 2.0"
    ),
    [string]$WSLDistro,
    [string]$UpdateCommand,
    [switch]$Verbose
)

if ($Verbose) {
    $VerbosePreference = "Continue"
}

$wslDistros = @{
    "Alpine" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apk add ca-certificates" }
    "Amazon Linux" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "Arch" = @{ Path = "/etc/ca-certificates/trust-source/anchors/"; Command = "trust extract-compat"; Install = "pacman -Sy ca-certificates-utils" }
    "CentOS" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "CoreOS" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-certificates"; Install = "Built into the system" }
    "Debian" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "Fedora" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "dnf install ca-certificates" }
    "RedHat" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "SUSE" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates"; Install = "zypper install ca-certificates" }
    "Ubuntu" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "Ubuntu-18.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "Ubuntu-20.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "Ubuntu-22.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "Ubuntu-24.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
    "OracleLinux_7_9" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "OracleLinux_8_7" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "OracleLinux_9_1" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract"; Install = "yum install ca-certificates" }
    "openSUSE-Leap-15.6" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates"; Install = "zypper install ca-certificates" }
    "SUSE-Linux-Enterprise-15-SP5" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates"; Install = "zypper install ca-certificates" }
    "SUSE-Linux-Enterprise-15-SP6" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates"; Install = "zypper install ca-certificates" }
    "openSUSE-Tumbleweed" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates"; Install = "zypper install ca-certificates" }
    "kali-linux" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates"; Install = "apt-get install -y ca-certificates" }
}

$addresses = @(
    "https://google.com/"
)

function Get-DefaultWSLDistro {
    $registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    $defaultDistro = Get-ItemProperty -Path $registryPath -Name DefaultDistribution | Select-Object -ExpandProperty DefaultDistribution
    $defaultDistro = (Get-ItemProperty -Path "$registryPath\$defaultDistro").DistributionName

    return $defaultDistro
}

function Test-WSL {
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        return $false
    }
    try {
        $wslOutput = wsl -l -q | Where-Object { $_ -ne "" }
        if ($wslOutput) {
            return $true
        }
    } catch {
        return $false
    }
}

function Test-CurlAvailability {
    param (
        [string]$WSLDistro
    )

    # Check if curl is available in the target WSL distribution
    $commandCheck = "if command -v curl > /dev/null 2>&1; then echo true; else echo false; fi"
    $commandAvailable = wsl -d $WSLDistro -u root -e bash -c $commandCheck
    return $commandAvailable -eq "true"
}

function Search-Certificates {
    param (
        [string]$DescriptionPattern,
        [string[]]$ExcludeIssuers
    )

    $storeLocations = @("LocalMachine", "CurrentUser")
    $storeNames = @("My", "Root", "CA", "AuthRoot", "TrustedPublisher", "TrustedPeople", "Disallowed")

    $results = @()
    foreach ($storeLocation in $storeLocations) {
        foreach ($storeName in $storeNames) {
            $storePath = "Cert:\$storeLocation\$storeName"
            Write-Verbose "Searching certificates in store: $storePath"

            $certificates = Get-ChildItem -Path $storePath -Recurse
            foreach ($cert in $certificates) {
                if ($cert.Subject -like "*$DescriptionPattern*" -and $cert.Issuer -notmatch ($ExcludeIssuers -join "|")) {
                    Write-Verbose "Matched certificate: $($cert.PSPath)"
                    $results += $cert
                }
            }
        }
    }

    return $results
}

function Export-CertificateToFile {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,
        [string]$FilePath
    )
    Write-Verbose "Exporting certificate to file: $FilePath"
    $certBytes = $Cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
    $base64CertContent = [System.Convert]::ToBase64String($certBytes)
    
    # Insert line breaks every 64 characters
    $formattedCertContent = ($base64CertContent -split "(.{64})" | Where-Object { $_ -ne "" }) -join "`n"
    
    $base64CertHeader = "-----BEGIN CERTIFICATE-----"
    $base64CertFooter = "-----END CERTIFICATE-----"
    $base64Cert = $base64CertHeader + "`n" + $formattedCertContent + "`n" + $base64CertFooter

    Set-Content -Path $FilePath -Value $base64Cert -ErrorAction Stop
}

function Remove-OldCertificateFromWSL {
    param (
        [string]$CertFileName,
        [string]$WSLDistro
    )

    try {
        # Remove the old certificate from WSL
        $removeCommand = "rm -f /usr/local/share/ca-certificates/$CertFileName"
        $removeOutput = wsl -d $WSLDistro -u root -e bash -c $removeCommand
        Write-Verbose ($removeOutput -join "`n")
    } catch {
        Write-Error "An error occurred while removing the old certificate from WSL: $($_ -join "`n")"
        throw
    }
}

function Install-CertificateInWSL {
    param (
        [string]$CertFilePath,
        [string]$WSLDistro,
        [string]$UpdateCommand,
        [string]$CertPath
    )

    $certFileName = [System.IO.Path]::GetFileName($CertFilePath)

    try {
        # Copy the certificate to WSL using WSL commands
        $copyCommand = "cp --verbose ./$certFileName $CertPath"
        $copyOutput = wsl --cd "$(Split-Path -Path $CertFilePath)" -d $WSLDistro -u root -e bash -c $copyCommand
        Write-Verbose ($copyOutput -join "`n")
    
        # Check if the file exists in WSL
        $checkCommand = "test -f $CertPath/$certFileName && echo 'File exists' || echo 'File does not exist'"
        $checkOutput = wsl --cd "$(Split-Path -Path $CertFilePath)" -d $WSLDistro -u root -e bash -c $checkCommand
        Write-Verbose ($checkOutput -join "`n")
    
        if ($checkOutput -like "*File exists*") {
            Write-Output "Certificate copied to ${CertPath}${certFileName}"
        } else {
            throw "Failed to copy certificate to $CertPath$certFileName"
        }
    
        # Check if the update command is available
        $commandCheck = "if command -v $UpdateCommand > /dev/null 2>&1; then echo true; else echo false; fi"
        $commandAvailable = wsl --cd "$(Split-Path -Path $CertFilePath)" -d $WSLDistro -u root -e bash -c $commandCheck
        Write-Verbose "Command check output: $commandAvailable"
    
        if ($commandAvailable -eq "true") {
            Write-Output "Success: $UpdateCommand is available in WSL."
            # Run the update command
            $updateOutput = wsl --cd "$(Split-Path -Path $CertFilePath)" -d $WSLDistro -u root -e bash -c $UpdateCommand
            Write-Verbose ($updateOutput -join "`n")
            Write-Output "CA certificates updated in WSL."
        } else {
            Write-Output "Failed: $UpdateCommand is not available in WSL."
            # Append the CA certificate directly to ca-certificates.crt
            $appendCommand = "cat $CertPath/$certFileName | sudo tee -a /etc/ssl/certs/ca-certificates.crt > /dev/null"
            $appendOutput = wsl --cd "$(Split-Path -Path $CertFilePath)" -d $WSLDistro -u root -e bash -c $appendCommand
            Write-Verbose ($appendOutput -join "`n")
            Write-Output "CA certificate appended directly to /etc/ssl/certs/ca-certificates.crt."
        }
    
    } catch {
        Write-Error "An error occurred while installing the certificate in WSL: $($_ -join "`n")"
        throw
    }
}

function Test-CertificateInWSL {
    param (
        [string]$WSLDistro,
        [string]$Address
    )

    # Run curl in WSL to check the response
    $output = wsl -d $WSLDistro -- bash -c "curl -s -o /dev/null -w '%{http_code}' $Address"
    return $output
}

function Main {
    param (
        [string]$DescriptionPattern,
        [string[]]$ExcludeIssuers,
        [string]$WSLDistro,
        [string]$UpdateCommand,
        [switch]$Verbose
    )

    if (-not (Test-WSL)) {
        throw "WSL is not available or no distributions are installed."
    }

    if (-not $WSLDistro) {
        $WSLDistro = Get-DefaultWSLDistro
        if (-not $WSLDistro) {
            throw "No default WSL distribution found. Please specify a WSL distribution using the -WSLDistro parameter."
        }
    }

    if (-not $wslDistros.ContainsKey($WSLDistro)) {
        throw "Unsupported WSL distribution: $WSLDistro"
    }

    if (-not (Test-CurlAvailability -WSLDistro $WSLDistro)) {
        throw "curl is not available in the target WSL distribution: ${WSLDistro}"
    }

    if (-not $UpdateCommand) {
        $UpdateCommand = $wslDistros[$WSLDistro].Command
    }

    $certPath = $wslDistros[$WSLDistro].Path

    # Search for certificates
    $certificates = Search-Certificates -DescriptionPattern $DescriptionPattern -ExcludeIssuers $ExcludeIssuers

    foreach ($cert in $certificates) {
        # Extract CN value from issuer and replace spaces with underscores
        $issuerCN = ($cert.Issuer -match "CN=([^,]+)") | Out-Null; $issuerCN = $matches[1] -replace " ", "_"
        $certFileName = "$issuerCN.crt"
        $certFilePath = Join-Path -Path $env:TEMP -ChildPath $certFileName
    
        # Export certificate to file
        Export-CertificateToFile -Cert $cert -FilePath $certFilePath
    
        # Remove old certificate from WSL
        Remove-OldCertificateFromWSL -CertFileName $certFileName -WSLDistro $WSLDistro
    
        # Install certificate in WSL
        Install-CertificateInWSL -CertFilePath $certFilePath -WSLDistro $WSLDistro -UpdateCommand $UpdateCommand -CertPath $certPath
    
        # Check certificate in WSL for each address
        $success = $false
        foreach ($address in $addresses) {
            $response = Test-CertificateInWSL -WSLDistro $WSLDistro -Address $address
            Write-Verbose "Response from Test-CertificateInWSL for ${address}: $response"
            if ($response -ge 200 -and $response -lt 400) {
                Write-Output "Certificate installed and verified successfully for ${address}."
                $success = $true
                break
            } else {
                Write-Warning "Certificate did not pass verification for ${address}."
            }
        }
    
        if ($success) {
            Write-Output "Certificate installed and verified successfully for at least one address."
            return
        } else {
            Write-Warning "Certificate verification failed for all addresses. Trying next certificate."
            Remove-OldCertificateFromWSL -CertFileName $certFileName -WSLDistro $WSLDistro
        }
    }
    
    throw "No valid certificate found that passes verification."
}

# Call the main function with parameters
Main -DescriptionPattern $DescriptionPattern -ExcludeIssuers $ExcludeIssuers -WSLDistro $WSLDistro -UpdateCommand $UpdateCommand -Verbose:$Verbose