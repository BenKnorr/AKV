#region preamble
<#
    title: Client AKV cert downloader

    purpose: 
    Downloads a certificate (including private key) from 
    Azure Key Vault and writes it back to a PFX file.

    assumptions:
    - Az.Accounts, Az.KeyVault modules are installed.
    1.2.1
#>
#endregion

#region static variables

    ##
    ## Log file location and/or outdirectories can be changed as needed here

    $timedate = get-date -Format "yyyyMMdd-HHmmss"
    $timestamp= (get-date).tostring("yyyy-MM-dd HH:mm:ss")
    $currentuser = whoami /upn
    $randomObscureFolder = -join ((48..57 + 65..90 + 97..122) | Get-Random -Count 12 | ForEach-Object { [char]$_ })
    $outdir= "$env:USERPROFILE\$randomObscureFolder"
    $outFile = Join-Path $outdir "$currentuser-$timedate.pfx"
    $RequiredModules = @(
        "Az.Accounts",
        "Az.KeyVault"
    )
    $logfile="$env:userprofile\AKV-userscript.log"
    $akvThumbprints = @{}

#endregion

# ====================================
# Logging Function
# ====================================
#region logging
    
    function Write-Log {
        param(
            [string]$Action,
            [string]$Status = "INFO",
            [string]$ErrorMessage = ""
        )

        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $logEntry = "$timestamp | $Status | $Action"

        if ($ErrorMessage) {
            $logEntry += " | Error: $ErrorMessage"
        }

        Add-Content -Path $LogFile -Value $logEntry
    }
    Write-Log -Action "Script started"

#endregion

# ====================================
# Module Check & Install
# ====================================
#region Module check and install

    foreach ($module in $RequiredModules) {

        try {
            
            if (-not (Get-Module -ListAvailable -Name $module -ErrorAction stop)) {

                Write-Log -Action "Module '$module' not found. Installing..."
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction stop
                Write-Log -Action "Module '$module' installed successfully"

            }

            else {

                Write-Log -Action "Module '$module' already installed"

            }
        }
        catch {

            Write-Log -Action "Failed to install module '$module'" -Status "ERROR" -ErrorMessage $_.Exception.Message
            exit 1

        }
    }
#endregion

# ====================================
# Azure Login
# ====================================
#region Azure Login

    ## this allows interactive login for the admin user who will be uploading the certificate to the respective
    ## keystore in AKV.
    try {

        Write-Log -Action "Attempting Azure login"
        Connect-AzAccount -AccountId "$currentuser" -ErrorAction Stop
        Write-Log -Action "Azure login successful"
        $vaults=Get-AzKeyVault

    }

    catch {

        Write-Log -Action "Azure login failed" -Status "ERROR" -ErrorMessage $_.Exception.Message
        exit 1

    }
    Write-Log -Action "Azure login completed"

#endregion

# ====================================
# Create obscure PFX folder
# ====================================
#region create obscure folder
    
    # creating a folder- note that this will happen each time the script is run, then deleted later.
    $Folder = New-Item -Path $outdir -ItemType Directory -Force
    
    # Set the Hidden attribute
    $Folder.Attributes = $Folder.Attributes -bor [System.IO.FileAttributes]::Hidden

#endregion

# ====================================
# Clean expired certs from localstore
# ====================================
#region checking local certstore

    ## check for "webcares" or "caiso" CA issued certs and
    ## delete user certs that are expired.

    try {
     
        $localCertStore= Get-ChildItem Cert:\currentuser\My |Where-Object {($_.issuer -like "*Caiso*") -or ($_.issuer -like "*WebCares*")}

    }
    
    catch {

        Write-Log -Action "we failed to get the local certficiate store." -Status "ERROR" -ErrorMessage $_.Exception.Message

    }

    foreach ($cert in ($localCertStore)) {

        if ($cert.notafter -lt (get-date)) {

            Write-Log -Action "deleting expired user cert with thumbprint $($cert.thumbprint)"
            Remove-Item (join-path "Cert:\CurrentUser\My" $cert.Thumbprint)

        }
    }

#endregion

# ====================================
# Check AKV for matching local cert
# ====================================
#region AKV cert check and PFX downloader

    ## The user won't know which vaults, subscriptions, or resource groups that they belong to.
    ## this will get all vaults of which they have access.
    
    try {
    
        $vaults=Get-AzKeyVault -erroraction stop
    
    }

    catch {

        write-log -action "we couldn't get get-azkeyvault to work" -Status "ERROR" -ErrorMessage $_.Exception.Message

    }

    foreach ($vault in $vaults){
    
        try {
        
            $matchedkeys = Get-AzKeyVaultCertificate -VaultName $vault.vaultname -ErrorAction stop

        }

        catch {

            write-log -action "we couldn't get get-azkeyvaultcertificate to work" -Status "ERROR" -ErrorMessage $_.Exception.Message

        }

        foreach ($matchedkey in ($matchedKeys |Where-Object {$_.Tags.values -contains $currentuser})) {
                
            ##we're looping through all keys, one at a time in this vault that have the UPN tag of the current logged in user.
            
            try {
               
                $matchedkey = Get-AzKeyVaultCertificate -VaultName $vault.vaultname -Name $matchedkey.name -ErrorAction Stop
                ## ^ this will match a 1 to 1 user cert. it might also match a shared cert with only the tag.
                ## $matchedkey will be the full certificate at this point.
            
            }

            catch {

                write-log -action "we couldn't get get-azkeyvaultcertificate to work" -Status "ERROR" -ErrorMessage $_.Exception.Message

            }
                        
            ## this check looks to see if the current AKV cert in $matchedkey exists in the localstore too
            if ($matchedkey.Certificate.Thumbprint) {

                $akvThumbprints[$matchedkey.Certificate.Thumbprint.ToUpper()] = $matchedkey.Name

            }

            ## local keystore portion : if $localcert get populated, then we have a match from the current
            ## AKV cert in $matchedkey to a cert in the local store with the same thumbprint.
            $localcert = $localCertStore |Where-Object {$_.thumbprint -contains $($matchedkey.Thumbprint)}

            if ([bool]($localcert.Thumbprint)) {

                Write-Log -Action "the cert $($localcert.Thumbprint) is already in the personal store!"    

            }

            ######################### ^ this detects an existing cert properly. BK June 29.2026

            ## we hit this loop if the $matchedkey thumbprint isn't in the local user's cert keystore.
            elseif (-not [bool]($localcert.Thumbprint)) {

                write-log -Action "the cert with AKV thumbprint $($matchedkey.thumbprint) doesn't exist on this system, installing..."
                # matchedkey has the cert & secret that this user has permissions to get from AKV
                   
                #region PFX assembly and import to local user's store

                    ## the rest of this loop assembles the PFX file from AKV for consumption on this client
                        
                    write-log -Action "getting secret for $($matchedkey.name)"

                    try {

                        $secret = Get-AzKeyVaultSecret -VaultName $vault.vaultname -Name $matchedkey.name -ErrorAction stop
                    }

                    catch {

                        write-log -action "we couldn't get get-azkeyvaultsercret to work" -Status "ERROR" -ErrorMessage $_.Exception.Message

                    }

                    write-log -Action "getting secret into bytestream for $($matchedkey.name)"
                    $plainBase64 = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(
                        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret.SecretValue))
                    $pfxBytes = [System.Convert]::FromBase64String($plainBase64)

                    write-log -Action "writing byestream secret for $($matchedkey.name)"
                    $collection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                    $collection.Import($pfxBytes, $null, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)

                    write-log -Action "setting up export for $($matchedkey.name)"
                    $pkcs12Type = [System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12
                    $exported   = $collection.Export($pkcs12Type, $pfxPasswordStr)

                    write-log -Action "writing PFX out to $($outFile) for $($matchedkey.name)"
                    [System.IO.File]::WriteAllBytes($outFile, $exported)
                #endregion

                try {
                
                    $import=Import-PfxCertificate -FilePath "$outFile" -CertStoreLocation Cert:\CurrentUser\My -ErrorAction stop
                    
                }
                
                catch {
                
                     write-log -action "we couldn't get import-pfxcertificate to work on $($outfile)" -Status "ERROR" -ErrorMessage $_.Exception.Message

                }
                       
                if ($import) {

                    write-log -Action "PFX with thumbprint $($matchedkey.Thumbprint) written imported to local store."

                }

                else {

                    write-log -Action "something happened while we were trying to import the PFX to the local store." -ErrorMessage $_.exception.message -Status "ERROR"

                }
            }
        }
    }                   
    Remove-Item $outFile -Force #-ErrorAction SilentlyContinue
    Write-Log -Action "deleted the PFX from $outfile ."
    Remove-Item $outdir -Force #-ErrorAction SilentlyContinue
    Write-Log -Action "removed the obscure directory, $outdir."
                    
#endregion


<# THIS CAN BE ADDED AFTER ALL USER CERTIFICATES HAVE BEEN ONBOARDED INTO AZURE KEY VAULT

# ==========================================
# local cert cleanup for missing cloud certs
# ==========================================
#region local cert cleanup for AKV leavers
#Compare local certificates to Key Vault certificates by thumbprint
foreach ($cert in $localcertstore) {
    $thumbprint = $cert.Thumbprint.ToUpper()

    ## $akvthumbprints has all of of the thumbprints of certificates that live in AKV WITH the user's UPN
    ## in the respective "user:" tag. NOTE that even if a user doesn't have permissions to the cert in AKV,
    ## the tag will still match the user and this script will not try and delete the local cert.
    ## The best practice is to delete the cert in AKV if it needs to be pruned everywhere, or remove the 
    ## "user:" tag.
    if ($akvThumbprints.ContainsKey($thumbprint)) {
        Write-Log -Action "$($cert.thumbprint) has been found in our local user's cert store and in AKV."
    }
    else {
        Remove-Item -Path  "Cert:\currentuser\My\$($thumbprint)"     
        Write-Log -Action "$($cert.Thumbprint) is here, but not in AKV! this one has been deleted."
    }
}
#prune local certs that are misisng from AKV that are in scope.
#endregion
#>
