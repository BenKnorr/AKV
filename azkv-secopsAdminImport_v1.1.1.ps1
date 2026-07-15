#region preamble
<#
    title : Azure Key Vault upload tool
    written by Ben Knorr, bknorr@compunet.biz

    this script is written for optimal functionality with powershell version 7. version 5 gives unexpected
    results.

    steps: 
    *install/check AZKV modules
    *connect to AZKV with Entra user with proper permissions
    functionality:
    1) Find, select and confirm .pfx file
    2) Open PFX file using user supplied password
    3) Parse PFX public key's subject information
    4.1) Check Entra for user-email attribute match to the certificate's "E" subject (if it exists)
    4.2) Check Entra for a user's display name match to the certificate's "CN" subject.
        * note that certificate should almost always have a Common Name [CN], and may not have an email [E]
        in their subjects. If the script gets to this point, a CN will be attempted to be matched based
        on "display name" of a user in Entra and the CN value in a cert's subject. If they can't be matched,
        the user/admin will need to supply a UPN of a valid Entra user manually to be associated with this
        certificate.
    5) Show user the proposed certificate to user mapping and ask for confirmation
    6) Import to Azure Key Vault after prompting user which vault is being targeted
    7) Set tags on imported certificate to align with imported user and selected vault name, and apply RBAC
        to corresponding secret.
    8) Delete PFX file and exit.

    v1.1.1
#>
#endregion



# ============================
# Static Variable Definitions
# ============================
#region variable static definitions
    ## this role is required to be assigned to both the certificate scope and the secret scope for the user.
    $userAKVrole="Key Vault Certificate User"
    
    ## tag app and user keys are for the uploaded certificate's tag names. Tag values will be populated via
    ## user interaction during the upload process. the "user" tag is used by the client-side script. the
    ## app tag is only used for informational purposes and not for any IAM purposes.
    $tagAppKey="App"
    $tagUserKey="User"
    
    $LogFile = "C:\Scripts\MyScript.log"
    ## These modules are required for the script to execute properly.
    $RequiredModules = @(
        "Az.Accounts",
        "Az.KeyVault",
        "Az.Resources"
    )
    ## This script assumes that the manually obtained PFX file lives in the current user's downloads folder.
    $Downloads = Join-Path $env:USERPROFILE "Downloads"
#endregion

# ============================
# Logging Function
# ============================
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

# ============================
# Module Check & Install
# ============================
#region Module check and install

    foreach ($module in $RequiredModules) {

        try {

            if (-not (Get-Module -ListAvailable -Name $module -erroraction stop)) {

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

# ============================
# Azure Login
# ============================
#region Azure Login

## this allows interactive login for the admin user who will be uploading the certificate to the respective
## keystore in AKV.
    try {

        Write-Log -Action "Attempting Azure login"
        Connect-AzAccount -ErrorAction Stop
        Write-Log -Action "Azure login successful"
    
    }
    
    catch {
        
        Write-Log -Action "Azure login failed" -Status "ERROR" -ErrorMessage $_.Exception.Message
        exit 1
    
    }
    Write-Log -Action "Azure login completed"
#endregion



######### SCRIPT REPEAT START ##########
while ($scriptRepeat) {

    # ============================
    # Step 1 — Prompt for PFX Path
    # ============================
    #region Get PFX path

        Write-Log -Action "Prompting user for PFX file path"
        Write-Host "
        ################################################
        ########  Step 1 — Prompt for PFX Path  ########
        ################################################" -ForegroundColor white


        # Find all .pfx files, sorted by last modified date (newest first)
        $pfxFiles = Get-ChildItem -Path $downloads -Filter *.pfx | Sort-Object LastWriteTime -Descending

        write-host "`tWhich PFX file in your DOWNLOADS folder do you want to use? (sorted by date modified)" -ForegroundColor Yellow
        # Display numbered list
        for ($i = 0; $i -lt $pfxFiles.Count; $i++) {

            $num = $i + 1
            Write-Host "`t$num) $($pfxFiles[$i].Name)" -ForegroundColor cyan
        
        }

        # Add manual option
        $manualOption = $pfxFiles.Count + 1
        Write-Host "`t$manualOption) Manually specify your own PFX path" -ForegroundColor Cyan

        # Prompt user
        write-host "Select a PFX file by number" -ForegroundColor Magenta
        $selection = Read-Host

        if ([int]$selection -eq $manualOption) {
            
            $manualPFXcheck=$null
            while (-not $manualPFXcheck) {
            
                write-host  "Enter full path to your PFX file" -foregroundcolor magenta
                $PfxPath = Read-Host
                if (test-path $pfxpath){
                    Write-Log -action "admin supplied PFX path is valid for $pfxpath"
                    $manualPFXcheck=$true
                }
                else {
                    write-host "`t `"$pfxpath`" couldn't be found. Please try again." -ForegroundColor Yellow
                }
            }

        } 

        else {
            
            $PfxPath = $pfxFiles[[int]$selection - 1].FullName
        
        }

        Write-Log -Action "PFX file exists: $PfxPath"
        Write-Host "`tSUCCESS! $PfxPath file exists." -ForegroundColor Green
    #endregion

    # ============================
    # Step 2 — Load PFX & Prompt for Password
    # ============================
    #region Load PFX and get password
        Write-Host "
        ##############################################
        ###### Step 2 — Load PFX with password  ######
        ##############################################" -ForegroundColor white

        ## 1. Capture the password as a SecureString
        Write-Host "`nEnter the password for the PFX file:" -ForegroundColor magenta
        $PfxPasswordSecure = Read-Host -AsSecureString

        Write-Log -Action "Attempting to load PFX certificate"

        try {
        
            ## 2. Load the certificate using the SecureString overload
            ## The 'Exportable' flag is not needed if you only intend to view public info
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $PfxPath, 
                $PfxPasswordSecure, 
                [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet
            )

            Write-Log -Action "PFX certificate loaded successfully"
            Write-Host "`tSUCCESS! PFX certificate loaded successfully" -ForegroundColor Green
        
        }
        
        catch {
        
            Write-Log -Action "Failed to load PFX certificate" -Status "ERROR" -ErrorMessage $_.Exception.Message
            throw "`tCould not load certificate. Maybe a bad password?"
        
        }
    #endregion

    # ============================
    # Step 3 — Parse Certificate Subject
    # ============================
    #region Parse Certificate Subject
        Write-Host "
        ################################################
        ####### Step 3 — Parse PFX cert subject  #######
        ################################################" -ForegroundColor white
        
        Write-Host "
        This script is only checking values of the certificate's subject shown below.
        CN [Common Name], E [email address], OU [org unit], O [org]"
        Write-Log -Action "Parsing certificate subject"

        ## we haven't included any error handling in this loop since $cert is populated with verified good data.

        ## The PFX file's public key is open at this point. We are pulling subject information to compare against
        ## a valid user in Entra. 
        $SubjectParts = $Cert.Subject -split ",\s*" | ForEach-Object {

            $kv = $_ -split "=", 2
            [PSCustomObject]@{ Key = $kv[0]; Value = $kv[1] }
        
        }

        $CN = ($SubjectParts | Where-Object Key -eq "CN").Value
        $E  = ($SubjectParts | Where-Object Key -eq "E").Value
        $OU = ($SubjectParts | Where-Object Key -eq "OU").Value
        $O  = ($SubjectParts | Where-Object Key -eq "O").Value

        Write-Host "`n`tCertificate Details:" -ForegroundColor Yellow
        Write-Host "`tCN: $CN`n`tE : $E`tOU: $OU`n`tO : $O" -ForegroundColor cyan

        Write-Log -Action "Extracted certificate subject fields: CN=$CN, E=$E, OU=$OU, O=$O"
    #endregion

    # ============================
    # Step 4.1 — Search Entra for User by Email (E)
    # ============================
    #region Find user in Entra using certificate email attribute

        ## This section checks Entra for a user that matches the email attribute in the certificate subject.
        ## The logic is that when the email value in the cert matches an Entra user's, it can be surmised
        ## that the cert+user go together. This is preferable to CN since the CN can be somewhat arbitrary,
        ## such as "Ben shared contractor" or "TEMP CAISO USER". If a cert is generated for shared users,
        ## the email attribute may be missing from the cert and the process will need to go to the next step.

        Write-Host "
        ################################################
        ### Step 4.1 — Check Entra for user by Email ###
        ################################################" -ForegroundColor white

        Write-Host "
        This method is preferred as it matches a unique email address in
        the certificate's subject to a user's email in Entra. If it doesn't
        match, we will continue to attempt a match based on CN/Display Name." -ForegroundColor white
        $MatchedUser = $null
        $MatchSource = ""

        if ($E) {

            Write-Log -Action "Searching Entra ID for user by email: $E"
            
            try {
            
                $MatchedUser = Get-AzADUser -Filter "mail eq '$E'" -ErrorAction Stop
                
                if ([bool]($MatchedUser)) {
            
                    Write-Host "`tFound Entra ID user by certificate email:" -ForegroundColor Yellow
                    Write-Host "`t$($MatchedUser.UserPrincipalName)" -ForegroundColor Cyan
                    $MatchSource = "Email"
                    Write-Log -Action "Found Entra ID user by certificate email: $($MatchedUser.UserPrincipalName)"
            
                }
            
                else {
            
                    Write-Host "`tWARNING! No Entra ID user found using the certificate's E attribute:" -ForegroundColor Red
                    Write-Host "`t ($E)." -ForegroundColor Red
                    write-host "`n`tGoing to CN match next." -ForegroundColor Yellow
                    Write-Log -Action "No Entra ID user found by email to UPN matching"
            
                }
            }
            
            catch {
            
                Write-Log -Action "We failed running get-adazuser while trying to find an Entra user by email lookup" -Status "ERROR" -ErrorMessage $_.Exception.Message
                exit

            }
        }

        else {
            
            Write-Log -Action "Certificate missing E attribute; skipping email lookup"
        
        }
    #endregion

    # ============================
    # Step 4.2 — If no email match, try CN-based match
    # ============================
    #region Find user in Azure using CN if no email was found in previous step

        ## Note that this step is only processed fully if the previous step did not succeed.
        ## The matching source in this region is either UPN or CN.
        ## Passing through this region is only possible is if a matcheduser is found here or
        ## in previous region.

        Write-Host "
        ################################################
        #### Step 4.2 — Check Entra for user by CN  ####
        ################################################" -ForegroundColor white

        Write-Host "
        We will try to match the certificate's CN with an Entra user's
        'Display Name' attribute. There may be inconsistencies with
        CN vs. Display name; the script will attempt to match them
        automatically." -ForegroundColor white
        
        Write-Log -Action "Attempting CN-based lookup"

        # Extract display name before "x####"
        $DisplayNameCandidate = $CN -replace "x\d+$","" -replace "\s+$",""
        Write-Host "`n`tOur CN-derived display name:" -ForegroundColor Yellow
        Write-Host "`t$displaynamecandidate`n" -ForegroundColor Cyan
        
        try {

            $MatchedUser = Get-AzADUser -Filter "displayName eq '$DisplayNameCandidate'" -ErrorAction Stop

        }
        catch {

            Write-Log -Action "failed to run `'ge-azaduser`' while attempting to get a user based on the certificate's sanitized CN." -Status "ERROR" -ErrorMessage $_.Exception.Message

        }

        if ($MatchedUser) {

            ## this loop is processed only if the display name in entra matches the certificate's CN field. No other actions are needed in this 4.2 section.
            $MatchSource = "DisplayName"
            
            Write-Host "`tSUCCESS!" -foregroundcolor green
            write-host "`tEntra display name & certificate CN match:" -ForegroundColor yellow
            Write-Host "`tENTRA   : $matcheduser.displayname`n`tCERT-CN : $displaynamecandidate" -ForegroundColor Green
            Write-Log -Action "Found matching certificate CN to Entra user Display Name: $ManualUPN / $($MatchedUser.DisplayName)"

        }

        else {

            Write-Host "`tWARNING!" -ForegroundColor Red
            write-host "`tWe couldn't find an Entra user's Display Name that matches the certificate's CN field:" -ForegroundColor Yellow
            write-host "`tCERT-CN : `"$displaynamecandidate`"" -ForegroundColor cyan
                
            while (-not $matchedUser) {
    
                ## ^we only go through this loop if displayname -ne cert-CN

                write-host "`nPlease enter a UPN manually (example: user@domain.com):" -ForegroundColor Magenta
                $ManualUPN = Read-Host
                if ($manualUPN) {
                    
                    try {
                    
                        $MatchedUser = Get-AzADUser -Filter "UserPrincipalName eq '$ManualUPN'" -ErrorAction Stop
                    
                    }
                    
                    catch {

                        write-log -action "failed to run `'ge-azaduser`' while attempting to get a user based on an admin's manual input. this shouldn't fail if a user is not found/matched." -Status "ERROR" -ErrorMessage $_.Exception.Message    

                    }
                }
                
                if ($matcheduser) {
    
                    Write-Host "`n`tSUCCESS! Entra ID UPN found." -foregroundcolor green
                    Write-Log -Action "Admin entered manual UPN and was found in Entra: $ManualUPN"
    
                }
    
                else {
    
                    write-host "`tNo user found with that UPN in Entra ID." -ForegroundColor yellow
    
                }
            }
        }
    #endregion

    # ============================
    # Step 5 — Prompt User to Confirm Matches
    # ============================
    #region User confirmation of matched-cert

        Write-Host "
        ################################################
        #### Step 5 — Confirming cert-to-user map  #####
        ################################################" -ForegroundColor white

        Write-Host "
        Compare the mappings in green. 'Certificate' fields are from
        the certificate's subject. 'Entra' fields come from a valid Entra
        user who this script will associate the certificate to.
        " -ForegroundColor white
        Write-Log -Action "Beginning user confirmation step"

        ## we aren't doing any error handling in this section since we're only confirming
        ## information that has already been gathered and will be used later.

        $ConfirmedUser = $null

        if ($MatchedUser) {
            
            # adding color for ease of user comparison
            if ($MatchSource -match "Email"){

                $Emailmatchcolor="green"
                $CNmatchcolor="cyan"

            }

            elseif ($MatchSource -match "CN" -or "UPN"){

                $CNmatchcolor="green"
                $Emailmatchcolor="cyan"

            }

            Write-Host "`tEmail (Certificate)       : $E" -ForegroundColor $Emailmatchcolor 
            Write-Host "`tEmail (Entra)             : $($MatchedUser.mail)" -ForegroundColor $Emailmatchcolor 
            Write-Host "`tCN (Certificate)          : $CN" -ForegroundColor $CNmatchcolor 
            Write-Host "`tDisplayName (Entra)       : $($MatchedUser.DisplayName)" -ForegroundColor $CNmatchcolor 
            Write-Host "`tUPN (Entra)               : $($MatchedUser.UserPrincipalName)" -ForegroundColor $CNmatchcolor 

            Write-Host  "`nIs this the desired user/certificate? (Y to confirm, N to stop the script and re-try)" -ForegroundColor Magenta
            $Response = Read-Host

            if ($Response -match '^[Yy]$') {

                $ConfirmedUser = $MatchedUser
                Write-Log -Action "Admin confirmed Azure AD match: $($MatchedUser.UserPrincipalName)"

            }
            else {

                Write-Log -Action "Admin declined match; aborting"
                break

            }
        }
    #endregion

    # ============================
    # Step 6 — Upload PFX to Azure Key Vault
    # ============================
    #region Upload to AZ Key Vault
        Write-Host "
        ################################################
        ####  Step 6 — Uploading cert to Azure KV  #####
        ################################################`n" -ForegroundColor white

        Write-Log -Action "Beginning Azure Key Vault upload step"
    
        # ----- Import PFX into Key Vault -----
        # get and show vaults
        $importSuccess=$null

        while (-not $importSuccess) {

            #region Azure subscription picker

                ## this section asks the user for the subscription they want. Subscriptions
                ## can be statically set here and user input set to chose them instead.
                try {

                    $subscriptions = Get-AzSubscription -ErrorAction Stop
                
                }
                
                catch {
                
                    Write-Log -Action "Something broke when trying to get subscriptions via get-azsubscription" -Status "ERROR" -ErrorMessage $_.Exception.Message
                    exit
                }

                Write-Host "`tAvailable Azure Subscriptions:" -ForegroundColor yellow
                for ($i = 0; $i -lt $subscriptions.Count; $i++) {

                    $num = $i + 1
                    Write-Host "`t$num) $($subscriptions[$i].Name)" -ForegroundColor Cyan

                }

                Clear-Variable selection -ErrorAction ignore
                # Validate input
                while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $subscriptions.Count) {

                    write-host "`nEnter the number of the subscription you want to use" -ForegroundColor Magenta
                    $selection = Read-Host

                }

                $chosenSub = $subscriptions[$selection - 1]
                try {
                
                    Set-AzContext -SubscriptionId $chosenSub.Id -ErrorAction stop
                
                }
                
                catch {
                
                    Write-Log -Action "Something broke when trying to set-azcontext" -Status "ERROR" -ErrorMessage $_.Exception.Message
                    exit

                }
                
                Write-Log -Action "admin selected $($chosenSub.ID) / $($chosensub.name) and switched context.  "
                Write-Host "`tSwitched context to subscription: $($chosenSub.Name)" -ForegroundColor yellow

                Clear-Variable selection -ErrorAction SilentlyContinue
            #endregion

            #region resource group picker
                Write-Host "`tAvailable Resource Groups in this subscription:" -ForegroundColor yellow
                
                try {
                    
                    $RGs=Get-AzResourceGroup -ErrorAction Stop

                }
                
                catch {
                
                    Write-Log -Action "Something broke when trying to get-azresourcegroup (all groups)" -Status "ERROR" -ErrorMessage $_.Exception.Message
                    exit
                
                }

                for ($i = 0; $i -lt $RGs.Count; $i++) {

                    $num = $i + 1
                    Write-Host "`t$num) $($RGs[$i].ResourceGroupName)" -ForegroundColor Cyan

                }

                Clear-Variable selection -ErrorAction ignore   
                # Validate input
                while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $RGs.Count) {

                    write-host "`nEnter the number of the Resource Group you want to use" -ForegroundColor Magenta
                    $selection = Read-Host
                    $chosenRG = $rgs[$selection -1]
                    Write-Log -Action "admin selected resource group $($chosenRG.ResourceGroupName)"

                }
            #endregion
            
            ## ^ from here forward, all interactions occur within vaults in this RG. This assumes that 
            ## the admin boundary for merchant/non-merchant vaults is in RGs, and respective vaults
            ## inside of them.
            
            #region vault picker
                Write-Host "`tAvailable Vaults in this resource group:" -ForegroundColor yellow
                
                try {
                
                    $vaultlist=Get-AzKeyVault -ResourceGroupName $chosenRG.ResourceGroupName -ErrorAction stop
                
                }
                
                catch {
                
                    Write-Log -Action "Something broke when trying to get vaults via get-azkeyvault" -Status "ERROR" -ErrorMessage $_.Exception.Message
                    exit

                }
                
                for ($i = 0; $i -lt $vaultlist.Count; $i++) {

                    $num = $i + 1
                    Write-Host "`t$num) $($vaultlist[$i].VaultName)" -ForegroundColor Cyan

                }
                
                Clear-Variable selection -ErrorAction ignore   
                #validate input
                while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt $vaultlist.Count) {

                    write-host "`nEnter the number of the Vault you want to use" -ForegroundColor Magenta
                    $selection = Read-Host
                    $kvName = $vaultlist[$selection -1]
                    Write-Log -Action "admin selected vault $($kvName.vaultname)"

                }

            #endregion

            write-host "`tSanitizing the certificate subject prior to import." -foregroundcolor yellow
            # 1. Replace all non-alphanumeric/non-hyphen characters with a hyphen
            # 2. Remove all spaces
            $proposedCleanCertSubject = (($subjectparts | Where-Object Key -eq 'CN').Value -replace '[^a-zA-Z0-9-]', '-') -replace '\s', ''

            write-host "`tThe suggested friendly name for this certificate in Azure Key Vault is:" -foregroundcolor yellow
            write-host "`t$proposedCleanCertSubject" -ForegroundColor cyan
            write-host "`nPress ENTER to use this, or enter a name manually (no spaces, no special characters except '-'):" -ForegroundColor Magenta
            $CertSubject=read-host

            if ([string]::IsNullOrWhiteSpace($CertSubject)) {

                Write-Log -Action "User selected cleaned certificate subject automatically: $proposedCleanCertSubject"
                $certSubject=$proposedCleanCertSubject

            }

            else {

                $CertSubject = $CertSubject -replace ('[^a-zA-Z0-9-]', '-') -replace '\s', ''
                Write-Host "`tThe sanitized version of the certificate is:" -ForegroundColor Yellow
                write-host "`t$certsubject" -ForegroundColor cyan
                Write-Log -Action "User entered custom cleaned certificate subject: $certSubject"

            }

            Write-Host "`nContinue with Azure Key Vault PFX upload? (y/n)" -ForegroundColor Magenta
            Clear-Variable response -ErrorAction Ignore
            $Response = Read-Host

            if ($Response -match '^[Yy]$') {

                Write-Log -Action "Continuing with PFX upload to Azure Key Vault using $($ConfirmedUser.UserPrincipalName)"

            }
            
            else {

                Write-Log -Action "Admin aborted before the upload process has started."
                exit

            }   
            
            Write-Host "`tImporting certificate into Key Vault '$($kvName.vaultname)' as '$certSubject'..." -ForegroundColor Yellow
            try {

                $CertImportResult = Import-AzKeyVaultCertificate `
                    -VaultName $kvName.vaultname `
                    -Name "$certSubject" `
                    -FilePath $pfxPath `
                    -Password $PfxPasswordSecure -ErrorAction stop
                Write-Host "`tImported certificate:" -ForegroundColor Yellow
                $CertImportResult | Select-Object VaultName, Name, Id, Thumbprint, Enabled, Created, Updated | Format-List    
                Write-Host "`n`tSUCCESSS! The certificate (with private key) is now in Azure Key Vault." -ForegroundColor Green
                Write-Log -Action "PFX file $pfxpath successfully uploaded to AKV."
                $importSuccess = "yes"
                
            }

            catch {
                
                Write-Host "`n$($_.Exception.Message)" -ForegroundColor Red
                Write-Log -Action "Certificate was not uploaded to AKV." -Status "ERROR" -ErrorMessage $_.Exception.Message
                throw "`tAn error occured. Please check your vault name and the name of the certificate."
                exit 1

            }
        }
    #endregion

    # ============================
    # Step 7 — Apply tags & RBAC
    # ============================
    #region apply tags
        Write-Host "
        #################################################
        ### Step 7 — Applying tags and access to AKV ####
        #################################################" -ForegroundColor white

        Write-Log -Action "Beginning tagging action to new key in Azure Key Vault"

        ##at this point, $CertImportresult is the uploaded keypair
        ## $kvname is our vault


        #region app tag picker
            $selection=$null
            write-host "`tApp tags" -ForegroundColor Yellow
            write-host "`t1) CAISO" -ForegroundColor Cyan
            write-host "`t2) OATI" -ForegroundColor Cyan
            write-host "`t3) manual entry" -ForegroundColor Cyan

            while (-not ($selection -as [int]) -or $selection -lt 1 -or $selection -gt 3) {

                write-host "`nEnter the number of the app tag you want to apply" -ForegroundColor Magenta
                $selection = Read-Host
                $kvName = $vaultlist[$selection -1]
                Write-Log -Action "admin selected vault $($kvName.vaultname)"

            }

            switch ($selection) {

                "1" { $tagAppValue = "CAISO" }
                "2" { $tagAppValue = "OATI" }
                "3" { $tagAppValue = Read-Host "Enter app name" }

            }
        #endregion

        $tagUserValue=$ConfirmedUser.UserPrincipalName
        $updatedtags=@{$tagAppKey="$tagAppValue" ; $tagUserKey=$tagUserValue}

        try {

            Set-AzKeyVaultCertificateAttribute -VaultName $kvname.VaultName -Name $CertImportResult.Name -Tag $updatedtags -ErrorAction stop
            write-host "`tSUCCESS! user tag '$taguservalue' and app tag '$tagappvalue' applied." -ForegroundColor green
            Write-Log -Action "user tag '$taguservalue' and app tag '$tagappvalue' applied."

        }
        catch {

            Write-Log -Action "user tag '$taguservalue' and app tag '$tagappvalue' weren't applied." -Status "ERROR" -ErrorMessage $_.Exception.Message
            throw "`tsomething didn't work while applying tags."

        }
        
        $scope = "$($kvname.resourceid)/certificates/$($CertImportResult.name)"
        $secretscope="$($kvname.resourceid)/secrets/$($certimportResult.Name)"
        
        try {

            [bool]$currentAzRoleAssignment=(Get-AzRoleAssignment -scope $scope -signinname $($MatchedUser.UserPrincipalName) -RoleDefinitionName $userAKVrole -ErrorAction stop)
        
        }

        catch {

            Write-Log -Action "Trying to get-azroleassignment is failing for $($scope) and  $($MatchedUser.UserPrincipalName)" -Status "ERROR" -ErrorMessage $_.Exception.Message

        }


        if (-not $currentAzRoleAssignment) {

            try{

                New-AzRoleAssignment -SignInName $MatchedUser.UserPrincipalName -Scope $scope -RoleDefinitionName $userAKVrole -ErrorAction stop

            }

            catch {

                write-log -Action "failed to assign role to $($scope) " -Status "ERROR" -ErrorMessage $_.Exception.Message 
                throw "`tfailed to assign role to $($scope)"

            }
        }

        elseif ($currentAzRoleAssignment) {

                write-host "`tSUCCESS! the role for $($certimportresult.name) --CERTIFICATE-- is already there!" -ForegroundColor Green
                Write-Log -action "the role for $($scope) is alredy present."
        
        }


        try {

            [bool]$currentAzSecretRoleAssignment=(Get-AzRoleAssignment -scope $secretscope -signinname $($MatchedUser.UserPrincipalName) -RoleDefinitionName $userAKVrole -ErrorAction stop)
        
        }

        catch {

            Write-Log -Action "Trying to get-azroleassignment is failing for (secret) $($scope) and  $($MatchedUser.UserPrincipalName)" -Status "ERROR" -ErrorMessage $_.Exception.Message

        }

        if (-not $currentAzSecretRoleAssignment) {

            try {

                New-AzRoleAssignment -SignInName $MatchedUser.UserPrincipalName -Scope $secretscope -RoleDefinitionName $userAKVrole -ErrorAction Stop
            
            }
            
            catch {
            
                write-log -Action "failed to add role assignment"  -Status "ERROR" -ErrorMessage $_.Exception.Message
                #throw "failed to assign role to $secretscope"
            
            }
        }
        elseif ($currentAzSecretRoleAssignment) {

                write-host "`tSUCCESS! the role for $($certimportresult.name) --SECRET-- is already there!" -ForegroundColor green
                Write-Log -action "the role for $secretscope is alredy present."
    
        }
    #endregion

    # Repeat?
    Clear-Variable selection -ErrorAction ignore
    write-host "==================================" -ForegroundColor Yellow
    write-host "do you want to try another import? (y/n)" -ForegroundColor Magenta
    $response = Read-Host
    if ($Response -match '^[Yy]$') {

        Write-Log -Action "admin requested to repeat the script"
        write-host "let's do it again!`n`n" -ForegroundColor Yellow
        $scriptRepeat=$true

    }
    else {

        Write-Log -Action "Admin exited"
        $scriptRepeat=$false

    }   

}

write-host "done!" -ForegroundColor white
