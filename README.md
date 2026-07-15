# Azure Keyvault uploader and downloader

## DESCRIPTION
These scripts are designed to allow an admin to upload PFX files that were manually obtained through other means and to upload them to Azure Key Vault. Once in AKV, the KV_downloader script that is intended to be installed on users' workstations and will download public/private keys that are scoped to them in AKV and then install them onto the personal certificate store of their respective Windows user profiles. The end result is that the manually obtained PFX files will be automatically installed on users' workstations after manual upload through the admin script.

## AZURE PERMISSIONS AND ROLES
Admins :
* "OWNER" role implicitly or explicitly for the vaults they will be uploading to and managing certificates in. Ultimately, the role/s in use need to allow the admin running the script to upload     certificates.
Users :
* "KEY VAULT READER" for any vaults that their respective certificates may live in. Note that this role allows them to see a vault, including other users' public keys which are not required to be confidential. This role is typically logically applied via adding certificate users ("CAISO USERS" security group for instance) to an Active Directory security group that is synchronized to Entra, then assigning that AZ group the role for the respective keyvault ("MERCHANT" or "NON-MERCHANT" typically).
* [automatically assigned roles via script] : The admin uploader script will assign the "KEY VAULT CERTIFICATE USER" role to both the public and private key that is scoped to the targeted user to enable that respective user to ultimately obtain the keypair. This ensures that this targeted user (and admins) are the only ones who can access their respective keypair/s.
* RBAC/Azure Roles are maintained as separate logical objects and are not tied to AKV (role assignments live outside of AKV regardless of scope/application). They may be implicitly or explicitly applied; because of this, if uploading a certificate multiple times to the same AKV object or if a certificate is renewed and uploaded in the same fashion, the RBAC object that applies/applied to that object will still exist. If a user leaves and their account is disabled/deleted, this will not matter. If a user changes a business role, the AKV certificate object formerly assigned to them should be manually deleted, and the Azure Role for those objects deleted manually (although if the AKV cert object is deleted, they are just orphaned roles and don't represent additional risk).

## AZURE NOTES
TAGNAMES/VALUES :
* User : -username-
* App : -appname- (this is not used for RBAC currently and is only for human visibilty/reporting/future-uses)

SHARED CERTIFICATES :

Scripts that are meant to be shared among multiple users need to be re-run through this script for each user (3x users who use certificate-A need 3x runs for the script that target each user separately). This will result in multiple certificates that have the same thumbprint in any given vault, with each copy having individual user role permissions.

RENEWED CERTIFICATES OR REUPLOADED CERTIFICATES THAT ALREADY EXIST

When a certificate is uploaded to Azure Key Vault, the resulting AKV object will contain a single certificate. When a certificate is reuploaded or renewed and uploaded to the same object in AKV, a history is maintained for that AKV object. By default, all user-side actions on a certificate that they have permissions for will target the most recent certificate populated in that AKV object. 

## ADMIN SCRIPT UPLOAD
### prerequisites:
1) Powershell 7.0
2) The user who runs the script does not need to run scripts from an elevated terminal 
    
### workflow:
* Static variable definitions are in top of script. $LogFile should be updated by admin prior to running script for the first time.
1) Automatic checking for Az.Accounts , Az.KeyVault , and Az.Resources PS modules: they are installed if not already.
2) Admin is prompted to authenticate to Azure.
3) Admin is shown all PFX files in their 'Downloads' folder , sorted in order of last modified. Note that this folder can be changed in static variable section if needed.
4) Admin chooses PFX file or supplies a path manually.
5) PFX file is opened and admin is prompted for the password, and loaded to memory. If unsuccessful, repeated attempts are allowed to open its contents.
6) Certificate is parsed for narrow subject information (CN, Email, OU, O) and presented to admin.
7) Automatic searching of EntraID to find a user that matches the certificate's "Email" attribute. This is typically the most reliable match.
8) If a user isn't found that matches the certificate's "Email" attribute, the script continues with the "CN" attribute instead.
9) Customer supplied sample certificates include "CN" attributes that will never match a user (a shared certificate for instance), and some that have similar CN matches to Entra "Display Name" attributes. These have been observed to be in a format like "Ben Knorrx12345" ; the script trims the "x[5 digits]" and attempts to match the CN of the certificate to the Display Name of EntraID users.
10) If the script can't find a match for Cert:CN to EntraID:DisplayName , it stops and asks the admin for a manual input for the targeted user. This needs to be in UPN format (bknorr@compunet.biz) of an actual EntraID user.
11) Admin is presented with the certificate's subject information and the automatically or manually matched EntraID user , and is asked to confirm this mapping. This is essential since some certificates will not have much or any information in their subjects that suggests who will be using it.
12) Admin is shown all Azure subscriptions and prompted which Azure subscription will be used.
13) Admin is shown all Resource Groups in the subscription and prompted which Resource Group will be used.
14) Admin is shown all Key Vaults in the Resource Group and prompted which Key Vault will be used.
15) The certificate's CN is shown to the admin again. The purpose of this step is to allow the admin to create a name for the certificate that will be uploaded to AKV. This is typically an identifier to represent the user and certificate purpose. For example, a unique CAISO certifiate for Ben Knorr might be named "ben knorr - CAISO". Or, a shared certificate that will be used by Ben Knorr might be "ben knorr - shared - CAISO".
16) AKV requires no special characters except a "-". The script will automatically sanitize the admin specified AKV certificate name to not produce errors when uploaded.
17) Admin is asked to confirm the upload to AKV.
18) -PFX is uploaded to AKV-
19) Admin is shown CAISO and OATI tags that may be used for organizational purposes (these are not used in the script for any type of RBAC or other non-human facing readability concerns). A manual input of an admin defined tag is possible as well here. Future revision of the prepopulated app tags should be done in the region "app tag picker".
20) Script adds a usertag for the user identified in step 11 to the uploaded certificate. This is essential to ensure proper RBAC and confidentiality of the uploaded certificate.
21) Script identifies certificate and secret scopes for the newly uploaded certificate and assigns Azure roles for the targeted user. Note that if this is not the first time the script targets an AKV certificate object, the script will check if the RBAC exists for the public/private keypair and not apply it repeatedly since the original upload maintains the role and won't be changed with each re-upload.
22) Admin is prompted to re-run the script for another PFX upload- they don't have to reauthenticate and are sent back up to step 2.

## USER SCRIPT DOWNLOAD
### prerequisites:
1) Powershell 5 or higher
2) No admin permissions are required.
3) The script needs to be run in a user context.
4) The script should be set to run as a login-script, scheduled task (trigger to run at login typically), or other means.
5) The script should not be restricted to run: setting the task to run with the ExecutionPolicy -Bypass is a typical method to avoid a greater risk of setting the system or user PS context to run with Unrestricted. Signing the script using Customer supplied certificate is also possible to ensure integrity of the contents and avoid unintentional operations.
6) The workstation where the user logs in must be Entra joined or AD hybrid joined.
7) The Azure Connect service (on a separate system) should be set to allow seamless SSO to allow the user's kerberos ticket to authenticate them to Azure resources.
8) The user who runs the script needs to be either an EntraID native account, or a hybrid synchronized account from AD to EntraID.
9) The workstation that the user is logging into needs to be Entra joined or hybrid AD synchronized.

### workflow (no user interaction is needed):
1) Script logs activity to the user's home directory.
2) Script checks for NuGet package provider and installs it if not present.
3) Script checks for Az.Account and Az.KeyVault modules and installs them if not present.
4) Script logs into Azure using the current Windows user's kerberos ticket- this should be seamless and not prompt the user to authenticate. Note that running snippets of the script manually/interactively may not perform the same.
5) Script creates a hidden folder in the user's home directory that will be used for PFX download/installation (future release may skip this step and only work in memory).
6) Certificates in the user's personal certificate store are parsed: expired certificates from \*CAISO\* or \*WEBCARES\* certificate authorities are deleted.
7) Script checks AKV and finds all vaults that the user has access to.
8) Script loops through all vaults, finding any certificates that have the user tag that match the user logged into the Windows client.
9) Each certificate's thumbprint that is found in AKV matching the usertag is compared to the user's Windows personal certificate store: if a certificate match is found, no further action happens to this certificate on this run.
10) A "new" certificate that isn't in the user's personal store on their client is downloaded and assembled into a PFX that is temporarily stored in the hidden/randomly-named directory in their home folder.
11) The temp directory and PFX in it is deleted, regardless of any earlier errors that occured in the script.

### FUTURE FUNCTIONALITY
*Cleanup of certificates for changers or cert revocations*

In the "local cert cleanup for AKV leavers" region at the bottom of the script (commented out in v1.2.2) there is functionality that will delete user certificates that don't also exist in AKV. This has use cases which include removing a certificate locally that is manually deleted from AKV by an admin, and for a user who changes business roles and their previous certificates must be removed to restrict access from their older roles. Note that this only applies to certificates issued by \*CAISO\* or \*WEBCARES\* certificate authorities. This should be used with caution until all user or admin certificates are brought into AKV, since this will forcibly remove locally installed user certificates that aren't in AKV.

Given a user that changes a business role, from merchant to non-merchant for instance, they may still possess their previous business role's user certificate on their workstation. This script-region will check certificates in the user's local certificate store and compare them against certificate objects in AKV that they have access to and have their usertag. If a local certificate's thumbrpint can't be found in the user's scope of vaults and usertags in AKV, the local certificate is removed from the user's personal certificate store.
