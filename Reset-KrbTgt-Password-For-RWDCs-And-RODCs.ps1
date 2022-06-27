### Abstract: This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner
###
### Written by: Jorge de Almeida Pinto [MVP-EMS]
### BLOG: http://jorgequestforknowledge.wordpress.com/
### E-Mail Address For Feedback/Questions: scripts.gallery@iamtec.eu
###
### Paste The Following Quick Link Between The Double Quotes In Browser To Send Mail:
### --> "mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'"
###
### For Questions/Feedback:
### --> Please Describe Your Scenario As Best As Possible With As Much Detail As Possible.
### --> If Applicable Describe What Does and Does Not Work.
### --> If Applicable Describe What Should Be/Work Different And Explain Why/How.
### --> Please Add Screendumps.
###

<#
.SYNOPSIS
	This PoSH Script Resets The KrbTgt Password For RWDCs And RODCs In A Controlled Manner

.VERSION
	v2.8, 2020-04-02 (UPDATE THE VERSION VARIABLE BELOW)
	
.AUTHOR
	Initial Script/Thoughts.......: Jared Poeppelman, Microsoft
	Script Re-Written/Enhanced....: Jorge de Almeida Pinto [MVP Enterprise Mobility And Security, EMS]
	Blog..........................: Blog: http://jorgequestforknowledge.wordpress.com/
	For Feedback/Questions........: scripts.gallery@iamtec.eu ("mailto:Jorge's Script Gallery <scripts.gallery@iamtec.eu>?subject=[Script Gallery Feedback:] 'REPLACE-THIS-PART-WITH-SOMETHING-MEANINGFULL'")

.DESCRIPTION
    This PoSH script provides the following functions:
	- Single Password Reset for the KrbTgt account in use by RWDCs in a specific AD domain, using either TEST or PROD KrbTgt accounts
	- Single Password Reset for the KrbTgt account in use by an individual RODC in a specific AD domain, using either TEST or PROD KrbTgt accounts
		* A single RODC in a specific AD domain
		* A specific list of RODCs in a specific AD domain
		* All RODCs in a specific AD domain
	- Resetting the password/keys of the KrbTgt Account can be done for multiple reasons such as for example:
		* From a security perspective as mentioned in https://cloudblogs.microsoft.com/microsoftsecure/2015/02/11/krbtgt-account-password-reset-scripts-now-available-for-customers/
		* From an AD recovery perspective as mentioned in https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/manage/ad-forest-recovery-resetting-the-krbtgt-password
	- For all scenarios, an informational mode, which is mode 1 with no changes
	- For all scenarios, a simulation mode, which is mode 2 where replication is tested through the replication of a temporary canary
		object that is created and deleted afterwards. No Password Resets involved here as the temporary canary object is a contact object
	- For all scenarios, a simulation mode, which is mode 3 where NO password reset of the chosen TEST KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 4 where the password reset of the chosen TEST KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a simulation mode, which is mode 5 where NO password reset of the chosen PROD KrbTgt account occurs. Basically this
		just checks the status of the objects on scoped DCs. NOTHING is changed. Can be scoped for RWDCs and RODCs (single, multiple, all)
	- For all scenarios, a real reset mode, which is mode 6 where the password reset of the chosen PROD KrbTgt account is actually executed
		and replication of it is monitored through the environment for its duration
	- The creation of Test KrbTgt Accounts, which is mode 8
	- The deletion of Test KrbTgt Accounts, which is mode 9
	
	Behavior:
	- In this script a DC is reachable/available, if its name is resolvable and connectivity is possible for all of the following ports:
		TCP:135 (Endpoint Mapper), TCP:389 (LDAP) and TCP:9839 (AD Web Services)
	- In mode 1 you will always get a list of all RWDCs, and alls RODCs if applicable, in the targeted AD domain that are available/reachable
		or not
	- In mode 2 it will create the temporary canary object and, depending on the scope, it will check if it exists in the AD database of the
		remote DC(s) (RWDC/RODC)
	- In mode 3, depending on the scope, it uses TEST/BOGUS krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 4, depending on the scope, it uses TEST/BOGUS krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted TEST/BOGUS krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the
		pwdLastSet attribute value of the same TEST/BOGUS krbtgt account on the originating RWDC
		* For RWDCs it uses the TEST/BOGUS krbtgt account "krbtgt_TEST" (All RWDCs) (= Created when running mode 8)
		* For RODCs it uses the TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" (RODC Specific) (= Created when running mode 8)
	- In mode 5, depending on the scope, it uses PROD/REAL krbtgt account(s). It just checks and compares the state of the pwdLastSet attribute
		on the source RWDC with other scoped DCs. Nothing is changed/updated!
	- In mode 6, depending on the scope, it uses PROD/REAL krbtgt account(s) to reset the password on an originating RWDC. After that it
		checks if pwdLastSet attribute value of the targeted PROD/REAL krbtgt account(s) on the remote DC(s) (RWDC/RODC) matches the pwdLastSet
		attribute value of the same PROD/REAL krbtgt account on the originating RWDC
		* For RWDCs it uses the PROD/REAL krbtgt account "krbtgt" (All RWDCs)
		* For RODCs it uses the PROD/REAL krbtgt account "krbtgt_<Numeric Value>" (RODC Specific)
	- In mode 8, for RWDCs it creates (in disabled state!) the TEST/BOGUS krbtgt account "krbtgt_TEST" and adds it to the AD group
		"Denied RODC Password Replication Group". If any RODC exists in the targeted AD domain, it reads the attribute "msDS-KrbTgtLink" of
		each RODC computer account to determine the RODC specific krbtgt account and creates (in disabled state!) the TEST/BOGUS krbtgt
		account "krbtgt_<Numeric Value>_TEST" and adds it to the AD group "Allowed RODC Password Replication Group"
	- In mode 9, for RWDCs it deletes the TEST/BOGUS krbtgt account "krbtgt_TEST" if it exists. If any RODC exists in the targeted AD domain,
		it reads the attribute "msDS-KrbTgtLink" of each RODC computer account to determine the RODC specific krbtgt account and deletes the
		TEST/BOGUS krbtgt account "krbtgt_<Numeric Value>_TEST" if it exists.
	- In mode 2, 3, 4, 5 or 6, if a remote DC (RWDC/RODC) is not available or cannot be reached, there will not be a check against its AD database
		to determine if the change made reached it or not.
	- In mode 2 when performing the "replicate single object" operation, it will always be for the full object, no matter if the remote DC
		is an RWDC or an RODC
	- In mode 3, 4, 5 or 6 when performing the "replicate single object" operation, it will always be for the full object, if the remote DC is an
		RWDC. If the remote DC is an RODC it will always be for the partial object and more specifically "secrets only"
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by all the RWDCs, the originating RWDC is the RWDC with the PDC FSMO
		and all other available/reachable RWDCs will be checked against to see if the change has reached them. No RODCs are involved as those
		do not use the krbtg account in use by the RWDCs and also do not store/cache its password.
	- When targeting the krbtgt account (TEST/BOGUS or PROD/REAL) in use by an RODC, the originating RWDC is the direct replication RWDC if
		available/reachable and when not available the RWDC with the PDC FSMO is used as the originating RWDC. Only the RODC that uses the
		specific krbtgt account is checked against to see if the change has reached them, but only if the RODCs is available/reachable. If the
		RODC itself is not available, then the RWDC with the PDC FSMO is used as the originating RWDC and the change will eventually replicate
		to the RODC
	- If the operating system attribute of an RODC computer account does not have a value, it is determined to be unknown (not a real RODC),
		and therefore something else. It could for example be a Riverbed appliance in "RODC mode".
	- The only DC that knows what the real replication partner is of an RODC, is the RODC itself. Only the RODC manages a connection object
		that only exists in the AD database of the RODC and does not replicate out to other DCs as RODCs do not support outbound replication.
		Therefore, assuming the RODC is available, the CO is looked up in the RODC AD database and from that CO, the "source" server is
		determined. In case the RODC is not available or its "source" server is not available, the RWDC with the PDC FSMO is used to reset
		the password of the krbtgt account in use by that RODC. If the RODC is available a check will be done against its database, and if
		not available the check is skipped

.TODO
	- N.A.

.KNOWN ISSUES/BUGS
	- When targeting a remote AD forest for which no trust exist with the AD forest the running account belongs to, the public profile of WinRM may be
		used. In that case the PSSession for 'Get-GPOReport' may fail due to the default firewall exception only allowing access from remote computers
		on the same local subnet. In that case the default 'MaxTicketAge' (default 10 hours) and 'MaxClockSkew' (default 5 minutes) is used instead.
		You may see the following error:
		[<FQDN TARGET DC>] Connecting to remote server <FQDN TARGET DC> failed with the following error message : WinRM cannot complete the operation.
		Verify that the specified computer name is valid, that the computer is accessible over the network, and that a firewall exception for the WinRM
		service is enabled and allows access from this computer. By default, the WinRM firewall exception for public profiles limits access to remote
		computers within the same local subnet. For more information, see the about_Remote_Troubleshooting Help topic.
		+ CategoryInfo          : OpenError: (<FQDN TARGET DC>:String) [], PSRemotingTransportException
        + FullyQualifiedErrorId : WinRMOperationTimeout,PSSessionStateBroken
	- Although this script can be used in an environment with Windows Server 2000/2003 RWDCs, it is NOT supported to do this. Windows Server
		2000/2003 RWDCs cannot do KDC PAC validation using the previous (N-1) krbtgt password. Those RWDCs only attempt that with the current
		(N) password. That means that in the subset of KRB AP exchanges where KDC PAC validation is performed, authentication issues could be
		experienced because the target server gets a PAC validation error when asking the KDC (domain controller) to validate the KDC signature
		of the PAC that is inside the service ticket that was presented by the client to the server. This problem would potentially persist
		for the lifetime of the service ticket(s). It is also highly recommended NOT to use products that have reached their end support.
		Please upgrade as soon as possible.
	- This is not related to this script. When increasing the DFL from Windows Server 2003 to any higher level, the password of the KrbTgt
		Account will be reset automatically due to the introduction of AES encryption for Kerberos and the requirement to regenerate new keys
		for DES, RC4, AES128, AES256!

.RELEASE NOTES
	v2.8, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
		- Fixed an issue when the RODC itself is not reachable/available, whereas in that case, the source should be the RWDC with the PDC FSMO
		- Checks to make sure both the RWDC with the PDC FSMO role and the nearest RWDC are available. If either one is not available, the script will abort

	v2.7, 2020-04-02, Jorge de Almeida Pinto [MVP-EMS]:
		- Added DNS name resolution check to the portConnectionCheck function
		- To test membership of the administrators group in a remote AD forest the "title" attribute is now used instead of the "displayName" attribute to try to write to it
		- Removed usage of $remoteADforest variable and only use the $localADforest variable
		- Removed usage of $remoteCredsUsed variable and only use the $adminCrds variable (Was $adminCreds)
		- Added a warning if the special purpose krbtgt account 'Krbtgt_AzureAD' is discovered in the AD domain
		- If the number of RODCs in the AD domain is 0, then it will not present the options for RODCs
		- If the number of RODCs in the AD domain is 1 of more, amd you chose to manually specify the FQDN of RODCs to process, it will present a list of RODCs to choose from
		- Operational modes have been changed (WARNING: pay attention to what you choose!). The following modes are the new modes
			- 1 - Informational Mode (No Changes At All)
			- 2 - Simulation Mode | Temporary Canary Object Created To Test Replication Convergence!
			- 3 - Simulation Mode | Use KrbTgt TEST/BOGUS Accounts - No Password Reset/WhatIf Mode!
			- 4 - Real Reset Mode | Use KrbTgt TEST/BOGUS Accounts - Password Will Be Reset Once!
			- 5 - Simulation Mode | Use KrbTgt PROD/REAL Accounts - No Password Reset/WhatIf Mode!
			- 6 - Real Reset Mode | Use KrbTgt PROD/REAL Accounts - Password Will Be Reset Once!
		- When choosing RODC Krb Tgt Account scope the following will now occur:
			- If the RODC is not reachable, the real source RWDC of the RODC cannot be determined. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
			- If the RODC is reachable, but the real source RWDC of the RODC is not reachable it cannot be used as the source for the change and replication. In that case, the RWDC with the PDC FSMO role is used as the source for the change and replication
		- Sections with '#XXX' have been removed
		- Calls using the CMDlet 'Get-ADReplicationAttributeMetadata' (W2K12 and higher) have been replaced with .NET calls to support older OS'es such as W2K8 and W2K8R2. A function has been created to retrieve metadata
		- Some parts were rewritten/optimized

	v2.6, 2020-02-25, Jorge de Almeida Pinto [MVP-EMS]:
		- Removed code that was commented out
		- Logging where the script is being executed from
		- Updated the function 'createTestKrbTgtADAccount' to also include the FQDN of the RODC for which the Test KrbTgt account is created for better recognition
		- In addition to the port 135 (RPC Endpoint Mapper) and 389 (LDAP), the script will also check for port 9389 (AD Web Service) which is used by the ADDS PoSH CMDlets
		- Updated script to included more 'try/catch' and more (error) logging, incl. line where it fails, when things go wrong to make troubleshooting easier
	
	v2.5, 2020-02-17, Jorge de Almeida Pinto [MVP-EMS]:
		- To improve performance, for some actions the nearest RWDC is discovered instead of using the RWDC with the PDC FSMO Role
		
	v2.4, 2020-02-10, Jorge de Almeida Pinto [MVP-EMS]:
		- Checked script with Visual Studio Code and fixed all "problems" identified by Visual Studio Code
			- Variable "$remoteCredsUsed" is ignored by me, as the problem is due to the part 'Creds' in the variable name 
			- Variable "$adminCreds" is ignored by me, as the problem is due to the part 'Creds' in the variable name
		- Bug Fix: Fixed language specific issue with the groups 'Allowed RODC Password Replication Group' and 'Denied RODC Password Replication Group'
		- Added support to execute this script against a remote AD forest, either with or without a trust

	v2.3, 2019-02-25, Jorge de Almeida Pinto [MVP-EMS]:
		- Bug Fix: Removed the language specific error checking. Has been replaced with another check. This solution also resolved another
			issue when checking if a (RW/RO)DC was available or not

	v2.2, 2019-02-12, Jorge de Almeida Pinto [MVP-EMS]:
		- Bug Fix: Instead of searching for "Domain Admins" or "Enterprise Admins" membership, it resolves the default RIDs of those groups,
			combined with the corresponding domain SID, to the actual name of those domain groups. This helps in supporting non-english names
			of those domain groups
		
	v2.1, 2019-02-11, Jorge de Almeida Pinto [MVP-EMS]:
		- New Feature: Read and display metadata of the KrbTgt accounts before and after to assure it was only updated once!
		- Bug Fix: Added a try catch when enumerating details about a specific AD domain that appears not to be available
			
	v2.0, 2018-12-30, Jorge de Almeida Pinto [MVP-EMS]:
		- Renamed script to Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1
		- Full rewrite and major release
		- Added possibility to also reset KrbTgt account in use by RODCs
		- Added possibility to try this procedure using a temp canary object (contact object)
		- Added possibility to try this procedure using a TEST krbtgt accounts and perform password reset on those TEST krbtgt accounts
		- Added possibility to create TEST krbtgt accounts if required
		- Added possibility to delete TEST krbtgt accounts if required
		- Check if an RODC account is indeed in use by a Windows RODC and not something simulating an RODC (e.g. Riverbed)
		- Removed dependency for REPADMIN.EXE
		- Removed dependency for RPCPING.EXE
		- Extensive logging to both screen and file
		- Added more checks, such as permissions check, etc.

    v1.7, Jared Poeppelman, Microsoft
		- Modified rpcping.exe call to use "-u 9 -a connect" parameters to accomodate tighter RPC security settings as specified in
			DISA STIG ID: 5.124 Rule ID: SV-32395r1_rule , Vuln ID: V-14254 (thanks Adam Haynes)

    v1.6, Jared Poeppelman, Microsoft
		- Removed 'finally' block of Get-GPOReport error handling (not a bug, just not needed)
                
    v1.5, Jared Poeppelman, Microsoft
		- Renamed script to New-CtmADKrbtgtKeys.ps1
		- Added logic for GroupPolicy Powershell module dependency
		- Fixed bug of attempting PDC to PDC replication
		- Replaced function for password generation
		- Renamed functions to use appropriate Powershell verbs 
		- Added error handling around Get-GpoReport for looking up MaxTicketAge and MaxClockSkew

    v1.4, Jared Poeppelman, Microsoft
 		- First version published on TechNet Script Gallery

.EXAMPLE
	Execute The Script
	
	.\Reset-KrbTgt-Password-For-RWDCs-And-RODCs.ps1

.NOTES
	- To execute this script, the account running the script MUST be a member of the "Domain Admins" or Administrators group in the
		targeted AD domain.
	- If the account used is from another AD domain in the same AD forest, then the account running the script MUST be a member of the
		"Enterprise Admins" group in the AD forest or Administrators group in the targeted AD domain. For all AD domains in the same
		AD forest, membership of the "Enterprise Admins" group is easier as by default it is a member of the Administrators group in
		every AD domain in the AD forest
	- If the account used is from another AD domain in another AD forest, then the account running the script MUST be a member of the
		"Administrators" group in the targeted AD domain. This also applies to any other target AD domain in that same AD forest
	- This is due to the reset of the password for the targeted KrbTgt account(s) and forcing (single object) replication between DCs
	- Testing "Domain Admins" membership is done through "IsInRole" method as the group is domain specific
	- Testing "Enterprise Admins" membership is done through "IsInRole" method as the group is forest specific
	- Testing "Administrators" membership cannot be done through "IsInRole" method as the group exist in every AD domain with the same
		SID. To still test for required permissions in that case, the value of the Description attribute of the KRBTGT account is copied
		into the Title attribute and cleared afterwards. If both those actions succeed it is proven the required permissions are
		in place!
#>

### FUNCTION: Logging Data To The Log File
Function Logging($dataToLog, $lineType) {
	$datetimeLogLine = "[" + $(Get-Date -format "yyyy-MM-dd HH:mm:ss") + "] : "
	Out-File -filepath "$logFilePath" -append -inputObject "$datetimeLogLine$dataToLog"
	If ($null -eq $lineType) {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
	}
	If ($lineType -eq "SUCCESS") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "ERROR") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "WARNING") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "MAINHEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Magenta
	}
	If ($lineType -eq "HEADER") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor DarkCyan
	}
	If ($lineType -eq "REMARK") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Cyan
	}
	If ($lineType -eq "REMARK-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Green
	}
	If ($lineType -eq "REMARK-MORE-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Yellow
	}
	If ($lineType -eq "REMARK-MOST-IMPORTANT") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor Red
	}
	If ($lineType -eq "ACTION") {
		Write-Host "$datetimeLogLine$dataToLog" -ForeGroundColor White
	}
	If ($lineType -eq "ACTION-NO-NEW-LINE") {
		Write-Host "$datetimeLogLine$dataToLog" -NoNewline -ForeGroundColor White
	}
}

### FUNCTION: Test The Port Connection
Function portConnectionCheck($fqdnServer, $port, $timeOut) {
	# Test To See If The HostName Is Resolvable At All
	Try {
		[System.Net.Dns]::gethostentry($fqdnServer) | Out-Null
	} Catch {
		Return "ERROR"
	}
	
	$tcpPortSocket = $null
	$portConnect = $null
	$tcpPortWait = $null
	$tcpPortSocket = New-Object System.Net.Sockets.TcpClient
	$portConnect = $tcpPortSocket.BeginConnect($fqdnServer, $port, $null, $null)
	$tcpPortWait = $portConnect.AsyncWaitHandle.WaitOne($timeOut, $false)
	If(!$tcpPortWait) {
		$tcpPortSocket.Close()
		Return "ERROR"
	} Else {
		$ErrorActionPreference = "SilentlyContinue"
		$tcpPortSocket.EndConnect($portConnect) | Out-Null
		If (!$?) {
			Return "ERROR"
		} Else {
			Return "SUCCESS"
		}
		$tcpPortSocket.Close()
		$ErrorActionPreference = "Continue"
	}
}

### FUNCTION: Load Required PowerShell Modules
Function loadPoSHModules($PoSHModule) {
	$retValue = $null
	If(@(Get-Module | Where-Object{$_.Name -eq $PoSHModule}).count -eq 0) {
		If(@(Get-Module -ListAvailable | Where-Object{$_.Name -eq $PoSHModule} ).count -ne 0) {
			Import-Module $PoSHModule
			Logging "PoSH Module '$PoSHModule' Has Been Loaded..." "SUCCESS"
			$retValue = "HasBeenLoaded"
		} Else {
			Logging "PoSH Module '$PoSHModule' Is Not Available To Load..." "ERROR"
			Logging "Aborting Script..." "ERROR"
			$retValue = "NotAvailable"
		}
	} Else {
		Logging "PoSH Module '$PoSHModule' Already Loaded..." "SUCCESS"
		$retValue = "AlreadyLoaded"
	}
	Return $retValue
}

### FUNCTION: Test Credentials For Specific Admin Role
Function testAdminRole($adminRole) {
	# Determine Current User
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	
	# Check The Current User Is In The Specified Admin Role
	(New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole($adminRole)
}

### FUNCTION: Create Temporary Canary Object
Function createTempCanaryObject($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $execDateTimeCustom1, $localADforest, $adminCrds) {
	# Determine The DN Of The Default NC Of The Targeted Domain
	$targetedADdomainDefaultNC = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetedADdomainDefaultNC = (Get-ADRootDSE -Server $targetedADdomainRWDCFQDN -Credential $adminCrds).defaultNamingContext
		} Catch {
			Logging "" "ERROR"
			Logging "Error Connecting To '$targetedADdomainRWDCFQDN' For 'rootDSE' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Determine The DN Of The Users Container Of The Targeted Domain
	$containerForTempCanaryObject = $null
	$containerForTempCanaryObject = "CN=Users," + $targetedADdomainDefaultNC
	
	# Generate The Name Of The Temporary Canary Object
	$targetObjectToCheckName = $null
	$targetObjectToCheckName = "_adReplTempObject_" + $krbTgtSamAccountName + "_" + $execDateTimeCustom1
	
	# Specify The Description Of The Temporary Canary Object
	$targetObjectToCheckDescription = "...!!!.TEMP OBJECT TO CHECK AD REPLICATION IMPACT.!!!..."
	
	# Generate The DN Of The Temporary Canary Object
	$targetObjectToCheckDN = $null
	$targetObjectToCheckDN = "CN=" + $targetObjectToCheckName + "," + $containerForTempCanaryObject
	Logging "  --> RWDC To Create Object On..............: '$targetedADdomainRWDCFQDN'"
	Logging "  --> Full Name Temp Canary Object..........: '$targetObjectToCheckName'"
	Logging "  --> Description...........................: '$targetObjectToCheckDescription'"
	Logging "  --> Container For Temp Canary Object......: '$containerForTempCanaryObject'"
	Logging ""
	
	# Try To Create The Canary Object In The AD Domain And If Not Successfull Throw Error
	Try {
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN
		}
		If ($localADforest -eq $false -And $adminCrds) {
			New-ADObject -Type contact -Name $targetObjectToCheckName -Path $containerForTempCanaryObject -DisplayName $targetObjectToCheckName -Description $targetObjectToCheckDescription -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		}
	} Catch {
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] FAILED TO BE CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "ERROR"
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}
	
	# Check The Temporary Canary Object Exists And Was created In AD
	$targetObjectToCheck = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$targetObjectToCheck = Get-ADObject -LDAPFilter "(&(objectClass=contact)(name=$targetObjectToCheckName))" -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'name=$targetObjectToCheckName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($targetObjectToCheck) {
		$targetObjectToCheckDN = $null
		$targetObjectToCheckDN = $targetObjectToCheck.DistinguishedName
		Logging "  --> Temp Canary Object [$targetObjectToCheckDN] CREATED on RWDC [$targetedADdomainRWDCFQDN]!..." "REMARK"
		Logging "" "REMARK"
	}
	Return $targetObjectToCheckDN
}

### FUNCTION: Confirm Generated Password Meets Complexity Requirements
# Source: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
Function confirmPasswordIsComplex($pwd) {
	Process {
		$criteriaMet = 0
		
		# Upper Case Characters (A through Z, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[A-Z]') {$criteriaMet++}
		
		# Lower Case Characters (a through z, sharp-s, with diacritic marks, Greek and Cyrillic characters)
		If ($pwd -cmatch '[a-z]') {$criteriaMet++}
		
		# Numeric Characters (0 through 9)
		If ($pwd -match '\d') {$criteriaMet++}
		
		# Special Chracters (Non-alphanumeric characters, currency symbols such as the Euro or British Pound are not counted as special characters for this policy setting)
		If ($pwd -match '[\^~!@#$%^&*_+=`|\\(){}\[\]:;"''<>,.?/]') {$criteriaMet++}
		
		# Check If It Matches Default Windows Complexity Requirements
		If ($criteriaMet -lt 3) {Return $false}
		If ($pwd.Length -lt 8) {Return $false}
		Return $true
	}
}

### FUNCTION: Generate New Complex Password
Function generateNewComplexPassword([int]$passwordNrChars) {
	Process {
		$iterations = 0
        Do {
			If ($iterations -ge 20) {
				Logging "  --> Complex password generation failed after '$iterations' iterations..." "ERROR"
				Logging "" "ERROR"
				EXIT
			}
			$iterations++
			$pwdBytes = @()
			$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
			Do {
				[byte[]]$byte = [byte]1
				$rng.GetBytes($byte)
				If ($byte[0] -lt 33 -or $byte[0] -gt 126) {
					CONTINUE
				}
                $pwdBytes += $byte[0]
			}
			While ($pwdBytes.Count -lt $passwordNrChars)
				$pwd = ([char[]]$pwdBytes) -join ''
			} 
        Until (confirmPasswordIsComplex $pwd)
        Return $pwd
	}
}

### FUNCTION: Retrieve The Metadata Of An Object
Function retrieveObjectMetadata($targetedADdomainRWDCFQDN, $ObjectDN, $localADforest, $adminCrds) {
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadata = $null
	$targetedADdomainRWDCContext = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN)
	}
	If ($localADforest -eq $false -And $adminCrds) {
		$targetedADdomainRWDCContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("DirectoryServer", $targetedADdomainRWDCFQDN, $($adminCrds.UserName), $($adminCrds.GetNetworkCredential().Password))
	}
	$targetedADdomainRWDCObject = $null
	Try {
		$targetedADdomainRWDCObject = [System.DirectoryServices.ActiveDirectory.DomainController]::GetDomainController($targetedADdomainRWDCContext)
		$objectMetadata = $targetedADdomainRWDCObject.GetReplicationMetadata($ObjectDN)
	} Catch {
		Logging "" "ERROR"
		If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN'..." "ERROR"
		}
		If ($localADforest -eq $false -And $adminCrds) {
			Logging "Error Getting Metadata From '$targetedADdomainRWDCFQDN' For Object '$krbTgtObjectBeforeDN' Using '$($adminCrds.UserName)'..." "ERROR"
		}
		Logging "" "ERROR"
		Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
		Logging "" "ERROR"
		Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
		Logging "" "ERROR"
		Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
		Logging "" "ERROR"
	}

	If ($objectMetadata) {
		Return $($objectMetadata.Values)
	}
}

### FUNCTION: Reset Password Of AD Account
Function setPasswordOfADAccount($targetedADdomainRWDCFQDN, $krbTgtSamAccountName, $localADforest, $adminCrds) {
	# Retrieve The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBefore = $null
	If ($localADforest -eq $true -Or ($localADforest -eq $false -And !$adminCrds)) {
		Try {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For User Object With 'sAMAccountName=$krbTgtSamAccountName'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	If ($localADforest -eq $false -And $adminCrds) {
		Try {
			$krbTgtObjectBefore = Get-ADUser -LDAPFilter "(sAMAccountName=$krbTgtSamAccountName)" -Properties * -Server $targetedADdomainRWDCFQDN -Credential $adminCrds
		} Catch {
			Logging "" "ERROR"
			Logging "Error Querying AD Against '$targetedADdomainRWDCFQDN' For Contact Object With 'sAMAccountName=$krbTgtSamAccountName' Using '$($adminCrds.UserName)'..." "ERROR"
			Logging "" "ERROR"
			Logging "Exception Type......: $($_.Exception.GetType().FullName)" "ERROR"
			Logging "" "ERROR"
			Logging "Exception Message...: $($_.Exception.Message)" "ERROR"
			Logging "" "ERROR"
			Logging "Error On Script Line: $($_.InvocationInfo.ScriptLineNumber)" "ERROR"
			Logging "" "ERROR"
		}
	}
	
	# Get The DN Of The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforeDN = $null
	$krbTgtObjectBeforeDN = $krbTgtObjectBefore.DistinguishedName
	
	# Get The Password Last Set Value From The KrgTgt Object In The AD Domain BEFORE THE PASSWORD SET
	$krbTgtObjectBeforePwdLastSet = $null
	$krbTgtObjectBeforePwdLastSet = Get-Date $([datetime]::fromfiletime($krbTgtObjectBefore.pwdLastSet)) -f "yyyy-MM-dd HH:mm:ss"
	
	# Get The Metadata Of The Object, And More Specific Of The pwdLastSet Attribute Of That Object BEFORE THE PASSWORD SET
	$objectMetadataBefore = $null
	$objectMetadataBefore = retrieveObjectMetadata $targetedADdomainRWDCFQDN $krbTgtObjectBeforeDN $localADforest $adminCrds
	$objectMetadataBeforeAttribPwdLastSet = $null
	$objectMetadataBeforeAttribPwdLastSet = $objectMetadataBefore | Where-Object{$_.Name -eq "pwdLastSet"}
	$objectMetadataBeforeAttribPwdLastSetOrgRWDCFQDN = $null
	$objectMetadataBeforeAttribPwdLastSetOrgRW