
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Create the function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
$xHeaders = "x-ms-date:" + $date
$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
 
$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
$keyBytes = [Convert]::FromBase64String($sharedKey)
 
$sha256 = New-Object System.Security.Cryptography.HMACSHA256
$sha256.Key = $keyBytes
$calculatedHash = $sha256.ComputeHash($bytesToHash)
$encodedHash = [Convert]::ToBase64String($calculatedHash)
$authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
return $authorization
}
 
# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
$method = "POST"
$contentType = "application/json"
$resource = "/api/logs"
$rfc1123date = [DateTime]::UtcNow.ToString("r")
$contentLength = $body.Length
$signature = Build-Signature `
-customerId $customerId `
-sharedKey $sharedKey `
-date $rfc1123date `
-contentLength $contentLength `
-fileName $fileName `
-method $method `
-contentType $contentType `
-resource $resource
$uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
 
$headers = @{
"Authorization" = $signature;
"Log-Type" = $logType;
"x-ms-date" = $rfc1123date;
"time-generated-field" = $TimeStampField;
}
write-host "$TimeStampField"
$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
return $response.StatusCode
 
}
 

#Function for convert from UTC to Local time
function ConvertUTCtoLocal {
    param(
        $timeDifferenceInHours
    )

    $UniversalTime = (Get-Date).ToUniversalTime()
    $TimeDifferenceMinutes = 0 
    if ($TimeDifferenceInHours -match ":") {
        $TimeDifferenceHours = $TimeDifferenceInHours.Split(":")[0]
        $TimeDifferenceMinutes = $TimeDifferenceInHours.Split(":")[1]
    }
    else {
        $TimeDifferenceHours = $TimeDifferenceInHours
    }
    #Azure is using UTC time, justify it to the local time
    $ConvertedTime = $UniversalTime.AddHours($TimeDifferenceHours).AddMinutes($TimeDifferenceMinutes)
    Return $ConvertedTime
}

#Function write log
function Write-Log {
    param(
        [int]$level
        , [string]$Message
        , [ValidateSet("Info", "Warning", "Error")] [string]$severity = 'Info'
        , [string]$logname = $WVDTenantlog
        , [string]$color = "white"
    )
    $time = ConvertUTCtoLocal -timeDifferenceInHours $TimeDifference
    Add-Content $logname -Value ("{0} - [{1}] {2}" -f $time, $severity, $Message)
    if ($interactive) {
        switch ($severity) {
            'Error' { $color = 'Red' }
            'Warning' { $color = 'Yellow' }
        }
        if ($level -le $VerboseLogging) {
            if ($color -match "Red|Yellow") {
                Write-Output ("{0} - [{1}] {2}" -f $time, $severity, $Message) -ForegroundColor $color -BackgroundColor Black
                if ($severity -eq 'Error') {

                    throw $Message
                }
            }
            else {
                Write-Output ("{0} - [{1}] {2}" -f $time, $severity, $Message) -ForegroundColor $color
            }
        }
    }
    else {
        switch ($severity) {
            'Info' { Write-Verbose -Message $Message }
            'Warning' { Write-Warning -Message $Message }
            'Error' {
                throw $Message
            }
        }
    }
}

#Function get variable
function SetScriptVariable ($Name, $Value) {
    Invoke-Expression ("`$Script:" + $Name + " = `"" + $Value + "`"")
}

#set variables
$CurrentPath = Split-Path $script:MyInvocation.MyCommand.Path
#Json path
$JsonPath = "$CurrentPath\Config-MSI.Json"
#Log path
$WVDTenantlog = "$CurrentPath\wvdlogs.log"
# Specify the name of the record type that you'll be creating
$LogType = "PSTest"
# Specify a field with the created time for the records
$TimeStampField = ConvertUTCtoLocal -timeDifferenceInHours $TimeDifference
$TimeStampField = $TimeStampField.GetDateTimeFormats(115)

###### Verify Json file ######
if (Test-Path $JsonPath) {
    Write-Verbose "Found $JsonPath"
    Write-Verbose "Validating file..."
    try {
        $Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
    }
    catch {
        #$Validate = $false
        Write-Error "$JsonPath is invalid. Check Json syntax - Unable to proceed"
        Write-Log 3 "$JsonPath is invalid. Check Json syntax - Unable to proceed" "Error"
        exit 1
    }
}
else {
    #$Validate = $false
    Write-Error "Missing $JsonPath - Unable to proceed"
    Write-Log 3 "Missing $JsonPath - Unable to proceed" "Error"
    exit 1
}
##### Load Json Configuration values as variables #########
Write-Verbose "Loading values from Config.Json"
$Variable = Get-Content $JsonPath | Out-String | ConvertFrom-Json
$Variable.WVDScale.Azure | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { SetScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.WVDScaleSettings | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { SetScriptVariable -Name $_.Name -Value $_.Value }
$Variable.WVDScale.Deployment | ForEach-Object { $_.Variable } | Where-Object { $_.Name -ne $null } | ForEach-Object { SetScriptVariable -Name $_.Name -Value $_.Value }
##### Construct Begin time and End time for the Peak period from utc to local time #####
$TimeDifference = [string]$TimeDifferenceInHours

# Checking if the WVD Modules are existed
$WVDModules = Get-InstalledModule -Name "Microsoft.RDInfra.RDPowershell" -ErrorAction SilentlyContinue
if (!$WVDModules) {
    Write-Log 1 "WVD Modules doesn't exist. Ensure WVD Modules are installed if not execute this command 'Install-Module Microsoft.RDInfra.RDPowershell  -AllowClobber' "
    exit
}

Import-Module "Microsoft.RDInfra.RDPowershell"
$isServicePrincipalBool = ($isServicePrincipal -eq "True")

# MSI based authentication
#    - In order to rely on this, please add the MSI accounts as VM contributors at resource group level
Add-AzureRmAccount -Identity

#select the current Azure Subscription specified in the config
Select-AzureRmSubscription -SubscriptionId $currentAzureSubscriptionId

# Building credentials from KeyVault
$WVDServicePrincipalPwd = (Get-AzureKeyVaultSecret -VaultName $KeyVaultName -Name $KeyVaultSecretName).SecretValue
$WVDCreds = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList($Username, $WVDServicePrincipalPwd)

if (!$isServicePrincipalBool) {
    # if standard account is provided login in WVD with that account 
    try {
        $authentication = Add-RdsAccount -DeploymentUrl $RDBroker -Credential $WVDCreds

    }
    catch {
        Write-Log 1 "Failed to authenticate with WVD Tenant with standard account: $($_.exception.message)" "Error"
        exit 1

    }
    $obj = $authentication | Out-String
    Write-Log 3 "Authenticating as standard account for WVD. Result: `n$obj" "Info"
}
else {
    # if service principal account is provided login in WVD with that account 
    try {
        $authentication = Add-RdsAccount -DeploymentUrl $RDBroker -TenantId $AADTenantId -Credential $wvdCreds -ServicePrincipal

    }
    catch {
        Write-Log 1 "Failed to authenticate with WVD Tenant with the service principal: $($_.exception.message)" "Error"
        exit 1
    }
    $obj = $authentication | Out-String
    Write-Log 3 "Authenticating as service principal account for WVD. Result: `n$obj" "Info"
} 

$hostpoolInfo = Get-RdsHostPool -TenantName $tenantName -Name $hostPoolName
Write-Log 1 "$hostPoolName hostpool loadbalancer type is $($hostpoolInfo.LoadBalancerType)" "Info"
   
#Get the session hosts in the hostpool
$getHosts = Get-RdsSessionHost -TenantName $tenantname -HostPoolName $hostpoolname | Sort-Object Sessions -Descending | Sort-Object Status
if ($getHosts -eq $null) {
    Write-Log 1 "Hosts are does not exist in the Hostpool of '$hostpoolname'. Ensure that hostpool have hosts or not?." "Info"
    exit
}
    
#check the number of running session hosts
foreach ($sessionHost in $getHosts) {
    Write-Log 1 "Checking session host:$($sessionHost.SessionHostName | Out-String)  of sessions:$($sessionHost.Sessions) and status:$($sessionHost.Status)" "Info"
    $Sessionhostname = $sessionHost.SessionHostName
    $sessionCapacityofhost = $sessionhost.Sessions

    try {
    $hostPoolUserSessions = Get-RdsUserSession -TenantName $tenantName -HostPoolName $hostPoolName
    }
    catch {
        Write-Log 1 "Failed to retrieve user sessions in hostPool:$($hostPoolName) with error: $($_.exception.message)" "Error"
        exit 1
    }

     foreach($hostPoolUserSession in $hostPoolUserSessions){
        $hp = $hostPoolUserSession.HostPoolName
        $HN = $hostPoolUserSession.SessionHostName
        $upn = $hostPoolUserSession.UserPrincipalName
        $ss = $hostPoolUserSession.SessionState
        $ct = $hostPoolUserSession.CreateTime

$json = @"
[
    {
        "HostPoolName": "$hp",
        "SessionHostName": "$HN",
        "UserPrincipalName" : "$upn",
        "CreateTime" : "$ct",
        "SessionState" : "$ss"
    }
]
"@
        write-host $json
        Post-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
        Write-Log 3 "Send log to Log analytics" "Info"
     }
 }

