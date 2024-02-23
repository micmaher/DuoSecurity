<#
.SYNOPSIS
    Monitor Duo Posture
.DESCRIPTION
    What is the posture of users authing to Duo
    Do they have disk encryption
    Do they have security agents
    
.NOTES

    AUTHOR:    Michael Maher
#>
[cmdletbinding()]
Param()


#region Variables
    $kScript = 'monitorDuoPosture'
    $Kdate = ( get-date ).ToString('yyyy-MM-dd_H-mm')

    $cred = (Get-SavedCredential -UserName '*********'-Context 'Duo')
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred.Password)
    $Token = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

    $duoAPILimit = 999 # Paginate above this. Limit imposed by Duo is 1000 for this API


    $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls,Tls11,Tls12'
    [System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null # Turn SSL validation back on
 
#endregion


#region Modules and Functions

function New-DuoRequest(){
    param(
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            $apiHost = 'api-*****.duosecurity.com',
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiEndpoint,
        
        [Parameter(ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            $apiKey = '********',
        
        [Parameter(Mandatory=$true,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $apiSecret,
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            $requestMethod = 'GET',
        
        [Parameter(Mandatory=$false,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
            [ValidateNotNull()]
            [System.Collections.Hashtable]$requestParams
    )
    $date = (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000")
    $formattedParams = ($requestParams.Keys | Sort-Object | ForEach-Object {$_ + "=" + [uri]::EscapeDataString($requestParams.$_)}) -join "&"
    
    #DUO Params formatted and stored as bytes with StringAPIParams
    $requestToSign = (@(
        $Date.Trim(),
        $requestMethod.ToUpper().Trim(),
        $apiHost.ToLower().Trim(),
        $apiEndpoint.Trim(),
        $formattedParams
    ).trim() -join "`n").ToCharArray().ToByte([System.IFormatProvider]$UTF8)
    #Hash out some secrets 
    $hmacsha1 = [System.Security.Cryptography.HMACSHA1]::new($apiSecret.ToCharArray().ToByte([System.IFormatProvider]$UTF8))
    $hmacsha1.ComputeHash($requestToSign) | Out-Null
    $authSignature = [System.BitConverter]::ToString($hmacsha1.Hash).Replace("-", "").ToLower()
    #Create the Authorization Header
    $authHeader = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(('{0}:{1}' -f $apiKey, $authSignature)))
    #Create our Parameters for the webrequest - Easy @Splatting!
    $httpRequest = @{
        URI         = ('https://{0}{1}' -f $apiHost, $apiEndpoint)
        Headers     = @{
            "X-Duo-Date"    = $Date
            "Authorization" = "Basic $authHeader"
        }
        Body = $requestParams
        Method      = $requestMethod
        ContentType = 'application/x-www-form-urlencoded'
    }
    Write-Verbose $httpRequest.uri
    Write-Verbose $httpRequest.body
    $httpRequest
}
    

function ConvertTo-UnixTime {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [DateTime]$DateTime
    )
    begin {
        $epoch = [DateTime]::SpecifyKind('1970-01-01', 'Utc')
    }
    process {
        [Int64]($DateTime.ToUniversalTime() - $epoch).TotalMilliseconds
    }
}

#endregion


#region Main


$mintime = (Get-Date).AddHours(-3) | ConvertTo-UnixTime
$maxtime = (Get-Date) | ConvertTo-UnixTime
$next_offset = $null

$results = Do {
    
    $values = @{
        apiHost         = '******.duosecurity.com'
        apiEndpoint     = '/admin/v2/logs/authentication'
        requestMethod   = 'GET'
        requestParams   = @{
                               limit = $duoAPILimit
                               mintime = $mintime
                               maxtime = $maxtime
                               event_types = 'authentication'
                               }
        apiSecret       = $Token
        apiKey          = '********'
    }

    If ($null -ne $next_offset){
        Write-Verbose "Sleeping for 60 seconds between API calls"
        Start-Sleep -Seconds 60 # Duo limit requests to 1 per min as long as we don't go over 59,940 auth requests per hour we are good ;- )
        $values.requestParams.Add("next_offset",$next_offset)
        }

    $contructWebRequest = New-DuoRequest @values
    $wr = Invoke-WebRequest @contructWebRequest -UseBasicParsing -Verbose

    # Total results can increase since you are using the txtid as a marker and new auths come in and increase totalobjects while the script runs
    Write-Host "There are $((($wr.Content | ConvertFrom-Json).response.metadata).total_objects) objects"
    Write-Host "The first record is $(($wr.Content | ConvertFrom-Json).response.authlogs.txid | Select -First 1)"
    Write-Host "The last record is $(($wr.Content | ConvertFrom-Json).response.authlogs.txid | Select -Last 1)"

    If ((($wr.Content | ConvertFrom-Json).response.metadata).next_offset){
        $next_offset = (($wr.Content | ConvertFrom-Json).response.metadata).next_offset -join ","
        Write-Host "Offset is $next_offset"
    } 
    Else {
        Write-Host "No more results"
        $next_offset = $null
        }

    ($wr.Content | ConvertFrom-Json).response 
    If ($((($wr.Content | ConvertFrom-Json).response.metadata).total_objects) -lt $duoAPILimit){
        Write-Verbose "Total objects is less that $duoAPILimit so no need to make another query"
        $next_offset = $null
        }

} While ($next_offset)

$results.authlogs.txid | select -last 1




$main = $results.authlogs | 
    Select @{l="application_name";e={$_.application.name}}, email, factor, remembered_factor, reason, result, isotimestamp, trusted_endpoint_status, txid, 
    @{l="userid";e={$_.user.key}}, @{l="username";e={$_.user.name}}, @{l="auth_city";e={($_.auth_device | Select -ExpandProperty location).city}},
    @{l="auth_country";e={($_.auth_device | Select -ExpandProperty location).country}}, @{l="auth_state";e={($_.auth_device | Select -ExpandProperty location).state}},
    @{l="authip";e={$_.auth_device.ip}}
   
 

$access_device = $results.authlogs | 
    Select @{l="browser";e={($_.access_device).browser}}, @{l="browser_version";e={($_.access_device).browser_version}},@{l="endpoint_key";e={($_.access_device).epkey}}, 
    @{l="flash_version";e={($_.access_device).flash_version}},@{l="access_ip";e={($_.access_device).ip}}, @{l="encryption_enabled";e={($_.access_device).is_encryption_enabled}}, 
    @{l="firewall_enabled";e={($_.access_device).is_firewall_enabled}}, @{l="password_set";e={($_.access_device).is_password_set}},
    @{l="java_version";e={($_.access_device).java_version}}, @{l="city";e={($_.access_device | Select -ExpandProperty location).city}},
    @{l="country";e={($_.access_device| Select -ExpandProperty location).country}}, @{l="state";e={($_.access_device | Select -ExpandProperty location).state}},
    @{l="os";e={($_.access_device).os}}, @{l="os_version";e={($_.access_device).os_version}}, txid
    
       $access_device | select -first 5

$security_agents = $results.authlogs| 
    Select @{l="security_agents";e={($_.access_device | Select -ExpandProperty security_agents).security_agent}}, txid
