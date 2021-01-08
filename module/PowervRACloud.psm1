#Author - Munishpal Makhija

#    ===========================================================================
#    Created by:    Munishpal Makhija
#    Release Date:  04/15/2020
#    Organization:  VMware
#    Version:       1.2
#    Blog:          http://bit.ly/MyvBl0g
#    Twitter:       @munishpal_singh
#    ===========================================================================


####################### Get-vRACloudCommands ######################### 

function Get-vRACloudCommands {
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          01/13/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all cmdlets for vRA Cloud
    .DESCRIPTION
        This cmdlet will allow you to return all cmdlets included in the Power vRA Cloud Module
    .EXAMPLE
        Get-vRACloudCommands
    .EXAMPLE
        Get-Command -Module PowervRACloud
    .NOTES
        You can either use this cmdlet or the Get-Command cmdlet as seen in Example 2
#>
    Get-Command -Module PowervRACloud

}

####################### Connect-vRA-Cloud ######################### 

function Connect-vRA-Cloud
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          06/29/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Connects to vRA Cloud and gets CSP Access Token to be used with APIs 
    .DESCRIPTION
        This cmdlet creates $global:defaultvRAConnection object
    .EXAMPLE
        Connect-vRA-Cloud -APIToken $APIToken
        Input APIToken as Secure String by using Read-Host "$APIToken = Read-Host -AsSecureString"            
#>
    param (
    [Parameter (Mandatory=$true)]
      # vRA Cloud API Token
      [ValidateNotNullOrEmpty()]
      [Security.SecureString]$APIToken
  )  
  if (($PSVersionTable.PSVersion.Major -eq 6)) {
     $API = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($APIToken)) 
  }
  elseif (($PSVersionTable.PSVersion.Major -eq 7)) {
     $API = ConvertFrom-SecureString -SecureString $APIToken -AsPlainText
  }  
  $url = "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token="+ $API
  $headers = @{"Accept"="application/json";
 "Content-Type"="application/json";
}
$payload = @{"refresh_token"=$API;}
$body= $payload | Convertto-Json
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -ErrorAction:Stop
  if($response)
  {
    #$response = ($response | ConvertFrom-Json)

    # Setup a custom object to contain the parameters of the connection, including the URL to the CSP API & Access token
    $connection = [pscustomObject] @{
      "Server" = "api.mgmt.cloud.vmware.com"
      "CSPToken" = $response.access_token
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRAConnection -value $connection -scope Global

    # Return the connection
    $connection
  }
}

####################### Connect-vRA-Server ######################### 

function Connect-vRA-Server
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          10/06/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Connects to vRA Server and gets CSP Access Token to be used with APIs 
    .DESCRIPTION
        This cmdlet creates $global:defaultvRAConnection object
    .EXAMPLE
        Connect-vRA-Server -Server "vraserverfqdn" -Credential $credentials            
#>
    param (
    [Parameter (Mandatory=$true)]
      # vRA Server hostname or IP address
      [ValidateNotNullOrEmpty()]
      [string]$Server,    
    [Parameter (Mandatory=$true)]
      #PSCredential object containing vRA Server Authentication credentials
      [PSCredential]$Credential      
  )  
  
  $pwd = $Credential.Password
  $username = $Credential.Username
  if (($PSVersionTable.PSVersion.Major -eq 6)) {
     $password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pwd))
  }
  elseif (($PSVersionTable.PSVersion.Major -eq 7)) {
     $password = ConvertFrom-SecureString -SecureString $pwd -AsPlainText
  }    
  $uri = "/csp/gateway/am/api/login?access_token"
  $url = "https://"+ $Server+ $uri
  $headers = @{"Accept"="application/json";
 "Content-Type"="application/json";
}
$payload = @{"username"=$username;
"password"=$password;}
$body= $payload | Convertto-Json
$response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $body -SkipCertificateCheck -ErrorAction:Stop
  if($response)
  {
    #$response = ($response | ConvertFrom-Json)

    # Setup a custom object to contain the parameters of the connection, including the URL to the CSP API & Access token
    $connection = [pscustomObject] @{
      "Server" = $Server
      "CSPToken" = $response.access_token
    }

    # Remember this as the default connection
    Set-Variable -name defaultvRAConnection -value $connection -scope Global

    # Return the connection
    $connection
  }
}
 
####################### Disconnect-vRA-Cloud ######################### 

function Disconnect-vRA-Cloud
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          01/13/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Destroys $global:defaultvRAConnection object if it exists
    .DESCRIPTION
        REST is not connection oriented, so there really isnt a connect/disconnect concept. It destroys $global:defaultvRAConnection object if it exists
    .EXAMPLE
        Disconnect-vRA-Cloud                  
#>
    if (Get-Variable -Name defaultvRAConnection -scope global ) {
        Remove-Variable -name defaultvRAConnection -scope global
    }
}



######################### New-vRA-CloudAccount-vSphere ######################### 

function New-vRA-CloudAccount-vSphere
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          01/13/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .EXAMPLE
        New-vRA-CloudAccount-vSphere -vCenterHostName "vCenter FQDN" -Credential $Credential -vCenterDCName "vCenter Datacenter Name" -CloudProxyName "Cloud Proxy Name" -CloudAccountName "CloudAccountName"
        Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential    
#>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$true)]
        # vCenter Hostname Name
        [ValidateNotNullOrEmpty()]
        [string]$vCenterHostName,
      [Parameter (Mandatory=$true)]
        #PSCredential object containing vCenter Authentication Credentials
        [PSCredential]$Credential,
      [Parameter (Mandatory=$true)]
        # vCenter Datacenter Name
        [ValidateNotNullOrEmpty()]
        [string]$vcenterDCName,
      [Parameter (Mandatory=$true)]
        # vRA Cloudproxy Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudProxyName,        
      [Parameter (Mandatory=$true)]
        # vRA Cloud Account Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudAccountName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            ##### VC Connection to get DCID #####
            $vcenterusername = $Credential.UserName
            $vcenterpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            Write-Host "Validating vCenter Details:  " $vcenterhostname -ForegroundColor Green
            $vc = Connect-VIServer -Server $vCenterHostName -Credential $Credential
            $vc
            $dcid = (Get-Datacenter -Server $vCenterHostName | Get-View).MoRef.Value
            $dc = "Datacenter:"+$dcid
            $cloudproxy = Get-vRA-Datacollectors | where{$_.name -match $CloudProxyName}
            $dcid = $cloudproxy.dcId
            $vra_payload = "{
              cloudAccountType: vsphere,
              privateKeyId: $vcenterusername,
              privateKey: $vcenterpassword,
              cloudAccountProperties:{
                hostName: $vcenterhostname,
                acceptSelfSignedCertificate: true,
                dcId: $dcid
              },
              createDefaultZones: true,
              name: $cloudaccountname,
              description: $vcenterhostname,
              regionIds: [ '$dc' ]
              }"
            $vra_body = $vra_payload
            Disconnect-VIServer * -Confirm:$false
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop
            $response
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Error "Error Adding vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-Server-CloudAccount-vSphere ######################### 

function New-vRA-Server-CloudAccount-vSphere
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          04/03/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .EXAMPLE
        New-vRA-Server-CloudAccount-vSphere -vCenterHostName "vCenter FQDN" -Credential $Credential -vCenterDCName "vCenter Datacenter Name" -CloudAccountName "CloudAccountName"
        Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential    
#>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$true)]
        # vCenter Hostname Name
        [ValidateNotNullOrEmpty()]
        [string]$vCenterHostName,
      [Parameter (Mandatory=$true)]
        #PSCredential object containing vCenter Authentication Credentials
        [PSCredential]$Credential,
      [Parameter (Mandatory=$true)]
        # vCenter Datacenter Name
        [ValidateNotNullOrEmpty()]
        [string]$vcenterDCName,       
      [Parameter (Mandatory=$true)]
        # vRA Cloud Account Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudAccountName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            ##### VC Connection to get DCID #####
            $vcenterusername = $Credential.UserName
            $vcenterpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            Write-Host "Validating vCenter Details:  " $vcenterhostname -ForegroundColor Green
            $vc = Connect-VIServer -Server $vCenterHostName -Credential $Credential
            $vc
            $dcid = (Get-Datacenter -Server $vCenterHostName | Get-View).MoRef.Value
            $dc = "Datacenter:"+$dcid
            $vra_payload = "{
              cloudAccountType: vsphere,
              privateKeyId: $vcenterusername,
              privateKey: $vcenterpassword,
              cloudAccountProperties:{
                hostName: $vcenterhostname,
                acceptSelfSignedCertificate: true
              },
              createDefaultZones: true,
              name: $cloudaccountname,
              description: $vcenterhostname,
              regionIds: [ '$dc' ]
              }"
            $vra_body = $vra_payload
            Disconnect-VIServer * -Confirm:$false
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Error "Error Adding vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-CloudAccount-VMC ######################### 

function New-vRA-CloudAccount-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          02/22/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Cloud Account for VMC endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Cloud Account for VMC endpoint in a particular Org 
    .EXAMPLE
        New-vRA-CloudAccount-VMC -VMC_API_KEY $VMC_API_Key -VMC_SDDC_Name "VMC SDDC Name" -vCenterHostname "vCenter FQDN" -Credential $Credential -VMC_NSX_IP "VMC NSX IP" -CloudProxyName "Cloud Proxy Name" -CloudAccountName "CloudAccountName"
        Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential
        Use Read-Host to add VMC_API_Key as Secure String ; $VMC_API_Key = Read-Host -AsSecureString    
#>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$true)]
        # VMC API Key
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]$VMC_API_KEY,
      [Parameter (Mandatory=$true)]
        # VMC SDDC Name
        [ValidateNotNullOrEmpty()]
        [string]$VMC_SDDC_Name,                
      [Parameter (Mandatory=$true)]
        # vCenter Hostname Name
        [ValidateNotNullOrEmpty()]
        [string]$vCenterHostname,
      [Parameter (Mandatory=$true)]
        #PSCredential object containing vCenter Authentication Credentials
        [PSCredential]$Credential,
      [Parameter (Mandatory=$true)]
        # VMC NSX IP
        [ValidateNotNullOrEmpty()]
        [string]$VMC_NSX_IP,
      [Parameter (Mandatory=$true)]
        # vRA Cloudproxy Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudProxyName,        
      [Parameter (Mandatory=$true)]
        # vRA Cloud Account Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudAccountName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            ##### VC Connection to get DCID #####
            $vcenterusername = $Credential.UserName
            $vcenterpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            $API = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($VMC_API_KEY))            
            Write-Host "Validating vCenter Details:  " $vcenterhostname -ForegroundColor Green
            $vc = Connect-VIServer -Server $vCenterHostName -Credential $Credential
            $vc
            $dcid = (Get-Datacenter -Server $vCenterHostName | Get-View).MoRef.Value
            $dc = "Datacenter:"+$dcid
            $cloudproxy = Get-vRA-Datacollectors | where{$_.name -match $CloudProxyName}
            $dcid = $cloudproxy.dcId
            $vra_payload = "{
              cloudAccountType: vmc,
              privateKeyId: $vcenterusername,
              privateKey: $vcenterpassword,
              cloudAccountProperties:{
                hostName: $vcenterhostname,
                acceptSelfSignedCertificate: false,
                dcId: $dcid,
                apiKey: $API,
                nsxHostName: $VMC_NSX_IP,
                sddcId: $VMC_SDDC_Name
              },
              createDefaultZones: true,
              name: $cloudaccountname,
              description: $vcenterhostname,
              regionIds: [ '$dc' ]
              }"
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop
            $response
            Disconnect-VIServer * -Confirm:$false                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Disconnect-VIServer * -Confirm:$false
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Disconnect-VIServer * -Confirm:$false
                Write-Error "Error Adding vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-Server-CloudAccount-VMC ######################### 

function New-vRA-Server-CloudAccount-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          04/03/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Cloud Account for VMC endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Cloud Account for VMC endpoint in a particular Org 
    .EXAMPLE
        New-vRA-Server-CloudAccount-VMC -VMC_API_KEY $VMC_API_Key -VMC_SDDC_Name "VMC SDDC Name" -vCenterHostname "vCenter FQDN" -Credential $Credential -VMC_NSX_IP "VMC NSX IP" -CloudAccountName "CloudAccountName"
        Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential
        Use Read-Host to add VMC_API_Key as Secure String ; $VMC_API_Key = Read-Host -AsSecureString    
#>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$true)]
        # VMC API Key
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]$VMC_API_KEY,
      [Parameter (Mandatory=$true)]
        # VMC SDDC Name
        [ValidateNotNullOrEmpty()]
        [string]$VMC_SDDC_Name,                
      [Parameter (Mandatory=$true)]
        # vCenter Hostname Name
        [ValidateNotNullOrEmpty()]
        [string]$vCenterHostname,
      [Parameter (Mandatory=$true)]
        #PSCredential object containing vCenter Authentication Credentials
        [PSCredential]$Credential,
      [Parameter (Mandatory=$true)]
        # VMC NSX IP
        [ValidateNotNullOrEmpty()]
        [string]$VMC_NSX_IP,        
      [Parameter (Mandatory=$true)]
        # vRA Cloud Account Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudAccountName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            ##### VC Connection to get DCID #####
            $vcenterusername = $Credential.UserName
            $vcenterpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            $API = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($VMC_API_KEY))            
            Write-Host "Validating vCenter Details:  " $vcenterhostname -ForegroundColor Green
            $vc = Connect-VIServer -Server $vCenterHostName -Credential $Credential
            $vc
            $dcid = (Get-Datacenter -Server $vCenterHostName | Get-View).MoRef.Value
            $dc = "Datacenter:"+$dcid
            $vra_payload = "{
              cloudAccountType: vmc,
              privateKeyId: $vcenterusername,
              privateKey: $vcenterpassword,
              cloudAccountProperties:{
                hostName: $vcenterhostname,
                acceptSelfSignedCertificate: false,
                apiKey: $API,
                nsxHostName: $VMC_NSX_IP,
                sddcId: $VMC_SDDC_Name
              },
              createDefaultZones: true,
              name: $cloudaccountname,
              description: $vcenterhostname,
              regionIds: [ '$dc' ]
              }"
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response
            Disconnect-VIServer * -Confirm:$false                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Disconnect-VIServer * -Confirm:$false
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Disconnect-VIServer * -Confirm:$false
                Write-Error "Error Adding vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-CloudAccount-AWS ######################### 

function New-vRA-CloudAccount-AWS
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          07/15/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Cloud Account for vSphere endpoint in a particular Org 
    .EXAMPLE
        New-vRA-CloudAccount-AWS -CloudAccountName "CloudAccountName" -awsaccesskeyid "AWS Access Key" -awssecretAccessKey $awssecretAccessKey -awsregionid  "us-east-1" 
        Use ConvertTo-SecureString "AWS Secret AccessKey" -AsPlainText -Force and store it in variable and pass that as an Input     
#>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$true)]
        # vRA Cloud Account Name
        [ValidateNotNullOrEmpty()]
        [string]$CloudAccountName,        
      [Parameter (Mandatory=$true)]
        # AWS Access Key
        [ValidateNotNullOrEmpty()]
        [string]$awsaccesskeyid,
        # AWS Secret AccessKey
        [ValidateNotNullOrEmpty()]
        [Security.SecureString]$awssecretAccessKey,
      [Parameter (Mandatory=$true)]
        # AWS Region ID
        [ValidateNotNullOrEmpty()]
        [string]$awsregionid            
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
              if (($PSVersionTable.PSVersion.Major -eq 6)) {
              $SecretAccessKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($awssecretAccessKey)) 
              }
              elseif (($PSVersionTable.PSVersion.Major -eq 7)) {
                $SecretAccessKey = ConvertFrom-SecureString -SecureString $awssecretAccessKey -AsPlainText
              } 
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }             
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $description = "Created-by-PowervRACloud"
            $region = @($awsregionid)           
            $vra_payload = @{
              "privateKey"=$SecretAccessKey;
              "regionIds"=$region;               
              "cloudAccountType"="aws";
              "name"=$cloudaccountname;
              "description"=$description;                                                        
              "privateKeyId"=$awsaccessKeyId;
              "createDefaultZones"="true";             
              }   
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -SkipCertificateCheck:$SkipSSLCheck -ErrorAction:Stop
            $response
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                Write-Error "Error Adding vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

  ######################### New-vRA-CloudAccount-NSXT ######################### 

    function New-vRA-CloudAccount-NSXT
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/22/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Creates new vRA Cloud Account for NSXT endpoint in a particular Org 
        .DESCRIPTION
            This cmdlet creates new vRA Cloud Account for NSXT endpoint in a particular Org 
        .EXAMPLE
            New-vRA-CloudAccount-NSXT -NSXTHostName "NSXT FQDN" -Credential $Credential -CloudProxyName "Cloud Proxy Name" -CloudAccountName "CloudAccountName" -VCCloudAccountName "VC CloudAccount Name"-UsePolicyAPI "true" -AcceptSelfSignedCertificate "false" 
            Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential    
    #>
          param (
          [Parameter (Mandatory=$False)]
            # vRA Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultvRAConnection,
          [Parameter (Mandatory=$true)]
            # NSXT Hostname Name
            [ValidateNotNullOrEmpty()]
            [string]$NSXTHostName,
          [Parameter (Mandatory=$true)]
            #PSCredential object containing vCenter Authentication Credentials
            [PSCredential]$Credential,
          [Parameter (Mandatory=$true)]
            # vRA Cloudproxy Name
            [ValidateNotNullOrEmpty()]
            [string]$CloudProxyName,        
          [Parameter (Mandatory=$true)]
            # vRA Cloud Account Name
            [ValidateNotNullOrEmpty()]
            [string]$CloudAccountName,
          [Parameter (Mandatory=$true)]
            # vCenter Cloud Account Name
            [ValidateNotNullOrEmpty()]
            [string]$VCCloudAccountName,            
          [Parameter (Mandatory=$false)]
            # Use Policy API Mode 
            [ValidateNotNullOrEmpty()]
            [string]$UsePolicyAPI="false",
          [Parameter (Mandatory=$false)]
            # Accept SelfSigned Certificate 
            [ValidateNotNullOrEmpty()]
            [string]$AcceptSelfsignedCertificate="false"                          
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $vra_uri = "/iaas/api/cloud-accounts"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $nsxtusername = $Credential.UserName
                $nsxtpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
                $cloudproxy = Get-vRA-Datacollectors | where{$_.name -match $CloudProxyName}
                $dcid = $cloudproxy.dcId
                $ca = Get-vRA-CloudAccounts | where{$_.name -eq $VCCloudAccountName}
                $caid = $ca.id
                $vra_payload = "{
                  cloudAccountType: nsxt,
                  privateKeyId: $nsxtusername,
                  privateKey: $nsxtpassword,
                  cloudAccountProperties:{
                    hostName: $nsxthostname,
                    acceptSelfSignedCertificate: $AcceptSelfsignedCertificate,
                    dcId: $dcid,
                    use.policy.api: $UsePolicyAPI
                  },
                  name: $cloudaccountname,
                  description: $nsxthostname,
                  associatedCloudAccountIds: [ '$caid' ]
                  }"
                $vra_body = $vra_payload
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop
                $response
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                    Write-Error "Error Adding vRA Cloud Accounts"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


    ######################### New-vRA-Server-CloudAccount-NSXT ######################### 

    function New-vRA-Server-CloudAccount-NSXT
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/22/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Creates new vRA Cloud Account for NSXT endpoint in a particular Org 
        .DESCRIPTION
            This cmdlet creates new vRA Cloud Account for NSXT endpoint in a particular Org 
        .EXAMPLE
            New-vRA-Server-CloudAccount-NSXT -NSXTHostName "NSXT FQDN" -Credential $Credential -CloudAccountName "CloudAccountName" -VCCloudAccountName "VC CloudAccount Name"-UsePolicyAPI "true" -AcceptSelfSignedCertificate "false" 
            Use Get-Credential to add vCenter Credentials and pass it as Input Parameter $Credential = Get-Credential    
    #>
          param (
          [Parameter (Mandatory=$False)]
            # vRA Connection object
            [ValidateNotNullOrEmpty()]
            [PSCustomObject]$Connection=$defaultvRAConnection,
          [Parameter (Mandatory=$true)]
            # NSXT Hostname Name
            [ValidateNotNullOrEmpty()]
            [string]$NSXTHostName,
          [Parameter (Mandatory=$true)]
            #PSCredential object containing vCenter Authentication Credentials
            [PSCredential]$Credential,       
          [Parameter (Mandatory=$true)]
            # vRA Cloud Account Name
            [ValidateNotNullOrEmpty()]
            [string]$CloudAccountName,
          [Parameter (Mandatory=$true)]
            # vCenter Cloud Account Name
            [ValidateNotNullOrEmpty()]
            [string]$VCCloudAccountName,            
          [Parameter (Mandatory=$false)]
            # Use Policy API Mode 
            [ValidateNotNullOrEmpty()]
            [string]$UsePolicyAPI="false",
          [Parameter (Mandatory=$false)]
            # Accept SelfSigned Certificate 
            [ValidateNotNullOrEmpty()]
            [string]$AcceptSelfsignedCertificate="false"                          
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $vra_uri = "/iaas/api/cloud-accounts"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $nsxtusername = $Credential.UserName
                $nsxtpassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
                $ca = Get-vRA-CloudAccounts | where{$_.name -eq $VCCloudAccountName}
                $caid = $ca.id
                $vra_payload = "{
                  cloudAccountType: nsxt,
                  privateKeyId: $nsxtusername,
                  privateKey: $nsxtpassword,
                  cloudAccountProperties:{
                    hostName: $nsxthostname,
                    acceptSelfSignedCertificate: $AcceptSelfsignedCertificate,
                    use.policy.api: $UsePolicyAPI
                  },
                  name: $cloudaccountname,
                  description: $nsxthostname,
                  associatedCloudAccountIds: [ '$caid' ]
                  }"
                $vra_body = $vra_payload
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop
                $response
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    if ($global:DefaultVIServers.Count -gt 0) {Disconnect-VIServer * -Confirm:$false}
                    Write-Error "Error Adding vRA Cloud Accounts"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


######################### Get-vRA-CloudAccounts ######################### 

function Get-vRA-CloudAccounts
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Cloud Accounts in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Cloud Accounts in a particular Org 
    .EXAMPLE
        Get-vRA-CloudAccounts
    .EXAMPLE
        Get-vRA-CloudAccounts | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/cloud-accounts"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }             
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Cloud Accounts"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-Machines ######################### 

function Get-vRA-Machines
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Machines in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Machines in a particular Org 
    .EXAMPLE
        Get-vRA-Machines
    .EXAMPLE
        Get-vRA-Machines | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=2000       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?`$top="+ $Size             
            $vra_uri = "/iaas/api/machines"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Machines"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-MachineSnapshots ######################### 

function Get-vRA-MachineSnapshots
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRA Machine Snapshots in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRA Machine Snapshots in a particular Org 
    .EXAMPLE
        Get-vRA-MachineSnapshots -MachineName "Test"       
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Machine Name
      [ValidateNotNullOrEmpty()]
      [string]$MachineName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $machine = Get-vRA-Machines | where{$_.name -eq $MachineName}
            $mid = $machine.id
            $vra_uri = "/iaas/api/machines/"+ $mid+ "/snapshots"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Machine Snapshots"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-Regions ######################### 

function Get-vRA-Regions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Regions in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Regions in a particular Org 
    .EXAMPLE
        Get-vRA-Regions
    .EXAMPLE
        Get-vRA-Regions | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/regions"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Regions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-Datacollectors ######################### 

function Get-vRA-Datacollectors
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          01/13/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Datacollectors in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Datacollectors in a particular Org 
    .EXAMPLE
        Get-vRA-Datacollectors
    .EXAMPLE
        Get-vRA-Datacollectors | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/data-collectors"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Datacollectors"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}




######################### New-vRA-FlavorProfiles-vSphere ######################### 

function New-vRA-FlavorProfiles-vSphere
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Flavor Profiles for vSphere endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Flavor Profile for vSphere endpoint in a particular Org 
    .EXAMPLE
        New-vRA-FlavorProfiles-vSphere -ProfileName "ProfileName" -FlavorName "FlavorName" -FlavorCpu "CPUCount" -FlavorMemory "MemoryinMB" -RegionName "vRA Zone Name"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,      
    [Parameter (Mandatory=$true)]
      # vRA Flavor Name
      [ValidateNotNullOrEmpty()]
      [string]$FlavorName,
    [Parameter (Mandatory=$true)]
      # vRA Flavor CPU Count
      [ValidateNotNullOrEmpty()]
      [string]$FlavorCpu,
    [Parameter (Mandatory=$true)]
      # vRA Flavor Memory in MB
      [ValidateNotNullOrEmpty()]
      [string]$FlavorMemory,      
    [Parameter (Mandatory=$true)]
      # vRA Zone Name
      [ValidateNotNullOrEmpty()]
      [string]$RegionName       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/flavor-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $RegionName} | Select id
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid} | Select id
            $regionid = $region.id
            $flavor = $flavorname+ ":"
            $vra_payload = "{
              name: $profilename,
              flavorMapping:{
                $flavor{
                  cpuCount: $flavorcpu,
                  memoryInMB: $flavormemory
              }},
              regionId: $regionid
              }"
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Flavor Profiles vSphere"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-FlavorProfiles-VMC ######################### 

function New-vRA-FlavorProfiles-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          06/30/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Flavor Profiles for VMC endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Flavor Profile for VMC endpoint in a particular Org 
    .EXAMPLE
        New-vRA-FlavorProfiles-VMC -ProfileName "ProfileName" -FlavorName "FlavorName" -FlavorCpu "CPUCount" -FlavorMemory "MemoryinMB" -RegionName "vRA Zone Name"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,      
    [Parameter (Mandatory=$true)]
      # vRA Flavor Name
      [ValidateNotNullOrEmpty()]
      [string]$FlavorName,
    [Parameter (Mandatory=$true)]
      # vRA Flavor CPU Count
      [ValidateNotNullOrEmpty()]
      [string]$FlavorCpu,
    [Parameter (Mandatory=$true)]
      # vRA Flavor Memory in MB
      [ValidateNotNullOrEmpty()]
      [string]$FlavorMemory,      
    [Parameter (Mandatory=$true)]
      # vRA Zone Name
      [ValidateNotNullOrEmpty()]
      [string]$RegionName       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/flavor-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $RegionName} | Select id
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -ne $caid -and ($_.name -eq "SDDC-Datacenter")} | Select id
            $regionid = $region.id
            $flavor = $flavorname+ ":"
            $vra_payload = "{
              name: $profilename,
              flavorMapping:{
                $flavor{
                  cpuCount: $flavorcpu,
                  memoryInMB: $flavormemory
              }},
              regionId: $regionid
              }"
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Flavor Profiles vSphere"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-FlavorProfiles-AWS ######################### 

function New-vRA-FlavorProfiles-AWS
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0New
    Date:          06/30/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Flavor Profiles for AWS endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Flavor Profile for AWS endpoint in a particular Org 
    .EXAMPLE
        New-vRA-FlavorProfiles-AWS -ProfileName "ProfileName" -FlavorName "FlavorName" -FlavorType "EC2 Instance Type" -RegionName "vRA Zone Name"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,      
    [Parameter (Mandatory=$true)]
      # vRA Flavor Name
      [ValidateNotNullOrEmpty()]
      [string]$FlavorName,
    [Parameter (Mandatory=$true)]
      # vRA Flavor Type
      [ValidateNotNullOrEmpty()]
      [string]$FlavorType,
    [Parameter (Mandatory=$true)]
      # vRA Zone Name
      [ValidateNotNullOrEmpty()]
      [string]$RegionName       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/flavor-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $RegionName} | Select id
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid} | Select id
            $regionid = $region.id
            $flavor = $flavorname+ ":"
            $vra_payload = "{
              name: $profilename,
              flavorMapping:{
                $flavor{
                  name: $flavortype
              }},
              regionId: $regionid
              }"
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Flavor Profiles vSphere"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-ImageMapping ######################### 

function New-vRA-ImageMapping
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Image Mapping in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Image Mapping in a particular Org 
    .EXAMPLE
        New-vRA-ImageMapping -ProfileName "ProfileName" -vRAImageName "vRA Image Name" -CloudAccountName "vRA Cloud Account Name" -VCImage "vCenter Image Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,
    [Parameter (Mandatory=$true)]
      # vRA Image Name
      [ValidateNotNullOrEmpty()]
      [string]$vRAImageName,            
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Image Name
      [ValidateNotNullOrEmpty()]
      [string]$VCImage         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/image-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $image = Get-vRA-FabricImagesFilter -filtertype "name" -filtervalue $VCImage
            $imageid =  $image.id
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id
            $vraimage = $vraimagename+ ":"
            $vra_payload = "{
              name: $profilename,
              imageMapping:{
                $vraimage{
                  id: $imageid
              }},
              regionId: $regionid
              }"  
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Image Mapping"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-ImageMapping-VMC ######################### 

function New-vRA-ImageMapping-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          06/30/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Image Mapping  for VMC endpoint in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Image Mapping for VMC endpoint in a particular Org 
    .EXAMPLE
        New-vRA-ImageMapping-VMC -ProfileName "ProfileName" -vRAImageName "vRA Image Name" -CloudAccountName "vRA Cloud Account Name" -VCImage "vCenter Image Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,
    [Parameter (Mandatory=$true)]
      # vRA Image Name
      [ValidateNotNullOrEmpty()]
      [string]$vRAImageName,            
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Image Name
      [ValidateNotNullOrEmpty()]
      [string]$VCImage         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/image-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $image = Get-vRA-FabricImagesFilter -filtertype "name" -filtervalue $VCImage
            $imageid =  $image[0].id
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -ne $caid -and ($_.name -eq "SDDC-Datacenter")} 
            $regionid = $region.id
            $vraimage = $vraimagename+ ":"
            $vra_payload = "{
              name: $profilename,
              imageMapping:{
                $vraimage{
                  id: $imageid
              }},
              regionId: $regionid
              }"  
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Image Mapping"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-ImageMapping-AWS ######################### 

function New-vRA-ImageMapping-AWS
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          10/06/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Image Mapping for AWS in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Image Mapping for AWS in a particular Org 
    .EXAMPLE
        New-vRA-ImageMapping-AWS -ProfileName "ProfileName" -vRAImageName "vRA Image Name" -CloudAccountName "vRA Cloud Account Name" -AMI "ami-ubuntu-16.04-1.9.1-00-1516139717" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,
    [Parameter (Mandatory=$true)]
      # vRA Image Name
      [ValidateNotNullOrEmpty()]
      [string]$vRAImageName,            
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # AWS AMI ID
      [ValidateNotNullOrEmpty()]
      [string]$AMI         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/image-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id
            $externalid = $region.externalRegionId
            $image = Get-vRA-FabricImagesFilter -filtertype "externalId" -filtervalue $AMI | where{$_.externalRegionId -eq $externalid}
            $imageid =  $image.id

            $vraimage = $vraimagename+ ":"
            $vra_payload = "{
              name: $profilename,
              imageMapping:{
                $vraimage{
                  id: $imageid
              }},
              regionId: $regionid
              }"  
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Image Mapping"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-NetworkProfile ######################### 

function New-vRA-NetworkProfile
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Network Profile with an existing Network in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Network Profile with an existing Network in a particular Org 
    .EXAMPLE
        New-vRA-NetworkProfile -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -VCNetwork "vCenter Network Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Network Name
      [ValidateNotNullOrEmpty()]
      [string]$VCNetwork         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/network-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id
            $network = Get-vRA-FabricNetworksFilter -filtertype "name" -filtervalue $VCNetwork
            $networkid =  $network.id            
            $vra_payload = "{
              name: $profilename,
              fabricNetworkIds: [ '$networkid' ],
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                   
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Network Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-NetworkProfile-VMC ######################### 

function New-vRA-NetworkProfile-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          06/30/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Network Profile for VMC with an existing Network in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Network Profile for VMC with an existing Network in a particular Org 
    .EXAMPLE
        New-vRA-NetworkProfile-VMC -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -VCNetwork "vCenter Network Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Network Name
      [ValidateNotNullOrEmpty()]
      [string]$VCNetwork         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/network-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -ne $caid -and ($_.name -eq "SDDC-Datacenter")} 
            $regionid = $region.id
            $network = Get-vRA-FabricNetworksFilter -filtertype "name" -filtervalue $VCNetwork
            $networkid =  $network.id            
            $vra_payload = "{
              name: $profilename,
              fabricNetworkIds: [ '$networkid' ],
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                   
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Network Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-NetworkProfile-AWS ######################### 

function New-vRA-NetworkProfile-AWS
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          07/07/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Network Profile with an existing Network in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Network Profile with an existing Network in a particular Org 
    .EXAMPLE
        New-vRA-NetworkProfile-AWS -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -AWSNetwork "AWS Network Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # AWS Network Name
      [ValidateNotNullOrEmpty()]
      [string]$AWSNetwork         
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/network-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id
            $network = Get-vRA-FabricNetworksFilter -filtertype "name" -filtervalue $AWSNetwork
            $networkid =  $network.id            
            $vra_payload = "{
              name: $profilename,
              fabricNetworkIds: [ '$networkid' ],
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $vra_body
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                   
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Network Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-vSphereStorageProfile ######################### 

function New-vRA-vSphereStorageProfile
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA vSphere Storage Profile for vSphere datastore in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA vSphere Storage Profile for vSphere datastore in a particular Org 
    .EXAMPLE
        New-vRA-vSphereStorageProfile -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -VCDatastore "vCenter Datastore Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Network Name
      [ValidateNotNullOrEmpty()]
      [string]$VCDatastore            
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/storage-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            

            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id
            $ds = Get-vRA-FabricvSphereDatastoresFilter -filtertype "name" -filtervalue $VCDatastore | where {$_.CloudAccountIds -eq $caid}
            #$ds = Get-vRA-FabricvSphereDatastores | where {$_.Name -eq $VCDatastore -and $_.CloudAccountIds -eq $caid}
            $dsid =  $ds.id            
            $defaultitem = "true"
            $ds_id = "'"+ $dsid+ "'"
            $vra_payload = "{
              name: $profilename, 
              defaultItem: $defaultitem,
              diskTargetProperties:{
                  datastoreId: $ds_id
              },              
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA vSphere Storage Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-vSphereStorageProfile-VMC ######################### 

function New-vRA-vSphereStorageProfile-VMC
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          06/30/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA vSphere Storage Profile for VMC datastore in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA vSphere Storage Profile for VMC datastore in a particular Org 
    .EXAMPLE
        New-vRA-vSphereStorageProfile-VMC -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -VCDatastore "vCenter Datastore Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # vCenter Network Name
      [ValidateNotNullOrEmpty()]
      [string]$VCDatastore            
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/storage-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -ne $caid -and ($_.name -eq "SDDC-Datacenter")}
            $regionid = $region.id
            $ds = Get-vRA-FabricvSphereDatastoresFilter -filtertype "name" -filtervalue $VCDatastore | where {$_.CloudAccountIds -ne $caid}
            $dsid =  $ds.id            
            $defaultitem = "true"
            $ds_id = "'"+ $dsid+ "'"
            $vra_payload = "{
              name: $profilename, 
              defaultItem: $defaultitem,
              diskTargetProperties:{
                  datastoreId: $ds_id
              },              
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA vSphere Storage Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-StorageProfile-AWS ######################### 

function New-vRA-StorageProfile-AWS
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          07/07/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Storage Profile for AWS datastore in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Storage Profile for AWS datastore in a particular Org 
    .EXAMPLE
        New-vRA-StorageProfile-AWS -ProfileName "ProfileName" -CloudAccountName "vRA Cloud Account Name" -DeviceType "EBS" -VolumeType "gp2" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Profile Name
      [ValidateNotNullOrEmpty()]
      [string]$ProfileName,           
      # vRA Cloud Account Name
    [Parameter (Mandatory=$true)]      
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$true)]
      # AWS Device Type
      [ValidateNotNullOrEmpty()]
      [string]$DeviceType,
    [Parameter (Mandatory=$true)]
      # AWS Volume Type
      [ValidateNotNullOrEmpty()]
      [string]$VolumeType                  
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/storage-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            

            $ca = Get-vRA-CloudAccounts | where{$_.name -match $CloudAccountName}
            $caid =  $ca.id
            $region = Get-vRA-Regions | where{$_.cloudAccountId -match $caid}
            $regionid = $region.id           
            $defaultitem = "true"
            $vra_payload = "{
              name: $profilename, 
              defaultItem: $defaultitem,
              diskProperties:{
                  deviceType: $DeviceType,
                  volumeType: $VolumeType    
              },                              
              regionId: $regionid
              }" 
            $vra_body = $vra_payload
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA vSphere Storage Profile"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-FlavorProfiles ######################### 

function Get-vRA-FlavorProfiles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA FlavorProfiles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA FlavorProfiles in a particular Org 
    .EXAMPLE
        Get-vRA-FlavorProfiles
    .EXAMPLE
        Get-vRA-FlavorProfiles | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/flavor-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Flavor Profiles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-Flavors ######################### 

function Get-vRA-Flavors
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Flavors in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Flavors in a particular Org 
    .EXAMPLE
        Get-vRA-Flavors
    .EXAMPLE
        Get-vRA-Flavors | where{$_.externalRegionId -match "us-east-1"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/flavors"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Flavors"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-ImageProfiles ######################### 

function Get-vRA-ImageProfiles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Image Profiles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Image Profiles in a particular Org 
    .EXAMPLE
        Get-vRA-ImageProfiles
    .EXAMPLE
        Get-vRA-ImageProfiles | where{$_.externalRegionId -match "us-east-1"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/image-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Image Profiles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-FabricImages ######################### 

function Get-vRA-FabricImages
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric Images in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric Images in a particular Org 
    .EXAMPLE
        Get-vRA-FabricImages
    .EXAMPLE
        Get-vRA-FabricImages | where{$_.externalRegionId -match "us-east-1"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=2000      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?`$top="+ $Size            
            $vra_uri = "/iaas/api/fabric-images"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam 
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric Images"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-FabricImagesFilter ######################### 

function Get-vRA-FabricImagesFilter
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric Images using filters in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric Images using filters in a particular Org 
    .EXAMPLE
        Get-vRA-FabricImagesFilter
    .EXAMPLE
        Get-vRA-FabricImagesFilter -filtertype "name" -filtervalue "ImageName"        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtertype="name", 
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtervalue="*"            
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $filter= $filtertype+ " eq '"+ $filtervalue+ "'"
            $filterparam = "?`$filter="+ $filter            
            $vra_uri = "/iaas/api/fabric-images"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $filterparam
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric Images"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-FabricNetworks ######################### 

function Get-vRA-FabricNetworks
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric Networks in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric Networks in a particular Org 
    .EXAMPLE
        Get-vRA-FabricNetworks    
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=2000       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?`$top="+ $Size              
            $vra_uri = "/iaas/api/fabric-networks"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam 
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric Networks"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-FabricNetworksFilter ######################### 

function Get-vRA-FabricNetworksFilter
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric Networks using filters in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric Networks using filters in a particular Org 
    .EXAMPLE
        Get-vRA-FabricNetworksFilter
    .EXAMPLE
        Get-vRA-FabricNetworksFilter -filtertype "name" -filtervalue "Network Name"               
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtertype="name", 
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtervalue="*"        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $filter= $filtertype+ " eq '"+ $filtervalue+ "'"
            $filterparam = "?`$filter="+ $filter              
            $vra_uri = "/iaas/api/fabric-networks"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $filterparam 
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric Networks"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-FabricvSphereDatastores ######################### 

function Get-vRA-FabricvSphereDatastores
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric vSphere Datastores in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric vSphere Datastores in a particular Org 
    .EXAMPLE
        Get-vRA-FabricvSphereDatastores
    .EXAMPLE
        Get-vRA-FabricvSphereDatastores | where {$_.type -match "vsan"}         
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/fabric-vsphere-datastores"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric vSphere Datastores"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-FabricvSphereDatastoresFilter ######################### 

function Get-vRA-FabricvSphereDatastoresFilter
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric vSphere Datastores using filters in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric vSphere Datastores using filters in a particular Org 
    .EXAMPLE
        Get-vRA-FabricvSphereDatastoresFilter
    .EXAMPLE
        Get-vRA-FabricvSphereDatastoresFilter -filtertype name -filtervalue "vsanDatastore_cluster02"        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtertype="name", 
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filtervalue="*"      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $filter= $filtertype+ " eq '"+ $filtervalue+ "'"
            $filterparam = "?`$filter="+ $filter      
            $vra_uri = "/iaas/api/fabric-vsphere-datastores"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $filterparam
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric vSphere Datastores"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-FabricFlavors ######################### 

function Get-vRA-FabricFlavors
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric Flavors in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric Flavors in a particular Org 
    .EXAMPLE
        Get-vRA-FabricFlavors
    .EXAMPLE
        Get-vRA-FabricFlavors | where {$_.name -match "Test"}         
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/fabric-flavors"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric Flavors"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-FabricvSphereStoragePolicies ######################### 

function Get-vRA-FabricvSphereStoragePolicies
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Fabric vSphere Storage Policies in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Fabric vSphere Storage Policies in a particular Org 
    .EXAMPLE
        Get-vRA-FabricvSphereStoragePolicies
    .EXAMPLE
        Get-vRA-FabricvSphereStoragePolicies | where {$_.name -match "Test"}         
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/fabric-vsphere-storage-policies"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Fabric vSphere Storage Policies"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Images ######################### 

function Get-vRA-Images
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Images in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Images in a particular Org 
    .EXAMPLE
        Get-vRA-Images
    .EXAMPLE
        Get-vRA-Images | where{$_.mapping -match "centos"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/images"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Images"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Networks ######################### 

function Get-vRA-Networks
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Networks in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Networks in a particular Org 
    .EXAMPLE
        Get-vRA-Networks
    .EXAMPLE
        Get-vRA-Networks | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/networks"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Networks"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-NetworkDomains ######################### 

function Get-vRA-NetworkDomains
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Network Domains in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Network Domains in a particular Org 
    .EXAMPLE
        Get-vRA-NetworkDomains
    .EXAMPLE
        Get-vRA-NetworkDomains | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/network-domains"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Network Domains"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-SecurityGroups ######################### 

function Get-vRA-SecurityGroups
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Security Groups in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Security Groups in a particular Org 
    .EXAMPLE
        Get-vRA-SecurityGroups
    .EXAMPLE
        Get-vRA-SecurityGroups | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/security-groups"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Security Groups"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-NetworkProfiles ######################### 

function Get-vRA-NetworkProfiles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Network Profiles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Network Profiles in a particular Org 
    .EXAMPLE
        Get-vRA-NetworkProfiles
    .EXAMPLE
        Get-vRA-NetworkProfiles | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/network-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Network Profiles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-StorageProfiles ######################### 

function Get-vRA-StorageProfiles
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Storage Profiles in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Storage Profiles in a particular Org 
    .EXAMPLE
        Get-vRA-StorageProfiles
    .EXAMPLE
        Get-vRA-StorageProfiles | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/storage-profiles"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Storage Profiles"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Projects ######################### 

function Get-vRA-Projects
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Projects in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Projects in a particular Org 
    .EXAMPLE
        Get-vRA-Projects
    .EXAMPLE
        Get-vRA-Projects | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/projects"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Projects"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### New-vRA-Project ######################### 

function New-vRA-Project
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          10/06/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Project in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Project in a particular Org 
    .EXAMPLE
        New-vRA-Project -ProjectName "ProjectName" -ProjectDescription "ProjectDescription" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,
    [Parameter (Mandatory=$true)]
      # vRA Project Description
      [ValidateNotNullOrEmpty()]
      [string]$ProjectDescription      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/projects"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }        
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vra_payload = @{"name"=$projectname;
             "description"=$projectdescription;
            }            
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### New-vRA-Project-With-Zone ######################### 

function New-vRA-Project-With-Zone
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new vRA Project and adds the specified Zone in a particular Org 
    .DESCRIPTION
        This cmdlet creates new vRA Project and adds the specified Zone in a particular Org 
    .EXAMPLE
        New-vRA-Project-With-Zone -ProjectName "ProjectName" -Zonename "Zone Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # vRA Zone Name
      [ValidateNotNullOrEmpty()]
      [string]$Zonename        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/projects"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $zone = Get-vRA-CloudZones | where{$_.name -match $zonename} | Select id
            $zoneid =  $zone.id
            $description = "Project created via PowervRACloud"
            $zoneAssignmentConfigurations = @()
            $zoneAssignmentConfigurations += [pscustomobject]@{
                'priority'='0';
                'maxNumberInstances'='0';
                'zoneId'="$zoneid"
            }            
            $vra_payload = @{name=$ProjectName;description=$description;zoneAssignmentConfigurations=$zoneAssignmentConfigurations
            }          
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method POST -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Update-vRA-Project-ZoneConfig ######################### 

function Update-vRA-Project-ZoneConfig
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Updates vRA Project Zone Configuration in a particular Org 
    .DESCRIPTION
        This cmdlet updates vRA Project Zone Configuration in a particular Org 
    .EXAMPLE
        Update-vRA-Project-ZoneConfig -ProjectName "ProjectName" -CloudAccountName "CloudAccount Name" 
    .EXAMPLE
        Update-vRA-Project-ZoneConfig -ProjectName "ProjectName" -CloudAccountName "CloudAccount Name" -MemoryLimitMB 2048 -maxNumberInstances 20 -Priority 1      
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # vRA Zone Name
      [ValidateNotNullOrEmpty()]
      [string]$CloudAccountName,
    [Parameter (Mandatory=$false)]
      # MemoryLimit
      [ValidateNotNullOrEmpty()]
      [Int]$MemoryLimitMB=0,
    [Parameter (Mandatory=$false)]
      # Max Number of Instances
      [ValidateNotNullOrEmpty()]
      [Int]$maxNumberInstances=0,
    [Parameter (Mandatory=$false)]
      # Priority
      [ValidateNotNullOrEmpty()]
      [Int]$Priority=0                             
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -eq $projectname} | Select id
            $zone = Get-vRA-CloudZones | where{$_.name -match $CloudAccountName} | Select id
            $projectid = $project.id
            $zoneid =  $zone.id

            $vra_uri = "/iaas/api/projects/"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $projectid

            $zoneAssignmentConfigurations = @()
            $zoneAssignmentConfigurations += [pscustomobject]@{
                'priority'="$Priority";
                'memoryLimitMB'="$MemoryLimitMB";
                'maxNumberInstances'="$maxNumberInstances";
                'zoneId'="$zoneid"
            }            
            $vra_payload = @{name=$ProjectName;zoneAssignmentConfigurations=$zoneAssignmentConfigurations
            }          
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method PATCH -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error Updating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Add-vRA-Project-Member ######################### 

function Add-vRA-Project-Member
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Adds vRA Project Member in a particular Org 
    .DESCRIPTION
        This cmdlet adds vRA Project Member in a particular Org 
    .EXAMPLE
        Add-vRA-Project-Member -ProjectName "ProjectName" -Member "email@vmware.com"   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # Member
      [ValidateNotNullOrEmpty()]
      [String]$Member                        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -eq $projectname} | Select id
            $projectid = $project.id

            $vra_uri = "/iaas/api/projects/"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $projectid

            $vra_payload = "{
              members:[{
                  email: $member
              }]
              }"
            $vra_body = $vra_payload          
            $response = Invoke-RestMethod -Uri $vra_url -Method PATCH -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Add-vRA-Project-Administrator ######################### 

function Add-vRA-Project-Administrator
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Adds vRA Project Administrator in a particular Org 
    .DESCRIPTION
        This cmdlet adds vRA Project Administrator in a particular Org 
    .EXAMPLE
        Add-vRA-Project-Administrator -ProjectName "ProjectName" -Administrator "email@vmware.com"   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # Member
      [ValidateNotNullOrEmpty()]
      [String]$Administrator                        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -eq $projectname} | Select id
            $projectid = $project.id

            $vra_uri = "/iaas/api/projects/"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $projectid

            $vra_payload = "{
              administrators:[{
                  email: $Administrator
              }]
              }"
            $vra_body = $vra_payload          
            $response = Invoke-RestMethod -Uri $vra_url -Method PATCH -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Remove-vRA-Project-Member ######################### 

function Remove-vRA-Project-Member
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Removes vRA Project Member in a particular Org 
    .DESCRIPTION
        This cmdlet removes vRA Project Member in a particular Org 
    .EXAMPLE
        Remove-vRA-Project-Member -ProjectName "ProjectName" -User "email@vmware.com"   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # Member
      [ValidateNotNullOrEmpty()]
      [String]$User                        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -eq $projectname}
            $projectid = $project.id
            $originalprojectmembers = $project.members
            $newprojectmembers = $originalprojectmembers | Where-Object { $_.email –ne $User }
            $jsonpayload = ConvertTo-Json @($newprojectmembers)
            $vra_uri = "/iaas/api/projects/"
            $url = $Connection.Server
            $type = "User"
            $vra_url = "https://"+ $url+ $vra_uri+ $projectid

            $vra_payload = "{
              members: $jsonpayload
              }"
            $vra_body = $vra_payload        
            $response = Invoke-RestMethod -Uri $vra_url -Method PATCH -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Remove-vRA-Project-Administrator ######################### 

function Remove-vRA-Project-Administrator
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Removes vRA Project Administrator in a particular Org 
    .DESCRIPTION
        This cmdlet removes vRA Project Administrator in a particular Org 
    .EXAMPLE
        Remove-vRA-Project-Administrator -ProjectName "ProjectName" -User "email@vmware.com"   
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # Member
      [ValidateNotNullOrEmpty()]
      [String]$User                        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }             
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -eq $projectname}
            $projectid = $project.id
            $originalprojectadministrators = $project.administrators
            $newprojectadministrators = $originalprojectadministrators | Where-Object { $_.email -ne $User }
            $jsonpayload = ConvertTo-Json @($newprojectadministrators)
            $vra_uri = "/iaas/api/projects/"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $projectid
            $vra_payload = "{
              administrators: $jsonpayload
              }"
            $vra_body = $vra_payload       
            $response = Invoke-RestMethod -Uri $vra_url -Method PATCH -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Project"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-CloudZones ######################### 

function Get-vRA-CloudZones
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Cloud Zones in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Cloud Zones in a particular Org 
    .EXAMPLE
        Get-vRA-CloudZones
    .EXAMPLE
        Get-vRA-CloudZones | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/zones"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Cloud Zones"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Requests #########################

function Get-vRA-Requests
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Requests in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Requests in a particular Org 
    .EXAMPLE
        Get-vRA-Requests
    .EXAMPLE
        Get-vRA-Requests | where{$_.name -match "Provisioning"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/iaas/api/request-tracker"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Requests"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Tags ######################### 

function Get-vRA-Tags
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.2
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Tags in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Tags in a particular Org 
    .EXAMPLE
        Get-vRA-Tags      
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=2000      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?`$top="+ $Size 
            $vra_uri = "/iaas/api/tags"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam 
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Tags"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### New-vRA-Blueprint ######################### 

function New-vRA-Blueprint
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Creates new simple vRA Blueprint with flavor and Image in a particular Org 
    .DESCRIPTION
        This cmdlet creates new simple vRA Blueprint with flavor and Image in a particular Org 
    .EXAMPLE
        New-vRA-Blueprint -ProjectName "ProjectName" -BlueprintName "BlueprintName" -FlavorName "small" -ImageName "ubuntu"  
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Project Name
      [ValidateNotNullOrEmpty()]
      [string]$ProjectName,       
    [Parameter (Mandatory=$true)]
      # vRA Blueprint Name
      [ValidateNotNullOrEmpty()]
      [string]$BlueprintName,
    [Parameter (Mandatory=$true)]
      # vRA Flavor Name
      [ValidateNotNullOrEmpty()]
      [string]$FlavorName,
    [Parameter (Mandatory=$true)]
      # vRA Image Mapping Name
      [ValidateNotNullOrEmpty()]
      [string]$ImageName                       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/blueprint/api/blueprints"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $project = Get-vRA-Projects | where{$_.name -match $projectname} | Select id
            $projectid = $project.id
            $scope = "false"
            
            $content = "formatVersion: 1`nresources:`n  Cloud_Machine_1:`n    type: Cloud.Machine`n    metadata:`n      layoutPosition:`n        - 0`n        - 1`n    name: CloudMachine`n    properties:`n      image: "+ $ImageName+ "`n      flavor: "+ $FlavorName+ "`n       "
            $vra_payload = @{"name"=$BlueprintName
             "projectId"=$projectid
             "content"=$content
            }                             
            $vra_body = $vra_payload | ConvertTo-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method POST -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error creating vRA Blueprint"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-Blueprints ######################### 

function Get-vRA-Blueprints
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Blueprints in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Blueprints in a particular Org 
    .EXAMPLE
        Get-vRA-Blueprints
    .EXAMPLE
        Get-vRA-Blueprints | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=200        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?size="+ $Size            
            $vra_uri = "/blueprint/api/blueprints"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content           
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Blueprints"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-Blueprint Details #########################

function Get-vRA-BlueprintDetails
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRA Blueprint Details in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRA Blueprint Details in a particular Org 
    .EXAMPLE
        Get-vRA-BlueprintDetails -id "Blueprint ID"
    .EXAMPLE
        Get-vRA-BlueprintDetails -id "Blueprint ID" | Select content | Format-list     
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Blueprint ID
      [ValidateNotNullOrEmpty()]
      [string]$id      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/blueprint/api/blueprints/"+ $id 
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Blueprint Details"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-BlueprintInputSchema #########################

function Get-vRA-BlueprintInputSchema
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRA Blueprint Input Schema in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRA Blueprint Input Schema in a particular Org 
    .EXAMPLE
        Get-vRA-BlueprintInputSchema -BlueprintName "Blueprint Name"    
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Blueprint ID
      [ValidateNotNullOrEmpty()]
      [string]$BlueprintName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $bp = Get-vRA-Blueprints | where{$_.name -eq $BlueprintName}
            $bpid = $bp.id
            $vra_uri = "/blueprint/api/blueprints/"+ $bpid+ "/inputs-schema"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }              
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Blueprint Input Schemas"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-BlueprintVersions #########################

function Get-vRA-BlueprintVersions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRA Blueprint Version Details in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRA Blueprint Version Details in a particular Org 
    .EXAMPLE
        Get-vRA-BlueprintVersions -BlueprintName "Blueprint Name"    
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Blueprint ID
      [ValidateNotNullOrEmpty()]
      [string]$BlueprintName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $bp = Get-vRA-Blueprints | where{$_.name -eq $BlueprintName}
            $bpid = $bp.id
            $vra_uri = "/blueprint/api/blueprints/"+ $bpid+ "/versions"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }             
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Blueprint Versions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Deploy-vRA-Blueprint ######################### 

function Deploy-vRA-Blueprint
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Provisions new vRA Deployment from a Blueprint with No Inputs in a particular Org 
    .DESCRIPTION
        This cmdlet provisions new vRA Project Deployment from a Blueprint with No Inputs in a particular Org 
    .EXAMPLE
        Deploy-vRA-Blueprint -BlueprintName "BlueprintName" -DeploymentName "Deployment Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Blueprint Name
      [ValidateNotNullOrEmpty()]
      [string]$BlueprintName,       
    [Parameter (Mandatory=$true)]
      # vRA Deployment Name
      [ValidateNotNullOrEmpty()]
      [string]$DeploymentName        
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/blueprint/api/blueprint-requests"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $blueprint = Get-vRA-Blueprints | where{$_.name -match $BlueprintName} | Select id
            $project = Get-vRA-Blueprints | where{$_.name -match $BlueprintName} | Select projectId
            $blueprintid = $blueprint.id
            $projectid = $project.projectId
            $vra_payload = @()
            $vra_payload += [pscustomobject]@{
                'blueprintId'= $blueprintid;
                'deploymentName'= $DeploymentName;
                'destroy'= 'false';
                'plan'= 'false';
                'projectId'= $projectid
            }     
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method POST -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                      
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error provisioning from vRA Blueprint"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-Deployments #########################

function Get-vRA-Deployments
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.3
    Date:          12/23/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Deployments in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Deployments in a particular Org 
    .EXAMPLE
        Get-vRA-Deployments
    .EXAMPLE
        Get-vRA-Deployments | where{$_.name -match "Test"}        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection 
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $deployments = Get-vRA-DeploymentFilters -filterId "projects" | Sort-Object Count -Descending
            $projects = $deployments | select id
            ForEach ($project in $projects)
            {
              $projectid = $project.id
              $sizeparam = "?Size="+ $Size
              $vra_uri = "/deployment/api/deployments?size=200&projects="+ $projectid+ "&expand=project%2Cresources"
              $url = $Connection.Server
              $vra_url = "https://"+ $url+ $vra_uri
              $cspauthtoken= $Connection.CSPToken
              if ($url -ne "api.mgmt.cloud.vmware.com")
              {
                $SkipSSLCheck = $True
              }
              else
              {
                $SkipSSLCheck = $False
              }            
              $vra_headers = @{"Accept"="application/json";
              "Content-Type"="application/json";
              "Authorization"="Bearer $cspauthtoken"; 
              }
              $vra_payload = @()
              $vra_payload += [pscustomobject]@{
                  'name'= $deploymentname
              }     
              $vra_body = $vra_payload | Convertto-Json            
              $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
              $response.content
            }          
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployments"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

  ######################### Get-vRA-SingleDeployment #########################

  function Get-vRA-SingleDeployment
  {

  <#
      .NOTES
      ==============================================================================================================================================
      Created by:    Munishpal Makhija                                                                                                              
      Version:       1.0
      Date:          12/24/2020
      Organization:  VMware
      Blog:          http://bit.ly/MyvBl0g
      ==============================================================================================================================================

      .SYNOPSIS
          Returns single vRA Deployment in a particular Org 
      .DESCRIPTION
          This cmdlet retrieves single vRA Deploymentin a particular Org 
      .EXAMPLE
          Get-vRA-SingleDeployment -DeploymentName "DeploymentName"      
  #>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$True)]
        # Deployment Name
        [ValidateNotNullOrEmpty()]
        [String]$DeploymentName     
    )
    If (-Not $global:defaultvRAConnection) 
      { 
        Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
      } 
    else
      {
        try {
              $vra_uri = "/deployment/api/deployments?name="+ $DeploymentName+ "&expand=project%2Cresources"
              $url = $Connection.Server
              $vra_url = "https://"+ $url+ $vra_uri
              $cspauthtoken= $Connection.CSPToken
              if ($url -ne "api.mgmt.cloud.vmware.com")
              {
                $SkipSSLCheck = $True
              }
              else
              {
                $SkipSSLCheck = $False
              }            
              $vra_headers = @{"Accept"="application/json";
              "Content-Type"="application/json";
              "Authorization"="Bearer $cspauthtoken"; 
              }
              $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
              $response.content          
            } catch {
              if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                  Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                  break
              } 
              else {
                  Write-Error "Error in retrieving vRA Deployments"
                  Write-Error "`n($_.Exception.Message)`n"
                  break
              }
      }
  }}


######################### Get-vRA-DeploymentFilters #########################

function Get-vRA-DeploymentFilters
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Deployments using Filter IDs in context of given User in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Deployments using Filter IDs in context of given User in a particular Org 
    .EXAMPLE
        Get-vRA-DeploymentFilters
    .EXAMPLE
        Get-vRA-DeploymentFilters -filterId "projects"                
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$False)]
      # Filter
      [ValidateNotNullOrEmpty()]
      [String]$filterId="projects",       
    [Parameter (Mandatory=$False)]
      # Response Page Size
      [ValidateNotNullOrEmpty()]
      [Int]$Size=200       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $sizeparam = "?size="+ $Size
            $vra_uri = "/deployment/api/deployments/filters/"+ $filterId
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.content          
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployments"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Get-vRA-DeploymentFilterTypes #########################

function Get-vRA-DeploymentFilterTypes
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns all vRA Deployment Filter Types in context of given User in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves all vRA Deployment Filter Types in context of given User in a particular Org 
    .EXAMPLE
        Get-vRA-DeploymentFilterTypes      
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection    
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $vra_uri = "/deployment/api/deployments/filters"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response.filters | select name,id          
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployments"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}


######################### Remove-vRA-Deployment ######################### 

function Remove-vRA-Deployment
{
<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/02/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Deletes vRA Deployment in a particular Org 
    .DESCRIPTION
        This cmdlet provisions destroys new vRA Deployment in a particular Org 
    .EXAMPLE
        Remove-vRA-Deployment -DeploymentName "Deployment Name" 
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Deployment Name
      [ValidateNotNullOrEmpty()]
      [string]$DeploymentName       
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
            $deploymentid = $deployment.id      
            $vra_uri = "/deployment/api/deployments/"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri+ $deploymentid+ "/requests"
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $vra_payload = @()
            $vra_payload += [pscustomobject]@{
                'actionId'= 'Deployment.Delete';
                'reason'= 'Destroy'
            }              
            $vra_body = $vra_payload | Convertto-Json
            $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response                 
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error deleting of vRA Deployment"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}



######################### Get-vRA-DeploymentResources #########################

function Get-vRA-DeploymentResources
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns resources associated with a vRA Deployment in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves resources associated with a vRA Deployment in a particular Org 
    .EXAMPLE
        Get-vRA-DeploymentResources -DeploymentName "DeploymentName"        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Deployment Name
      [ValidateNotNullOrEmpty()]
      [string]$DeploymentName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
            $depId  = $deployment.id
            $vra_uri = "/deployment/api/deployments/"+ $depId+ "/resources"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response.content        
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployment Resources"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

######################### Get-vRA-DeploymentActions #########################

function Get-vRA-DeploymentActions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.1
    Date:          04/01/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns available actions associated with a vRA Deployment in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves available actions associated with a vRA Deployment in a particular Org 
    .EXAMPLE
        Get-vRA-DeploymentActions -DeploymentName "DeploymentName"        
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$true)]
      # vRA Deployment Name
      [ValidateNotNullOrEmpty()]
      [string]$DeploymentName      
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
            $depId  = $deployment.id
            $vra_uri = "/deployment/api/deployments/"+ $depId+ "/actions"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck
            $response        
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployment Actions"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

  ######################### Get-vRA-DeploymentActionID #########################

  function Get-vRA-DeploymentActionID
  {

  <#
      .NOTES
      ==============================================================================================================================================
      Created by:    Munishpal Makhija                                                                                                              
      Version:       1.0
      Date:          12/23/2020
      Organization:  VMware
      Blog:          http://bit.ly/MyvBl0g
      ==============================================================================================================================================

      .SYNOPSIS
          Returns vRA Deployment Actions in a particular Org 
      .DESCRIPTION
          This cmdlet retrieves vRA Deployment Actions in a particular Org 
      .EXAMPLE
          Get-vRA-DeploymentActionID -DeploymentName "DeploymentName" -ActionID "Deployment.ChangeLease"
      .EXAMPLE
          Get-vRA-DeploymentActionID | where{$_.name -eq "DeploymentName"}        
  #>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$True)]
        # Deployment Name
        [ValidateNotNullOrEmpty()]
        [String]$DeploymentName,
      [Parameter (Mandatory=$True)]
        # Deployment Action ID
        [ValidateNotNullOrEmpty()]
        [String]$ActionID,              
      [Parameter (Mandatory=$False)]
        # Response Page Size
        [ValidateNotNullOrEmpty()]
        [Int]$Size=200       
    )
    If (-Not $global:defaultvRAConnection) 
      { 
        Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
      } 
    else
      {
        try {
              $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
              $deploymentid = $deployment.id
              $sizeparam = "?size="+ $Size
              $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/actions/"+ $ActionID
              $url = $Connection.Server
              $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
              $cspauthtoken= $Connection.CSPToken
              if ($url -ne "api.mgmt.cloud.vmware.com")
              {
                $SkipSSLCheck = $True
              }
              else
              {
                $SkipSSLCheck = $False
              }            
              $vra_headers = @{"Accept"="application/json";
              "Content-Type"="application/json";
              "Authorization"="Bearer $cspauthtoken"; 
              }
              $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
              $response          
            } catch {
              if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                  Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                  break
              } 
              else {
                  Write-Error "Error in retrieving vRA Deployments"
                  Write-Error "`n($_.Exception.Message)`n"
                  break
              }
      }
  }}

  ######################### Get-vRA-DeploymentResourceActionID #########################

  function Get-vRA-DeploymentResourceActionID
  {

  <#
      .NOTES
      ==============================================================================================================================================
      Created by:    Munishpal Makhija                                                                                                              
      Version:       1.0
      Date:          12/23/2020
      Organization:  VMware
      Blog:          http://bit.ly/MyvBl0g
      ==============================================================================================================================================

      .SYNOPSIS
          Returns vRA Deployment Actions in a particular Org 
      .DESCRIPTION
          This cmdlet retrieves vRA Deployment Actions in a particular Org 
      .EXAMPLE
          Get-vRA-DeploymentResourceActionID -DeploymentName "MMTest01" -ResourceName "ResourceName" -ActionID "Cloud.vSphere.Machine.Snapshot.Delete"     
  #>
      param (
      [Parameter (Mandatory=$False)]
        # vRA Connection object
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$Connection=$defaultvRAConnection,
      [Parameter (Mandatory=$True)]
        # Deployment Name
        [ValidateNotNullOrEmpty()]
        [String]$DeploymentName,
      [Parameter (Mandatory=$True)]
        # Deployment Resource Name
        [ValidateNotNullOrEmpty()]
        [String]$ResourceName,        
      [Parameter (Mandatory=$True)]
        # Deployment Action ID
        [ValidateNotNullOrEmpty()]
        [String]$ActionID      
    )
    If (-Not $global:defaultvRAConnection) 
      { 
        Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
      } 
    else
      {
        try {
              $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
              $deploymentid = $deployment.id
              $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
              $resourceid = $resource.id
              $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/actions/"+ $ActionID
              $url = $Connection.Server
              $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
              $cspauthtoken= $Connection.CSPToken
              if ($url -ne "api.mgmt.cloud.vmware.com")
              {
                $SkipSSLCheck = $True
              }
              else
              {
                $SkipSSLCheck = $False
              }            
              $vra_headers = @{"Accept"="application/json";
              "Content-Type"="application/json";
              "Authorization"="Bearer $cspauthtoken"; 
              }
              $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
              $response          
            } catch {
              if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                  Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                  break
              } 
              else {
                  Write-Error "Error in retrieving vRA Deployments"
                  Write-Error "`n($_.Exception.Message)`n"
                  break
              }
      }
  }}

######################### Get-vRA-DeploymentResourceActions #########################

function Get-vRA-DeploymentResourceActions
{

<#
    .NOTES
    ==============================================================================================================================================
    Created by:    Munishpal Makhija                                                                                                              
    Version:       1.0
    Date:          12/23/2020
    Organization:  VMware
    Blog:          http://bit.ly/MyvBl0g
    ==============================================================================================================================================

    .SYNOPSIS
        Returns vRA Deployment Resource Actions in a particular Org 
    .DESCRIPTION
        This cmdlet retrieves vRA Deployment Resource Actions in a particular Org 
    .EXAMPLE
        Get-vRA-DeploymentResourceActions -DeploymentName "DeploymentName" -ResourceName "ResourceName"
#>
    param (
    [Parameter (Mandatory=$False)]
      # vRA Connection object
      [ValidateNotNullOrEmpty()]
      [PSCustomObject]$Connection=$defaultvRAConnection,
    [Parameter (Mandatory=$True)]
      # Deployment Name
      [ValidateNotNullOrEmpty()]
      [String]$DeploymentName,
    [Parameter (Mandatory=$True)]
      # Deployment Resource   Name
      [ValidateNotNullOrEmpty()]
      [String]$ResourceName           
  )
  If (-Not $global:defaultvRAConnection) 
    { 
      Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
    } 
  else
    {
      try {
            $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
            $deploymentid = $deployment.id
            $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
            $resourceid = $resource.id
            $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/actions"
            $url = $Connection.Server
            $vra_url = "https://"+ $url+ $vra_uri
            $cspauthtoken= $Connection.CSPToken
            if ($url -ne "api.mgmt.cloud.vmware.com")
            {
              $SkipSSLCheck = $True
            }
            else
            {
              $SkipSSLCheck = $False
            }            
            $vra_headers = @{"Accept"="application/json";
            "Content-Type"="application/json";
            "Authorization"="Bearer $cspauthtoken"; 
            }
            $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
            $response          
          } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                break
            } 
            else {
                Write-Error "Error in retrieving vRA Deployments"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
    }
}}

    ######################### Change-vRA-DeploymentLease #########################

    function Change-vRA-DeploymentLease
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Modifies vRA Deployment Lease in a particular Org 
        .DESCRIPTION
            This cmdlet modifies vRA Deployment lease in a particular Org 
        .EXAMPLE
            Change-vRA-DeploymentLease -DeploymentName "DeploymentName" -LeaseExpiryDate "2021-01-06T19:13:00.000Z"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Lease Expiry Date (yyyy-mm-dd-Thh:mm:zz)
          [ValidateNotNullOrEmpty()]
          [String]$LeaseExpiryDate      
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Deployment.ChangeLease"
                $inputs = @{"Lease Expiration Date"=$LeaseExpiryDate}
                $vra_payload = @{"actionId"=$action;
                  "inputs"=$inputs;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


######################### Change-vRA-DeploymentOwner #########################

    function Change-vRA-DeploymentOwner
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/24/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Modifies vRA Deployment Owner in a particular Org 
        .DESCRIPTION
            This cmdlet modifies vRA Deployment owner in a particular Org 
        .EXAMPLE
            Change-vRA-DeploymentOwner -DeploymentName "DeploymentName" -OwnerEmail "abc@abc.com"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Owner Email Address
          [ValidateNotNullOrEmpty()]
          [String]$OwnerEmail      
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Deployment.ChangeOwner"
                $inputs = @{"New Owner"=$OwnerEmail}
                $vra_payload = @{"actionId"=$action;
                  "inputs"=$inputs;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


    ######################### Create-vRA-DeploymentResourceSnapshot #########################

    function Create-vRA-DeploymentResourceSnapshot
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Creates Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org 
        .DESCRIPTION
            This cmdlet creates Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org 
        .EXAMPLE
            Create-vRA-DeploymentResourceSnapshot -DeploymentName "DeploymentName" -ResourceName "ResourceName" -SnapshotName "SnapshotName"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName,           
        [Parameter (Mandatory=$True)]
          # Lease Expiry Date (yyyy-mm-dd-Thh:mm:zz)
          [ValidateNotNullOrEmpty()]
          [String]$SnapshotName,
        [Parameter (Mandatory=$False)]
          # Lease Expiry Date (yyyy-mm-dd-Thh:mm:zz)
          [ValidateNotNullOrEmpty()]
          [String]$MemorySnapshot="false"               
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Snapshot.Create"
                $inputs = @{"name"=$SnapshotName;"memorySnapshot"=$MemorySnapshot}
                $vra_payload = @{"actionId"=$action;
                  "inputs"=$inputs;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### Delete-vRA-DeploymentResourceSnapshot #########################

    function Delete-vRA-DeploymentResourceSnapshot
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Removes Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet removes Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            Delete-vRA-DeploymentResourceSnapshot -DeploymentName "DeploymentName" -ResourceName "ResourceName" -SnapshotName "SnapshotName"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName,           
        [Parameter (Mandatory=$True)]
          # Lease Expiry Date (yyyy-mm-dd-Thh:mm:zz)
          [ValidateNotNullOrEmpty()]
          [String]$SnapshotName              
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Snapshot.Delete"
                $snap = Get-vRA-DeploymentResourceActionID -DeploymentName $DeploymentName -ResourceName $ResourceName -ActionID "Cloud.vSphere.Machine.Snapshot.Delete"
                $snapshot = $snap.schema.properties.SnapshotId.oneOf | where {$_.title -match $SnapshotName}
                $snapshotId = $snapshot.const 
                $inputs = @{"snapshotId"=$snapshotId}
                $vra_payload = @{"actionId"=$action;
                  "inputs"=$inputs;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### Revert-vRA-DeploymentResourceSnapshot #########################

    function Revert-vRA-DeploymentResourceSnapshot
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Revert to a Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet reverts to a Snapshot for vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            Revert-vRA-DeploymentResourceSnapshot -DeploymentName "DeploymentName" -ResourceName "ResourceName" -SnapshotName "SnapshotName"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName,           
        [Parameter (Mandatory=$True)]
          # Lease Expiry Date (yyyy-mm-dd-Thh:mm:zz)
          [ValidateNotNullOrEmpty()]
          [String]$SnapshotName              
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Snapshot.Revert"
                $snap = Get-vRA-DeploymentResourceActionID -DeploymentName $DeploymentName -ResourceName $ResourceName -ActionID "Cloud.vSphere.Machine.Snapshot.Revert"
                $snapshot = $snap.schema.properties.SnapshotId.oneOf | where {$_.title -match $SnapshotName}
                $snapshotId = $snapshot.const 
                $inputs = @{"snapshotId"=$snapshotId}
                $vra_payload = @{"actionId"=$action;
                  "inputs"=$inputs;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### PowerON-vRA-DeploymentResource #########################

    function PowerON-vRA-DeploymentResource
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Power ON vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet powers on a vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            PowerON-vRA-DeploymentResource -DeploymentName "DeploymentName" -ResourceName "ResourceName"     
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName            
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.PowerOn"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### PowerOff-vRA-DeploymentResource #########################

    function PowerOff-vRA-DeploymentResource
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Power Off vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet powers off a vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            PowerOff-vRA-DeploymentResource -DeploymentName "DeploymentName" -ResourceName "ResourceName"     
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName            
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.PowerOff"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### Reboot-vRA-DeploymentResource #########################

    function Reboot-vRA-DeploymentResource
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Rebboot vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet reboots a vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            Reboot-vRA-DeploymentResource -DeploymentName "DeploymentName" -ResourceName "ResourceName"     
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName            
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Reboot"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

    ######################### Reset-vRA-DeploymentResource #########################

    function Reset-vRA-DeploymentResource
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/23/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Reset vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet reset a vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            Reset-vRA-DeploymentResource -DeploymentName "DeploymentName" -ResourceName "ResourceName"     
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName            
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Reset"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


    ######################### Suspend-vRA-DeploymentResource #########################

    function Suspend-vRA-DeploymentResource
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/24/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Suspend vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .DESCRIPTION
            This cmdlet suspend a vRA Deployment Resource (vSphere Virtual Machine) in a particular Org  
        .EXAMPLE
            Suspend-vRA-DeploymentResource -DeploymentName "DeploymentName" -ResourceName "ResourceName"     
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Resource   Name
          [ValidateNotNullOrEmpty()]
          [String]$ResourceName            
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $resource = Get-vRA-DeploymentResources -DeploymentName $DeploymentName | where {$_.name -eq $ResourceName}
                $resourceid = $resource.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/resources/"+ $resourceid+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Cloud.vSphere.Machine.Suspend"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}


######################### PowerON-vRA-Deployment #########################

    function PowerON-vRA-Deployment
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/24/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Power ON vRA Deployment in a particular Org 
        .DESCRIPTION
            This cmdlet powers ON  vRA Deployment in a particular Org 
        .EXAMPLE
            PowerON-vRA-Deployment -DeploymentName "DeploymentName"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName     
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Deployment.PowerOn"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

######################### PowerOff-vRA-Deployment #########################

    function PowerOff-vRA-Deployment
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/24/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Power Off vRA Deployment in a particular Org 
        .DESCRIPTION
            This cmdlet powers Off  vRA Deployment in a particular Org 
        .EXAMPLE
            PowerOff-vRA-Deployment -DeploymentName "DeploymentName"      
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName     
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/requests"
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $action = "Deployment.PowerOff"
                $vra_payload = @{"actionId"=$action;
                }
                $vra_body = $vra_payload | Convertto-Json
                $response = Invoke-RestMethod -Uri $vra_url -Method Post -Headers $vra_headers -Body $vra_body  -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}

######################### Get-vRA-DeploymentRequests #########################

    function Get-vRA-DeploymentRequests
    {

    <#
        .NOTES
        ==============================================================================================================================================
        Created by:    Munishpal Makhija                                                                                                              
        Version:       1.0
        Date:          12/29/2020
        Organization:  VMware
        Blog:          http://bit.ly/MyvBl0g
        ==============================================================================================================================================

        .SYNOPSIS
            Get vRA Deployment Requests in a particular Org 
        .DESCRIPTION
            This cmdlet gets vRA Deployment Requests in a particular Org 
        .EXAMPLE
            Get-vRA-DeploymentRequests -DeploymentName "DeploymentName" -RequestID "Request ID"   
    #>
        param (
        [Parameter (Mandatory=$False)]
          # vRA Connection object
          [ValidateNotNullOrEmpty()]
          [PSCustomObject]$Connection=$defaultvRAConnection,
        [Parameter (Mandatory=$True)]
          # Deployment Name
          [ValidateNotNullOrEmpty()]
          [String]$DeploymentName,
        [Parameter (Mandatory=$True)]
          # Deployment Request ID
          [ValidateNotNullOrEmpty()]
          [String]$RequestID               
      )
      If (-Not $global:defaultvRAConnection) 
        { 
          Write-error "Not Connected to vRA Cloud, please use Connect-vRA-Cloud"
        } 
      else
        {
          try {
                $deployment = Get-vRA-SingleDeployment -DeploymentName $DeploymentName
                $deploymentid = $deployment.id
                $vra_uri = "/deployment/api/deployments/"+ $deployment.id+ "/requests/"+ $RequestID
                $url = $Connection.Server
                $vra_url = "https://"+ $url+ $vra_uri+ $sizeparam
                $cspauthtoken= $Connection.CSPToken
                if ($url -ne "api.mgmt.cloud.vmware.com")
                {
                  $SkipSSLCheck = $True
                }
                else
                {
                  $SkipSSLCheck = $False
                }            
                $vra_headers = @{"Accept"="application/json";
                "Content-Type"="application/json";
                "Authorization"="Bearer $cspauthtoken"; 
                }
                $response = Invoke-RestMethod -Uri $vra_url -Method Get -Headers $vra_headers -ErrorAction:Stop -SkipCertificateCheck:$SkipSSLCheck 
                $response          
              } catch {
                if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                    Write-Host -ForegroundColor Red "`nvRA Cloud Session is no longer valid, please re-run the Connect-vRA-Cloud cmdlet to retrieve a new token`n"
                    break
                } 
                else {
                    Write-Error "Error in retrieving vRA Deployments"
                    Write-Error "`n($_.Exception.Message)`n"
                    break
                }
        }
    }}
