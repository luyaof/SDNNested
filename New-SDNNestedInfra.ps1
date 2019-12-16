# --------------------------------------------------------------
#  Copyright © Microsoft Corporation.  All Rights Reserved.
#  Microsoft Corporation (or based on where you live, one of its affiliates) licenses this sample code for your internal testing purposes only.
#  Microsoft provides the following sample code AS IS without warranty of any kind. The sample code arenot supported under any Microsoft standard support program or services.
#  Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#  The entire risk arising out of the use or performance of the sample code remains with you.
#  In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the code be liable for any damages whatsoever
#  (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss)
#  arising out of the use of or inability to use the sample code, even if Microsoft has been advised of the possibility of such damages.
# ---------------------------------------------------------------
<#
.SYNOPSIS 
    Deploys and configures the Microsoft SDN infrastructure, 
    including creation of the network controller, Software Load Balancer MUX 
    and gateway VMs.  Then the VMs and Hyper-V hosts are configured to be 
    used by the Network Controller.  When this script completes the SDN 
    infrastructure is ready to be fully used for workload deployments.
.EXAMPLE
    .\SDNExpress.ps1 -ConfigurationDataFile .\MyConfig.psd1
    Reads in the configuration from a PSD1 file that contains a hash table 
    of settings data.
.EXAMPLE
    .\SDNExpress -ConfigurationData $MyConfigurationData
    Uses the hash table that is passed in as the configuration data.  This 
    parameter set is useful when programatically generating the 
    configuration data.
.EXAMPLE
    .\SDNExpress 
    Displays a user interface for interactively defining the configuraiton 
    data.  At the end you have the option to save as a configuration file
    before deploying.
.NOTES
    Prerequisites:
    * All Hyper-V hosts must have Hyper-V enabled and the Virtual Switch 
    already created.
    * All Hyper-V hosts must be joined to Active Directory.
    * The physical network must be preconfigured for the necessary subnets and 
    VLANs as defined in the configuration data.
    * The VHD specified in the configuration data must be reachable from the 
    computer where this script is run. 
#>


[CmdletBinding(DefaultParameterSetName = "NoParameters")]
param(
    [Parameter(Mandatory = $false, ParameterSetName = "ConfigurationFile")]
    [String] $ConfigurationDataFile = ".\utils\SDNNested-Deploy-Infra.psd1",
    [Switch] $RemoveExistingDeployment
)    

import-module .\SDNExpress\SDNExpressModule.psm1 -force
import-module .\utils\SDNNested-Module.psm1 -force

# Script version, should be matched with the config files
$ScriptVersion = "2.0"

# Remove the current SDN Nested Deployment
if($RemoveExistingDeployment)
{
    Remove-SDNNested
}


#Validating passed in config files
if ($psCmdlet.ParameterSetName -eq "ConfigurationFile") {
    Write-Host "Using configuration file $ConfigurationDataFile passed in by parameter."    
    $configdata = [hashtable] (iex (gc $ConfigurationDataFile | out-string))
}
elseif ($psCmdlet.ParameterSetName -eq "ConfigurationData") {
    Write-Host "Using configuration data object passed in by parameter."    
    $configdata = $configurationData 
}

if ($Configdata.ScriptVersion -ne $scriptversion) {
    Write-Host "Configuration file $ConfigurationDataFile version $($ConfigData.ScriptVersion) is not compatible with this version of SDN express."
    Write-Host "Please update your config file to match the version $scriptversion example."
    return
}

Write-Host -ForegroundColor Green "Config Data:"
$configdata
#Get credentials for provisionning
$DomainJoinCredential = GetCred $ConfigData.DomainJoinSecurePassword $DomainJoinCredential `
    "Enter credentials for joining VMs to the AD domain." $configdata.DomainJoinUserName
$LocalAdminCredential = GetCred $ConfigData.LocalAdminSecurePassword $LocalAdminCredential `
    "Enter the password for the local administrator of newly created VMs.  Username is ignored." "Administrator"

$DomainJoinPassword = $DomainJoinCredential.GetNetworkCredential().Password
$LocalAdminPassword = $LocalAdminCredential.GetNetworkCredential().Password

$DomainJoinUserNameDomain = $ConfigData.DomainJoinUserName.Split("\")[0]
$DomainJoinUserNameName = $ConfigData.DomainJoinUserName.Split("\")[1]
$LocalAdminDomainUserDomain = $ConfigData.LocalAdminDomainUser.Split("\")[0]
$LocalAdminDomainUserName = $ConfigData.LocalAdminDomainUser.Split("\")[1]


$password = $LocalAdminPassword | ConvertTo-SecureString -asPlainText -Force
$LocalAdminCredential = New-Object System.Management.Automation.PSCredential(".\administrator", $password)

if ( $null -eq $ConfigData.VMProcessorCount) { $ConfigData.VMProcessorCount = 2 }
if ( $null -eq $ConfigData.VMMemory) { $ConfigData.VMMemory = 4GB }

$paramsVM = @{
    'VMLocation'          = $ConfigData.VMLocation;
    'VMName'              = '';
    'VHDSrcPath'          = $ConfigData.VHDPath;
    'VHDName'             = $ConfigData.VHDFile;
    'VMMemory'            = $ConfigData.VMMemory;
    'VMProcessorCount'    = $ConfigData.VMProcessorCount;
    'SwitchName'          = $ConfigData.SwitchName;
    'NICs'                = @();
    'CredentialDomain'    = $DomainJoinUserNameDomain;
    'CredentialUserName'  = $DomainJoinUserNameName;
    'CredentialPassword'  = $DomainJoinPassword;
    'JoinDomain'          = $ConfigData.DomainFQDN;
    'LocalAdminPassword'  = $LocalAdminPassword;
    'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
    'DomainAdminUserName' = $LocalAdminDomainUserName;
    'IpGwAddr'            = $ConfigData.ManagementGateway;
    'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
    'KeyboardLayout'      = $configdata.KeyboardLayout;
    'Roles'               = @()
}

$paramsGW = @{
    'VMLocation'          = $ConfigData.VMLocation;
    'VMName'              = '';
    'VHDSrcPath'          = $ConfigData.VHDPath;
    'VHDName'             = $ConfigData.VHDFile;
    'VMMemory'            = $ConfigData.VMMemory;
    'VMProcessorCount'    = $ConfigData.VMProcessorCount;
    'SwitchName'          = $ConfigData.SwitchName;
    'NICs'                = @();
    'CredentialDomain'    = $DomainJoinUserNameDomain;
    'CredentialUserName'  = $DomainJoinUserNameName;
    'CredentialPassword'  = $DomainJoinPassword;
    'JoinDomain'          = $ConfigData.DomainFQDN;
    'LocalAdminPassword'  = $LocalAdminPassword;
    'DomainAdminDomain'   = $LocalAdminDomainUserDomain;
    'DomainAdminUserName' = $LocalAdminDomainUserName;
    'IpGwAddr'            = $ConfigData.ManagementGateway;
    'DnsIpAddr'           = $ConfigDanoteta.ManagementDNS;
    'DomainFQDN'          = $ConfigData.DomainFQDN;
    'ProductKey'          = $ConfigData.ProductKey;
}


Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- This script will deploy Hyper-V hosts and DC to host SDN stack based on the configuration file passed in $ConfigurationDataFile"
Write-Host "--- Checking if all prerequisites before deploying"
#Checking Hyper-V role
$HypvIsInstalled = Get-WindowsFeature Hyper-V
if ( $HypvIsInstalled.InstallState -eq "Installed" ) {
    Write-Host -ForegroundColor Green "Hypv role is $($HypvIsInstalled.installstate)"
}
else {
    throw "Hyper-V Feature needs to be installed in order to deploy SDN nested"    
}
#Checking VMSwitch
$vmswitch = get-vmswitch
if ( $null -eq $vmswitch ) {
    #throw "No virtual switch found on this host.  Please create the virtual switch before adding this host."
    $vmswitch = New-VMSwitch -Name $configdata.SwitchName -SwitchType Internal
}    

if ( $vmswitch.name | Where-Object { $_ -eq $configData.SwitchName } ) { 
    Write-Host -ForegroundColor Green "VMSwitch $($configData.SwitchName) found"
}
else {
    throw "No virtual switch $($params.SwitchName) found on this host.  Please create the virtual switch before adding this host."    
}
#Checking if DCs are defined
<#
if ( $null -eq $configdata.DCs ) {
    throw "No Domain Controller configuration defined."    
}

#Checking if DCs are defined
if ( $null -eq $configdata.HyperVHosts ) {
    throw "No Hyper-V Host configuration defined."    
}



#Checking connectivity to the SDN-HOST*
try {
    $MgmtVNIC = Get-VMNetworkAdapter -ManagementOS -SwitchName $configdata.SwitchName 
}
catch { }

if ($null -eq $MgmtVNIC) { $MgmtVNIC = Add-VMNetworkAdapter -ManagementOS -SwitchName $configdata.SwitchName }

$AzureVmSDNIp = ($configdata.AzureVmSDNMgmtIP).split("/")[0]
$AzureVmSDNMask = ($configdata.AzureVmSDNMgmtIP).split("/")[1]

try { 
    $MgmtNetAdapter = Get-NetAdapter -Name  "vEthernet ($($MgmtVNIC.Name))" 
}
catch { }

try {
    $MgmtNetIpAddr = ($MgmtNetAdapter | Get-NetIPAddress -AddressFamily IPv4).IpAddress
}
catch { }

if ( ($null -eq $MgmtNetIpAddr) -or ($MgmtNetIpAddr -ne $AzureVmSDNIp)) {
    Write-Host -ForegroundColor Green "Adding Ip address/mask $($configdata.AzureVmSDNMgmtIP) on AzureVM : $env:COMPUTERNAME"
    $MgmtNetAdapter | New-NetIPAddress -AddressFamily IPv4 -IPAddress $AzureVmSDNIp -PrefixLength $AzureVmSDNMask | Out-Null
    Write-Host -ForegroundColor Green "Adding DNS $($configdata.ManagementDNSP) on AzureVM:$env:COMPUTERNAME NetAdapter:$($MgmtNetAdapter.Name)"
    $MgmtNetAdapter | Set-DnsClientServerAddress -ServerAddresses $configdata.ManagementDNS | Out-Null
}



Write-Host -ForegroundColor Green "Adding Ip Route to reach SDN VIP pool $($configdata.PublicVIPNet)"
New-NetRoute -AddressFamily "IPv4" -DestinationPrefix $configdata.PublicVIPNet -NextHop $configdata.ManagementGateway -InterfaceIndex $MgmtNetAdapter.InterfaceIndex

$MgmtVNIC | Set-VMNetworkAdapterVlan -Access -VlanId $configdata.ManagementVLANID

#>

Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start ToR deployment"

foreach ( $torRouter in $configdata.TORrouter) {
    $paramsVM.VMName = $torRouter.ComputerName
    $paramsVM.Nics = $torRouter.NICs
    $paramsVM.VMMemory = $torRouter.VMMemory
    $paramsVM.VMProcessorCount = $torRouter.VMProcessorCount
    # No need to join ToR to domain
    $paramsVM.JoinDomain = $null
    $peerAsn = [int]$configdata.TORrouter.SDNASN
    New-SdnToR -VMName $paramsVM.VMName -RouterIPAddress $configdata.TORrouter.bgprouter.RouterIPAddress -BgpPeers $configdata.TORrouter.BgpPeers -LocalASN $configdata.TORrouter.BgpRouter.RouterAsn -VMParams $paramsVM -LocalAdminCredential $LocalAdminCredential -PeerAsn $peerAsn
}
Start-Sleep 60

if($configData.DCs.Count -ne 0)
{
    Write-Host "############"
    Write-Host "########"
    Write-Host "####"
    Write-Host "--- Start Domain controller deployment "
    #Creating DC
    foreach ( $dc in $configdata.DCs) {
        Write-Host "Install DC on VM $dc.ComputerName"
        # Install DC and Create AD Forest 
        New-SdnDC -VMName $dc.ComputerName -DomainFQDN $ConfigData.DomainFQDN -LocalAdminPassword $password -DomainAdminCredential $DomainJoinCredential
        
        Invoke-Command -VMName $dc.ComputerName -Credential $DomainJoinCredential { 
            #Removing DNS registration on 2nd adapter
            Write-host -ForegroundColor Green "Configuring DNS server to only listening on mgmt NIC"   
            Get-NetAdapter | Set-DnsClient -RegisterThisConnectionsAddress $false
            Get-NetAdapter "Ethernet" | Set-DnsClient -RegisterThisConnectionsAddress $true
            #Get-NetAdapter "Ethernet 2" | Set-DnsClientServerAddress -ServerAddresses "" 
            ipconfig /registerdns
            dnscmd /ResetListenAddresses "$($configdata.ManagementDNS)"
            Restart-Service DNS
        } -ArgumentList $configdata
    }
    
    Start-Sleep 60
}


Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start Hypv hosts deployment "
#Creating HYPV Hosts
foreach ( $node in $configdata.HyperVHosts) {
    $paramsVM.VMName = $node.ComputerName
    $paramsVM.Nics = $node.NICs
    $paramsVM.VMMemory = $node.VMMemory
    $paramsVM.VMProcessorCount = $node.VMProcessorCount
    $paramsVM.JoinDomain = $configdata.DomainFQDN
    $paramsVM.Roles = @("Microsoft-Hyper-V")
    Write-Host -ForegroundColor Green "Step 1 - Creating Host VM $($node.ComputerName)" 
    New-SdnVM @paramsVM
    $paramsVM.Roles = @()
    $VlanInfo = @{
        'AllowedVlanIdList' = $node.AllowedVlanIdList
        'NativeVlanId' = $node.NativeVlanId
        'ManagementVlan' = $node.Nics[0].VLANID
    }

    Write-Host -ForegroundColor Green "Step 2 - Configuring VM $($node.ComputerName) used as SDN Host" 
    New-SdnHost -VMName $node.ComputerName -S2DDiskSize $ConfigData.S2DDiskSize -S2DDiskNumber $ConfigData.S2DDiskNumber -VlanInfo $VlanInfo -DomainJoinCredential $DomainJoinCredential -LocalAdminCredential $LocalAdminCredential
}
<#
Start-Sleep 60

Write-Host -ForegroundColor Green "Step 6 - Creating new S2D Failover cluster for Hyperconverged SDN"
New-SDNS2DCluster $ConfigData.HyperVHosts.ComputerName $DomainJoinCredential $ConfigData.S2DClusterIP $ConfigData.S2DClusterName 

Write-Host -ForegroundColor Yellow "Adding entry in Azure VM's host file to manage S2D and SDN with WAC"
Add-Content C:\windows\System32\drivers\etc\hosts -Value "$($ConfigData.S2DClusterIP) $($ConfigData.S2DClusterName)"

Write-Host -ForegroundColor Green "SDN HyperConverged Cluster is ready."
Write-Host -ForegroundColor Green ""

Write-Host -ForegroundColor Green "Creating SMBSHare containing VHDX template to use with SDNExpress deployment"
New-SmbShare -Name Template -Path $configdata.VHDPath -FullAccess Everyone

$account = (get-localuser | ? Description -Match "Built-in account for administraring").name
$Msg = "Please enter Password for local account $account"

if ( $configdata.AzureVMadmin -and $configdata.AzureVMPwd) {
    $secpasswd = ConvertTo-SecureString $configdata.AzureVMPwd -AsPlainText -Force
    $LocalAzureVMCred = New-Object System.Management.Automation.PSCredential ($configdata.AzureVMadmin, $secpasswd)
}
else {
    $LocalAzureVMCred = (Get-Credential -Message $Msg -Credential $account)   
}


#Misc things
Invoke-Command -VMName $configdata.HyperVHosts[0].ComputerName  -Credential $DomainJoinCredential {
    Write-Host -ForegroundColor Green "Mapping SMBSHare on $env:COMPUTERNAME to Z:"
    $AzureVMName = $args[0]; $Cred = $args[1]
    New-SmbGlobalMapping -LocalPath Z: -RemotePath "\\$AzureVMName\Template"  -Credential $Cred -Persistent $true

    #Write-Host -ForegroundColor Green "Configuring WMI over HTTPS and certificate authentication on $env:COMPUTERNAME"
    <#
    Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
    $NCthumbprint = (Get-ChildItem Cert:\LocalMachine\root | ? { $_.Subject -match "NCFABRIC.SDN.LAB" }).Thumbprint
    New-Item -Path WSMan:\localhost\ClientCertificate -URI * -Issuer $NCthumbprint -Credential (Get-Credential)
    $Mythumbprint = (Get-ChildItem Cert:\LocalMachine\My | ? { $_.Subject -match $env:COMPUTERNAME }).Thumbprint
    New-Item -Path WSMan:\localhost\Listener -Address * -Transport HTTPS -CertificateThumbPrint $Mythumbprint -force

    get-vm | restart-Vm -force 

    Add-MpPreference -ExclusionExtension "vhd"
    Add-MpPreference -ExclusionExtension "vhdx"
} -ArgumentList $env:COMPUTERNAME, $LocalAzureVMCred


#####Move back
Write-Host "############"
Write-Host "########"
Write-Host "####"
Write-Host "--- Start outside SDN stack Tenant GW deployment "
#Creating Gw Hosts
foreach ( $GW in $configdata.TenantInfraGWs) {
    $paramsVM.VMName = $GW.ComputerName
    $paramsVM.Nics = $GW.NICs
    $paramsVM.VMMemory = $ConfigData.VMMemory
    $paramsVM.VMProcessorCount = $ConfigData.VMProcessorCount

    Write-Host -ForegroundColor Green "Step 1 - Creating GW VM $($GW.ComputerName)" 
    New-SdnVM @paramsGW 

    Start-VM $GW.ComputerName
    Write-host "Wait till the VM $($GW.ComputerName) is not WinRM reachable"
    while ((Invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $GW.ComputerName) { Start-Sleep -Seconds 1 }

    foreach ( $TenantvGW in $configdata.TenantvGWs) {
        #"$($TenantvGW.tenant) ==  $($Tenant.name) => $($Tenant.PhysicalGwVMName)"
        if ( $TenantvGW.Tenant -eq $GW.Tenant ) {
            invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential {
                $TenantvGW = $args[0]
                Write-Host -ForegroundColor Yellow "Checking IP config from $($TenantvGW.VirtualGwName) config"
            
                Write-Host -ForegroundColor Green "Adding Remote Access feature on $env:COMPUTERNAME"
                $res = Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools

                if ( $res.RestartNeeded -eq "Yes" ) { Restart-Computer -Force; Write-host "Rebooting $env:COMPUTERNAME" }
            } -ArgumentList $TenantvGW
            
            Sleep 30

            while ((Invoke-Command -VMName $GW.ComputerName -Credential $LocalAdminCredential { $env:COMPUTERNAME } `
                        -ea SilentlyContinue) -ne $GW.ComputerName) { Start-Sleep -Seconds 1 }

            invoke-Command -VMName  $GW.ComputerName  -Credential $LocalAdminCredential {
                $TenantvGW = $args[0]

                $tunnelMode = $false                   
                if ( $TenantvGW.Type -eq "L3") {
                    $VpnType = "RoutingOnly"    
                }
                elseif ( $TenantvGW.Type -eq "GRE") {
                    $VpnType = "VpnS2S"   
                    $tunnelMode = $true                                    
                }
                Write-Host -ForegroundColor Green "Installing Remote Access VPNtype=$VpnType on $env:COMPUTERNAME"

                Install-RemoteAccess -VpnType $VpnType  
            
                $run = (Get-Service RemoteAccess).status

                if ( $run -ne "Running") { Start-Service RemoteAccess }

                if (  $tunnelMode ) {
                    Write-Host -ForegroundColor Yellow "Configuring $($TenantvGW.Type) tunnel on $env:COMPUTENAME"
                    if ( $TenantvGW.Type -eq "GRE") {
                        #GRE VIP POOL
                        if ( ! ((Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $TenantvGW.GrePeer) ) { 
                            Write-Host -ForegroundColor Yellow "IP Address $($TenantvGW.GrePeer) is missing so adding it"
                            New-NetIPAddress -InterfaceIndex (Get-NetAdapter).ifIndex -IPAddress $TenantvGW.GrePeer -PrefixLength 32 | Out-Null
                        }
                        $GrepVIPPool = "2.2.2.2"
                        
                        Add-VpnS2SInterface -Name FabrikamGRE -Destination $GrepVIPPool -SourceIpAddress $TenantvGW.GrePeer -GreKey $TenantvGW.PSK `
                            -GreTunnel -IPv4Subnet "$($TenantvGW.RouteDstPrefix):10"
                    }
                }
                # 
                if ( $TenantvGW.BGPEnabled) {
                    if ( ! (Get-NetIPAddress -AddressFamily IPv4).IPAddress -match $TenantvGW.BgpPeerIpAddress ) { 
                        Write-Host -ForegroundColor Yellow "IP Address $($TenantvGW.PeerIpAddrGW) is missing so adding it"
                        New-NetIPAddress -InterfaceIndex (Get-NetAdapter).ifIndex -IPAddress $TenantvGW.BgpPeerIpAddress -PrefixLength 24
                    }
                    
                    try {
                        $bgpRouter = Get-BgpRouter -ErrorAction Ignore
                    }
                    catch { }
                    
                    if ( ! $bgpRouter ) {
                        Add-BgpRouter -BgpIdentifier $TenantvGW.BgpPeerIpAddress -LocalASN $TenantvGW.BgpPeerAsNumber                        
                    }
                    
                    try {
                        $BpgPeer = Get-BgpPeer -Name $TenantvGW.VirtualGwName -ErrorAction Ignore
                    }
                    catch { }

                    if ( ! $BpgPeer ) {                 
                        Add-BgpPeer -Name $TenantvGW.VirtualGwName -LocalIPAddress $TenantvGW.BgpPeerIpAddress -LocalASN $TenantvGW.BgpPeerAsNumber `
                            -PeerIPAddress $TenantvGW.BgpLocalRouterIP[0] -PeerASN $($TenantvGW.BgpLocalExtAsNumber).split(".")[1] -OperationMode Mixed `
                            -PeeringMode Automatic
                    }   
                }
            } -ArgumentList $TenantvGW
        }     
    }
}

Write-Host -ForegroundColor Yellow "Adding a vNIC called Mirror on $($configdata.SwitchName) for port Mirroring purpose" -NoNewline
Write-Host -ForegroundColor Yellow "Run Wireshark upon this vNIC to see all SDN traffic"

Add-VMNetworkAdapter -ManagementOS -SwitchName $($configdata.SwitchName) -Name Mirror 

Write-Host -ForegroundColor Yellow "Configuring all SDN VM as port mirror source and vNIC Mirror as destination" 
Get-VMNetworkAdapter -VMName * | Set-VMNetworkAdapter -PortMirroring Source
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapter -PortMirroring Destination
Get-VMNetworkAdapter -ManagementOS -name Mirror | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList 7-1001 -NativeVlanId 0

#>
$HypvHost = $configdata.HyperVHosts[0].ComputerName
Write-Host -ForegroundColor Green `
    "SDN Nested Infrastrucre is ready. You can deploy SDN using SDNExpress.ps1 script. Execute it locally from $HypvHost"