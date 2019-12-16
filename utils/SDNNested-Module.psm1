function GetCred {
    param(
        [String] $SecurePasswordText,
        [PSCredential] $Credential,
        [String] $Message,
        [String] $UserName
    )
        write-Host "Using credentials from the command line."    
        return  get-Credential -Message $Message -UserName $UserName
}

function Add-UnattendFileToVHD {
    
    Param(
        [String] $VHD, 
        [String] $ProductKey = "",
        [String] $DomainJoin,
        [String] $ComputerName,
        [String] $KeyboardLayout,
        [String] $DomainFDQN,
        [String] $CredentialDomain,
        [String] $CredentialPassword,
        [String] $CredentialUsername,
        [String] $LocalAdminPassword,
        [Object] $NICs,
        [String[]] $Roles = @()
    )

    Write-Host "Generating and injecting unattend.xml to $VHD"

    $TempFile = New-TemporaryFile
    Remove-Item $TempFile.FullName -Force
    $MountPath = $TempFile.FullName

    New-Item -ItemType Directory -Force -Path $MountPath | out-null

    Write-Host "Mounting $VHD file"
    Mount-WindowsImage -ImagePath $VHD -Index 1 -path $MountPath | out-null

    if ($Roles.count -gt 0) {
        write-sdnexpresslog "Adding Roles ($Roles) offline to save reboot later"

        foreach ($role in $Roles) {
            Enable-WindowsOptionalFeature -Path $MountPath -FeatureName $role -All -LimitAccess | Out-Null
        }
    }
    
    $TimeZone = "Central European Time"
    $count = 1
    $TCPIPInterfaces = ""
    $dnsinterfaces = ""

    foreach ($Nic in $NICs) {
        
        #$MacAddress = [regex]::matches($nic.MacAddress.ToUpper().Replace(":", "").Replace("-", ""), '..').groups.value -join "-"

        if (![String]::IsNullOrEmpty($Nic.IPAddress)) {
            $sp = $NIC.IPAddress.Split("/")
            $IPAddress = $sp[0]
            $SubnetMask = $sp[1]
    
            $Gateway = $Nic.Gateway
            $NicName = $Nic.Name

            $gatewaysnippet = ""
    
            if (![String]::IsNullOrEmpty($Gateway)) {
                $gatewaysnippet = @"
                <routes>
                    <Route wcm:action="add">
                        <Identifier>0</Identifier>
                        <Prefix>0.0.0.0/0</Prefix>
                        <Metric>20</Metric>
                        <NextHopAddress>$Gateway</NextHopAddress>
                    </Route>
                </routes>
"@
            }
    
            $TCPIPInterfaces += @"
                <Interface wcm:action="add">
                    <Ipv4Settings>
                        <DhcpEnabled>false</DhcpEnabled>
                    </Ipv4Settings>
                    <Identifier>$NicName</Identifier>
                    <UnicastIpAddresses>
                        <IpAddress wcm:action="add" wcm:keyValue="1">$IPAddress/$SubnetMask</IpAddress>
                    </UnicastIpAddresses>
                    $gatewaysnippet
                </Interface>
"@ 
        }
        else {
            $TCPIPInterfaces += @"
            <Interface wcm:action="add">
                <Ipv4Settings>
                    <DhcpEnabled>true</DhcpEnabled>
                </Ipv4Settings>
                <Identifier>$NicName</Identifier>
            </Interface>
"@ 

        }        
        $alldns = ""
        foreach ($dns in $Nic.DNS) {
            $alldns += '<IpAddress wcm:action="add" wcm:keyValue="{1}">{0}</IpAddress>' -f $dns, $count++
        }

        if ( $null -eq $Nic.DNS -or $Nic.DNS.count -eq 0) {
            $dnsregistration = "false"
        }
        else {
            $dnsregistration = "true"
        }

        $dnsinterfaces += @"
            <Interface wcm:action="add">
                <DNSServerSearchOrder>
                $alldns
                </DNSServerSearchOrder>
                <Identifier>$NicName</Identifier>
                <EnableAdapterDomainNameRegistration>$dnsregistration</EnableAdapterDomainNameRegistration>
            </Interface>
"@
    }

    
    $UnattendedJoin = @"
    
                    <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Identification>
                    <Credentials>
                        <Domain>$CredentialDomain</Domain>
                        <Password>$CredentialPassword</Password>
                        <Username>$CredentialUsername</Username>
                    </Credentials>
                    <JoinDomain>$DomainFQDN</JoinDomain>
                </Identification>
            </component>    
"@

    $UnattendedDomainAccount = @"
                        <DomainAccounts>
                            <DomainAccountList wcm:action="add">
                                <DomainAccount wcm:action="add">
                                    <Name>$DomainAdminUserName</Name>
                                    <Group>Administrators</Group>
                                </DomainAccount>
                                <Domain>$DomainAdminDomain</Domain>
                            </DomainAccountList>
                        </DomainAccounts>
"@

    if ( $ComputerName -match "DC" -or $ComputerName -match "GW" ) {
        $UnattendedJoin = $null
    }

    if ( $ComputerName -match "GW"){
        $DomainAccount = $null
    }

    if([String]::IsNullOrEmpty($DomainJoin))
    {
        $UnattendedJoin = $null
        $DomainAccountn = $null
    }

    $UnattendFile = @"
<?xml version="1.0" encoding="utf-8"?>
    <unattend xmlns="urn:schemas-microsoft-com:unattend">
        <settings pass="specialize">
            <component name="Networking-MPSSVC-Svc" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <DomainProfile_EnableFirewall>false</DomainProfile_EnableFirewall>
                    <PrivateProfile_EnableFirewall>false</PrivateProfile_EnableFirewall>
                    <PublicProfile_EnableFirewall>false</PublicProfile_EnableFirewall>
                </component>
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <ComputerName>$ComputerName</ComputerName>
                <ProductKey>$ProductKey</ProductKey>
            </component>
            <component name="Microsoft-Windows-TerminalServices-LocalSessionManager" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <fDenyTSConnections>false</fDenyTSConnections>
            </component>
            <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <UserLocale>en-us</UserLocale>
                <UILanguage>en-us</UILanguage>
                <SystemLocale>en-us</SystemLocale>
                <InputLocale>$KeyboardLayout</InputLocale>
            </component>
            <component name="Microsoft-Windows-IE-ESC" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <IEHardenAdmin>false</IEHardenAdmin>
                <IEHardenUser>false</IEHardenUser>
            </component>
            <component name="Microsoft-Windows-TCPIP" processorArchitecture="wow64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Interfaces>
                    $TCPIPInterfaces
                </Interfaces>
            </component>
            <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <Interfaces>
                     $DNSInterfaces
                </Interfaces>
            </component>$UnattendedJoin
        </settings>
        <settings pass="oobeSystem">
            <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                   <UserAccounts>
                    <AdministratorPassword>
                        <Value>$LocalAdminPassword</Value>
                        <PlainText>true</PlainText>
                    </AdministratorPassword>$UnattendedDomainAccount
                </UserAccounts>
                <TimeZone>$TimeZone</TimeZone>
                <OOBE>
                    <HideEULAPage>true</HideEULAPage>
                    <SkipUserOOBE>true</SkipUserOOBE>
                    <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
                    <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
                    <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
                    <NetworkLocation>Work</NetworkLocation>
                    <ProtectYourPC>1</ProtectYourPC>
                    <HideLocalAccountScreen>true</HideLocalAccountScreen>
                </OOBE>
            </component>
        </settings>
    <cpi:offlineImage cpi:source="" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"@
 
    Write-Host "Writing unattend.xml to $MountPath\unattend.xml"
    Set-Content -value $UnattendFile -path "$MountPath\unattend.xml" | out-null
    
    DisMount-WindowsImage -Save -path $MountPath | out-null
    Remove-Item $MountPath -Recurse -Force
}
    
function New-SdnVM() {
    param(
        [String] $VMLocation,
        [String] $VMName,
        [String] $VHDSrcPath,
        [String] $VHDName,
        [Int64] $VMMemory,
        [int] $VMProcessorCount,
        [String] $SwitchName = "",
        [Object] $Nics,
        [String] $CredentialDomain,
        [String] $CredentialUserName,
        [String] $CredentialPassword,
        [String] $JoinDomain,
        [String] $LocalAdminPassword,
        [String] $DomainAdminDomain,
        [String] $DomainAdminUserName,
        [String] $ProductKey = "",
        [String] $Locale = [System.Globalization.CultureInfo]::CurrentCulture.Name,
        [String] $TimeZone = [TimeZoneInfo]::Local.Id,
        [String] $DomainFQDN,
        [String] $KeyboardLayout,
        [String[]] $Roles = @()
     )
    
    $CurrentVMLocationPath = "$VMLocation\$VMName"
    $VHDTemplateFile = "$VHDSrcPath\$VHDName"

    Write-Host -ForegroundColor Green "New-SDNVM"
    Write-Host -ForegroundColor Green "  -VMLocation: $VMLocation"
    Write-Host -ForegroundColor Green "  -VMName: $VMName"
    Write-Host -ForegroundColor Green "  -VHDSrcPath: $VHDSrcPath"
    Write-Host -ForegroundColor Green "  -VHDName: $VHDName"
    Write-Host -ForegroundColor Green "  -VMMemory: $VMMemory"
    Write-Host -ForegroundColor Green "  -SwitchName: $SwitchName"
    Write-Host -ForegroundColor Green "  -Nics:"
    foreach ($Nic in $Nics) {
        Write-Host -ForegroundColor Green "   $($Nic.Name), Mac:$($Nic.MacAddress), IP:$($nic.IPAddress), GW:$($Nic.Gateway), DNS:$($Nic.DNS), VLAN:$($Nic.VLANID)"
    }
    Write-Host -ForegroundColor Green "  -CredentialDomain: $CredentialDomain"
    Write-Host -ForegroundColor Green "  -CredentialUserName: $CredentialUserName"
    Write-Host -ForegroundColor Green "  -CredentialPassword: ********"
    Write-Host -ForegroundColor Green "  -JoinDomain: $JoinDomain"
    Write-Host -ForegroundColor Green "  -LocalAdminPassword: ********"
    Write-Host -ForegroundColor Green "  -DomainAdminDomain: $DomainAdminDomain"
    Write-Host -ForegroundColor Green "  -DomainAdminUserName: $DomainAdminUserName"
    Write-Host -ForegroundColor Green "  -ProductKey: ********"
    Write-Host -ForegroundColor Green "  -VMProcessorCount: $VMProcessorCount"
    Write-Host -ForegroundColor Green "  -Locale: $Locale"
    Write-Host -ForegroundColor Green "  -TimeZone: $TimeZone"
    Write-Host -ForegroundColor Green "  -Roles: $roles"

    if ( !(Test-Path $CurrentVMLocationPath) ) {  
        Write-Host -ForegroundColor Yellow "Creating folder $CurrentVMLocationPath"
        New-Item -ItemType Directory $CurrentVMLocationPath | Out-null
    }

    Write-Host "Copying VHD template $VHDTemplateFile to $CurrentVMLocationPath"
    Copy-Item -Path $VHDTemplateFile -Destination $CurrentVMLocationPath -Force | Out-Null
    
    $params = @{
        'VHD'                = "$CurrentVMLocationPath\$VHDName";
        'ProductKey'         = $ProductKey;
        'IpGwAddr'           = $IpGwAddr;
        'DomainJoin'         = $JoinDomain;
        'ComputerName'       = $VMName;
        'KeyboardLayout'     = $KeyboardLayout;
        'DomainFDQN'         = $DomainFQDN;
        'CredentialDomain'   = $CredentialDomain;
        'CredentialPassword' = $CredentialPassword;
        'CredentialUsername' = $CredentialUserName;
        'LocalAdminPassword' = $LocalAdminPassword;
        'NICS'               = $Nics;
        'Roles'              = $Roles
    }

    Add-UnattendFileToVHD @params
    
    if ( Test-Path $CurrentVMLocationPath) {
        Write-Host "Creating VM $VMName"

        $VHDOsFile = $(Get-Item $CurrentVMLocationPath\*.vhdx).FullName

        $NewVM = New-VM -Generation 2 -Name $VMName -Path $CurrentVMLocationPath -MemoryStartupBytes $VMMemory -VHDPath $VHDOsFile -SwitchName $SwitchName
        $NewVM | Set-VM -processorcount $VMProcessorCount | out-null

        for ( $i = 0; $i -lt $Nics.count; $i++ ) {
            if ( $i -gt 0) {
                $NewVM | Add-VMNetworkAdapter -SwitchName $SwitchName
                $vmNIC = ($NewVM | Get-VMNetworkAdapter)[-1]
                $vmNIC | Set-VMNetworkAdapterVlan -Access -VlanId $Nics[0].VLANID            
            }
            else { 
                #Hard to predict how PNP manager is enumerating NIC so set MGTM vLAN ID to all vNICS
                $NewVM | Get-VMNetworkAdapter | Set-VMNetworkAdapterVlan -Access -VlanId $Nics[0].VLANID            
            }
        }
    } 
}

function Add-WindowsFeature() {
    param(
        [String] $VMName,
        [PSCredential] $credential,
        [String[]] $FeatureList
    )

    foreach ($feature in $FeatureList) {
        Invoke-Command -VMName $VMName -Credential $credential {
            $feature=$args[0]
            Write-host "Installing Windows Feature $feature on $($env:COMPUTERNAME)"
            Install-WindowsFeature -Name $feature -IncludeManagementTools | Out-Null
        } -ArgumentList $feature
    }
    Write-host "Restarting $VMName"
    Invoke-Command -VMName $VMName -Credential $credential { Restart-Computer -Force }
}

function Add-VMDataDisk() {
    param(
        [String] $VMName,
        [int64] $DiskSize,
        [int] $DiskNumber
    )

    $VM = (Get-VM $VMName)
    $LocalVMPath = $VM.Path

    for ($i = 0; $i -lt $DiskNumber; $i++) {
        New-VHD -Path "$LocalVMPath\$VMNAme-S2D_Disk$i.vhdx" -SizeBytes $DiskSize -Dynamic | Out-Null
        Add-VMHardDiskDrive -Path "$LocalVMPath\$VMNAme-S2D_Disk$i.vhdx" -VMName $VMName -ControllerType SCSI | Out-Null
    }   
}


function New-SDNS2DCluster {
    param (
        [String[]] $Nodes,
        [PSCredential] $credential,
        [String] $IpAddress,
        [String] $ClusterName
    )

    Write-Host "S2DCONFIG: Cleaning Drives"
    Invoke-Command -VMName ($Nodes) -Credential $credential {
        Update-StorageProviderCache
        Get-StoragePool | Where-Object IsPrimordial -eq $false | Set-StoragePool -IsReadOnly:$false -ErrorAction SilentlyContinue
        Get-StoragePool | Where-Object IsPrimordial -eq $false | Get-VirtualDisk | Remove-VirtualDisk -Confirm:$false -ErrorAction SilentlyContinue
        Get-StoragePool | Where-Object IsPrimordial -eq $false | Remove-StoragePool -Confirm:$false -ErrorAction SilentlyContinue
        Get-PhysicalDisk | Reset-PhysicalDisk -ErrorAction SilentlyContinue
        Get-Disk | Where-Object Number -ne $null | Where-Object IsBoot -ne $true | Where-Object IsSystem -ne $true | Where-Object PartitionStyle -ne RAW | ForEach-Object {
            $_ | Set-Disk -isoffline:$false
            $_ | Set-Disk -isreadonly:$false
            $_ | Clear-Disk -RemoveData -RemoveOEM -Confirm:$false
            $_ | Set-Disk -isreadonly:$true
            $_ | Set-Disk -isoffline:$true
        }
        Get-Disk | Where-Object Number -Ne $Null | Where-Object IsBoot -Ne $True | Where-Object IsSystem -Ne $True | Where-Object PartitionStyle -Eq RAW | Group-Object -NoElement -Property FriendlyName
    } | Sort-Object -Property PsComputerName, Count

    Invoke-Command -VMName $Nodes[0] -ArgumentList $Nodes, $IpAddress, $ClusterName -Credential $credential -ScriptBlock {
         
        $ClusterNodes = $args[0]
        $ClusterIP = $args[1]
        $ClusterName = $args[2]

        # Create S2D Cluster
        Write-Verbose "Creating Cluster: SDNCLUSTER"
        Import-Module FailoverClusters 

        Test-Cluster –Node $ClusterNodes[0], $ClusterNodes[1] –Include "Storage Spaces Direct", "Inventory", "Network", "System Configuration"

        # Create Cluster
        New-Cluster -Name $ClusterName -Node $ClusterNodes -StaticAddress $ClusterIP -NoStorage | Out-Null

        # Invoke Command to enable S2D on SDNCluster        
        Enable-ClusterS2D -CacheState Disabled -AutoConfig:0 -SkipEligibilityChecks -Confirm:$false | Out-Null

        $params = @{
                StorageSubSystemFriendlyName = "*Clustered*"
                FriendlyName                 = 'SDN_S2D_Storage'
                ProvisioningTypeDefault      = 'Fixed'
            }

        New-StoragePool @params -PhysicalDisks (Get-PhysicalDisk | Where-Object { $_.CanPool -eq $true }) | Out-Null

        Get-PhysicalDisk | Where-Object  MediaType -eq "UnSpecified" | Set-PhysicalDisk -MediaType HDD | Out-Null

        $params = @{  
            FriendlyName            = 'S2D_CSV1' 
            FileSystem              = 'CSVFS_ReFS'
            StoragePoolFriendlyName = 'SDN_S2D_Storage'
            PhysicalDiskRedundancy  = 1    
        }

        New-Volume @params -UseMaximumSize | Out-Null

        # Set Virtual Environment Optimizations
        Get-storagesubsystem clus* | set-storagehealthsetting -name “System.Storage.PhysicalDisk.AutoReplace.Enabled” -value “False”
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\spaceport\Parameters -Name HwTimeout -Value 0x00007530
    } | Out-Null
}


function New-SdnDC()
{
    Param(
        [String] $VMName,
        [String] $DomainFQDN,
        #Local Admin Credential will also be used as SafeModeAdministratorPassword
        [securestring] $LocalAdminPassword,
        [pscredential] $DomainAdminCredential
    )
    
    $paramsDeployForest = @{
        DomainName                    = $DomainFQDN
        DomainMode                    = 'WinThreshold'
        DomainNetBiosName             = $DomainFQDN.split(".")[0]
        SafeModeAdministratorPassword = $LocalAdminPassword 
    }

    $LocalAdminCredential = New-Object System.Management.Automation.PSCredential(".\administrator", $LocalAdminPassword)

    Invoke-Command -VMName $VMName -Credential $LocalAdminCredential -ScriptBlock {
        Write-host -ForegroundColor Green "Installing AD-Domain-Services on vm $env:COMPUTERNAME"
        Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools | Out-Null
        
        $params = @{
            DomainName                    = $args.DomainName
            DomainMode                    = $args.DomainMode
            SafeModeAdministratorPassword = $args.SafeModeAdministratorPassword
        }
        Write-host -ForegroundColor Green "Installing ADDSForest on vm $env:COMPUTERNAME"
        Install-ADDSForest @params -InstallDns -Confirm -Force | Out-Null
        #
    } -ArgumentList $paramsDeployForest

    #Write-host -ForegroundColor Green "Restarting vm $($dc.computername)"
    #Restart-VM $dc.ComputerName -Force

    Write-host "Wait till ADDS is totally up and running"

    WaitForVMToBeReady -VMNames $VMName -CheckPendingReboot -Credential $DomainAdminCredential

    Write-host "ADDS has been up and running"
}
function New-SdnHost
{
    Param(
        [String] $VMName,
        [int64] $S2DDiskSize = 0,
        [Int] $S2DDiskNumber,
        [pscredential] $DomainJoinCredential,
        [pscredential] $LocalAdminCredential,
        [Object] $VlanInfo
    )
  
    #required for nested virtualization 
    Get-VM -Name $VMName | Set-VMProcessor -ExposeVirtualizationExtensions $true | out-null
    #Required to allow multiple MAC per vNIC
    Get-VM -Name $VMName | Get-VMNetworkAdapter | Set-VMNetworkAdapter -MacAddressSpoofing On

    #Create S2D Disk optional 
    if($S2DDiskSize -ne 0)
    {
        Write-Host -ForegroundColor Green "Step 2 - Adding  VM DataDisk for S2D on $VMName" 
        Add-VMDataDisk $VMName $S2DDiskSize $S2DDiskNumber
    }
    
    Write-Host -ForegroundColor Green  "Step 3 - Starting VM $VMName"
    Start-VM $VMName
 
    Write-Host -ForegroundColor yellow "Waiting till the $VMName is not domain joined to $($configdata.DomainFQDN)"
    Start-Sleep 120
    #Use Local Admin Credential to connect to VM for domain join detection
    while ((Invoke-Command -VMName $VMName -Credential $DomainJoinCredential { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }  


    Write-Host -ForegroundColor Green  "Step 4 - Adding required features on VM $VMName"
    Invoke-Command -VMName $VMName -Credential $DomainJoinCredential {
        $FeatureList = "Hyper-V", "Failover-Clustering", "Data-Center-Bridging", "RSAT-Clustering-PowerShell", "Hyper-V-PowerShell", "FS-FileServer"
        Add-WindowsFeature $FeatureList 
        Restart-Computer -Force
    }

    Write-host "Wait till the VM $VMName is not WinRM reachable"
    Start-Sleep 120
    while ((Invoke-Command -VMName $VMName -Credential $DomainJoinCredential { $env:COMPUTERNAME } `
                -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }  

    Invoke-Command -VMName $VMName -Credential $DomainJoinCredential {
        Write-Host -ForegroundColor Green "Step 5 - Adding SDN VMSwitch on $($env:COMPUTERNAME)"
        New-VMSwitch -NetAdapterName $(Get-Netadapter).Name -SwitchName SDNSwitch -AllowManagementOS $true | Out-Null
        Get-VMNetworkAdapter -ManagementOS -Name SDNSwitch | Rename-VMNetworkAdapter -NewName MGMT
        Get-VMNetworkAdapter -ManagementOS -Name MGMT | Set-VMNetworkAdapterVlan -Access -VlanId $args[0]
        #Cred SSDP for remote administration
        Write-Host -ForegroundColor Green "Step 6 - Allowing CredSSP to managed HYPV host $($env:COMPUTERNAME) from Azure VM"
        Enable-WSManCredSSP -Role Server -Force | Out-Null
        Set-VMHost  -EnableEnhancedSessionMode $true
    } -ArgumentList $VlanInfo.ManagementVlan
    Get-VMNetworkAdapter -VMName $VMName | Set-VMNetworkAdapterVlan -Trunk -AllowedVlanIdList $VlanInfo.AllowedVlanIdList -NativeVlanId $VlanInfo.NativeVlanId
    #Adding credential to the cache

    Write-Host -ForegroundColor Green "Adding credential to the cache"
    $DomainJoinPassword = $DomainJoinCredential.GetNetworkCredential().Password
    Invoke-Expression -Command "cmdkey /add:$VMName.$($configdata.DomainFQDN) /user:$($configdata.DomainJoinUsername) /pass:$DomainJoinPassword"

    #Configure Kerberos Delegation to Hyper-V Hosts
    #This is used when SOFS configured to store VHDX file for Hyper-V Hosts
    install-windowsfeature rsat-adds
    Write-Host "Enable Kerberos Delegation on computer $VMName"
    Get-ADComputer -Identity $VMName | Set-ADAccountControl -TrustedForDelegation $true
}

<#
   This function used to configure TOR on VM specified. If VM Creation Parameters passed, we create the VM first. 
#>
function New-SdnToR()
{
    Param(
        [String] $VMName,
        [String] $RouterIPAddress,
        [String] $LocalASN,
        [Object] $BgpPeers,
        [pscredential] $LocalAdminCredential,
        [Object] $VMParams = $null,
        [uint32] $PeerAsn = 0
    )

    Write-Host -ForegroundColor Green "New-SdnToR"
    Write-Host -ForegroundColor Green "  -VMName: $VMName"
    Write-Host -ForegroundColor Green "  -RouterIPAddress: $RouterIPAddress"
    Write-Host -ForegroundColor Green "  -LocalASN: $LocalASN"
    
    if($VMParams -ne $null)
    {
        Write-Host "VM Parameters specified, create the VM first"
        New-SdnVM @VMParams
        Start-VM $VMName
        Write-host "Wait till the VM $VMName is not WinRM reachable"
        while ((Invoke-Command -VMName $VMName -Credential $LocalAdminCredential { $env:COMPUTERNAME } `
                    -ea SilentlyContinue) -ne $VMName) { Start-Sleep -Seconds 1 }
    
    }

    Invoke-Command -VMName $VMName -Credential $LocalAdminCredential { 
        Write-host -ForegroundColor Green "Installing RemoteAccess on vm $env:COMPUTERNAME to act as TOR Router"   
        Add-WindowsFeature RemoteAccess -IncludeAllSubFeature -IncludeManagementTools -Restart
    }

    WaitForVMToBeReady -VMNames $VMName -CheckPendingReboot -Credential $LocalAdminCredential

    Invoke-Command -VMName $VMName -Credential $LocalAdminCredential { 
        param(
            [String] $RouterIPAddress,
            [String] $LocalASN,
            [Object] $BgpPeers,
            [uint32] $PeerAsn
        )

        Install-RemoteAccess -VpnType RoutingOnly
        Write-host -ForegroundColor Green "Configuring BGP router and peers"
        Write-host -ForegroundColor Green "RouterIPAddress: $RouterIPAddress"
        Write-host -ForegroundColor Green "PeerAsn: $PeerAsn"

        Add-BgpRouter -BgpIdentifier $RouterIPAddress -LocalASN $LocalASN
        foreach ( $BgpPeer in $BgpPeers) {
            if($BgpPeer.PeerAsn -eq $null){
                $BgpPeer.PeerAsn = $PeerAsn
            }
            Write-host -ForegroundColor Yellow "Configuring BGP Peer $($BgpPeer.Name), Peer IP: $($BgpPeer.PeerIPAddress), PeerAsn $($BgpPeer.PeerAsn)"  
            Add-BgpPeer -Name $BgpPeer.Name -LocalIPAddress $RouterIPAddress -PeerIPAddress $BgpPeer.PeerIPAddress `
                -PeerASN $BgpPeer.PeerASN -OperationMode Mixed -PeeringMode Automatic 
        }
    
    } -ArgumentList $RouterIPAddress, $LocalASN, $BgpPeers, $PeerAsn
}

function WaitForComputerToBeReady {
    param(
        [string[]] $ComputerName,
        [Switch]$CheckPendingReboot,
        [pscredential] $Credential
    )


    foreach ($computer in $computername) {        
        write-host "Waiting for $Computer to become active."
        
        $continue = $true
        while ($continue) {
            try {
                $ps = $null
                $result = ""
                
                klist purge | out-null  #clear kerberos ticket cache 
                Clear-DnsClientCache    #clear DNS cache in case IP address is stale
                
                write-host "Attempting to contact $Computer."
                if($Credential)
                {
                    $ps = new-pssession -computername $Computer -Credential $Credential -erroraction ignore
                }else
                {
                    $ps = new-pssession -computername $Computer -erroraction ignore
                }
                
                if ($ps -ne $null) {
                    if ($CheckPendingReboot) {                        
                        $result = Invoke-Command -Session $ps -ScriptBlock { 
                            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                "Reboot pending"
                            } 
                            else {
                                hostname 
                            }
                        }
                    }
                    else {
                        try {
                            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                        }
                        catch { }
                    }
                    remove-pssession $ps
                }
                if ($result -eq $Computer) {
                    $continue = $false
                    break
                }
                if ($result -eq "Reboot pending") {
                    write-host "Reboot pending on $Computer.  Waiting for restart."
                }
            }
            catch {
            }
            write-host "$Computer is not active, sleeping for 10 seconds."
            sleep 10
        }
        write-host "$Computer IS ACTIVE.  Continuing with deployment."
    }
}

function WaitForVMToBeReady{
    param(
        [string[]] $VMNames,
        [Switch]$CheckPendingReboot,
        [pscredential] $Credential
    )

    foreach ($VMName in $VMNames) {        
        write-host "Waiting for $VMName to become active."
        
        $continue = $true
        while ($continue) {
            try {
                $ps = $null
                $result = ""
                
                klist purge | out-null  #clear kerberos ticket cache 
                Clear-DnsClientCache    #clear DNS cache in case IP address is stale
                
                write-host "Attempting to contact $VMName."
                if($Credential)
                {
                    $ps = new-pssession -VMName $VMName -Credential $Credential -erroraction ignore
                }else
                {
                    $ps = new-pssession -VMName $VMName -erroraction ignore
                }
                
                if ($ps -ne $null) {
                    if ($CheckPendingReboot) {                        
                        $result = Invoke-Command -Session $ps -ScriptBlock { 
                            if (Test-Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
                                "Reboot pending"
                            } 
                            else {
                                hostname 
                            }
                        }
                    }
                    else {
                        try {
                            $result = Invoke-Command -Session $ps -ScriptBlock { hostname }
                        }
                        catch { }
                    }
                    remove-pssession $ps
                }
                if ($result -eq $VMName) {
                    $continue = $false
                    break
                }
                if ($result -eq "Reboot pending") {
                    write-host "Reboot pending on $VMName.  Waiting for restart."
                }
            }
            catch {
            }
            write-host "$VMName is not active, sleeping for 10 seconds."
            sleep 10
        }
        write-host "$VMName IS ACTIVE.  Continuing with deployment."
    }
}
    

<#
    Function used to remove the whole SDN Nested Deployment on current Host
#>

Function Remove-SDNNested{
    Write-Host -ForegroundColor Green "Stopping all VMs"
    Get-VM | Stop-Vm -Force
    Write-Host -ForegroundColor Green "All VMs stopped"
    Write-Host -ForegroundColor Green "Removing All VMs"
    $allVMs = Get-VM
    foreach($vmToRemove in $allVMs)
    {
        $vmPath = $vmToRemove.Path
        $vhdPath = ($vmToRemove | Get-VMHardDiskDrive).Path
        Write-Host "Removing VM $vmToRemove"
        $vmToRemove | Remove-VM -Force
        Write-Host "Removed VM $vmToRemove"
        Write-Host "Removing VM Path $vmPath $vhdPath"
        Remove-Item -Path $vmPath -Force -Recurse
        Remove-Item -Path $vhdPath -Force
        Write-Host "Removed VM Path and VHD Path"
    }
}