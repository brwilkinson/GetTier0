#Requires -Module Pester

<#
Set-Location -Path F:\Project\Tests
..\Scripts\Invoke-Tests.ps1
..\Scripts\Invoke-TestsParallel.ps1
#>

param (
   [String]$ModuleName = '.'
)

#region setup
$here = Split-Path -Parent -Path $MyInvocation.MyCommand.Path
$sut = (Split-Path -Leaf -Path $MyInvocation.MyCommand.Path) -replace '\.Tests\.', '.'
. "$here\$sut"

Write-Verbose -Message "ModuleName: $ModuleName" -Verbose

if ($ModuleName -eq '.')
{
    $ModuleName = Import-Module -Name .\HostTests.psm1 -Verbose -PassThru
}



# Only capture Baselines from a Clean AD environment.
[bool]$global:CaptureBaseline = 0
if ($global:CaptureBaseline)
{
    $Confirm = Read-Host -Prompt 'Type YES to capture new baselines from Current system, Enter will escape'
    If ($Confirm -eq 'yes')
    {
        $global:CaptureBaseline = $True
        Write-Warning -Message 'you chose yes, to capture the new baselines.'
    }
    else
    {
        $global:CaptureBaseline = $False
        Write-Warning -Message 'you chose not to capture the new baselines.'
    }
}
#endregion


InModuleScope $ModuleName {

$ComputerName = Get-ADSHComputerName
$DomainName = Get-ADSHDomainName
$RootDomain = Get-ADSHDomainRoot
$OSVersion = Get-ADSHOSVersion

# 1.0
Describe "Get DC Share Info" -Fixture {

    # 1.1
    Context "Compare Share Names on the DC [$ComputerName]" {
        
        $shares = Get-ADSHShare

        $baselinePath = '..\Baselines\Host\Get-ADSHShare-BaseShareNames.csv'
        
        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHShare | Select-Object -Property Name | Export-Csv -Path $baselinePath
        }

        $reference = Import-Csv -Path $baselinePath

        ## 1.1.1
        #It -name "1.1.1 Number of File Shares on the DC [$ComputerName]" {
        #    @($shares).Count | Should Be @($reference).Count
        #}
        #
        ## 1.1.2
        #It -name "1.1.2 Missing Share Names on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $shares -Property Name -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Name) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

        ## 1.1.3
        #It -name "1.1.3 Extra   Share Names on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $shares -Property Name -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '=>' } | Select -expandproperty Name) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

    }#Context
}#Describe


# 2.0
Describe "Share Access Info" -Fixture {
    
    # 2.1
    Context "2.1 NETLOGON Share Access" {
        
        $NetLogonAccess = Get-ADSHShareAccess -Name NETLOGON

        $baselinepath = '..\Baselines\Host\Get-ADSHShareAccess-NETLOGON.csv'
        
        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHShareAccess -Name NETLOGON | Select-Object -Property Identity | Export-Csv -path $baselinepath
        }

        $reference = Import-Csv -Path $baselinepath

        ## 2.1.1
        #It -name "2.1.1 Number of Share ACCESS ACE's on NETLOGON on the DC [$ComputerName]" {
        #    @($NetLogonAccess).Count | Should Be @($reference).Count
        #}
        #
        ## 2.1.2
        #It -name "2.1.2 Missing Identities on Share Access NETLOGON on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $NetLogonAccess -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
        
        # 2.1.3
        It -name "2.1.3 Extra   Identities on Share Access NETLOGON on the DC [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $NetLogonAccess -Property Identity -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context

    # 2.2
    Context "2.2 SYSVOL Share Access on the DC [$ComputerName]" {
        
        $SysVolAccess = Get-ADSHShareAccess -Name SYSVOL

        $baselinepath = '..\Baselines\Host\Get-ADSHShareAccess-SYSVOL.csv'
        
        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHShareAccess -Name SYSVOL | Select-Object -Property Identity | Export-Csv -Path $baselinepath
        }

        $reference = Import-Csv -Path $baselinepath

        ## 2.2.1
        #It -name "2.2.1 Number of Share ACCESS ACE's on SYSVOL on the DC [$ComputerName]" {
        #    @($SysVolAccess).Count | Should Be @($reference).Count
        #}
        #
        ## 2.2.2
        #It -name "2.2.2 Missing Identities on SYSVOL Share on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $SysVolAccess -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
        
        # 2.2.3
        It -name "2.2.3 Extra   Identities on SYSVOL Share on the DC [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $SysVolAccess -Property Identity -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context
}#Describe


# 3.0
Describe "File Access Info" -Fixture {

    # 3.1
    Context "3.1 Has NTFS permissions on SYSVOL on the DC [$ComputerName]" {
        
        $SysVolAccess = Get-ADSHShareFileAccess -Name SYSVOL

        $baselinepath = '..\Baselines\Host\Get-ADSHShareFileAccess-SYSVOL.csv'
        
        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHShareFileAccess -Name SYSVOL | Select-Object -Property Identity | export-csv -path $baselinepath
        }

        $reference = Import-Csv -Path $baselinepath

        ## 3.1.1
        #It -name "3.1.1 Number of File ACCESS ACE's on SYSVOL on the DC [$ComputerName]" {
        #    @($SysVolAccess).Count | Should Be @($reference).Count
        #}
        #
        ## 3.1.2
        #It -name "3.1.2 Missing Identities for File Access on SYSVOL on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $SysVolAccess -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
        
        # 3.1.3
        It -name "3.1.3 Extra   Identities for File Access on SYSVOL on the DC [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $SysVolAccess -Property Identity -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
            $compare | should BeNullOrEmpty 
        }
    }#Context

    # 3.2
    Context "3.2 Has NTFS permissions on NETLOGON on the DC [$ComputerName]" {
        
        $NetLogonAccess = Get-ADSHShareFileAccess -Name NETLOGON

        $baselinepath = '..\Baselines\Host\Get-ADSHShareFileAccess-NETLOGON.csv'
        
        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHShareFileAccess -Name NETLOGON | Select-Object -Property Identity | export-csv -path $baselinepath
        }

        $reference = Import-Csv -Path $baselinepath
        
        ## 3.2.1
        #It -name "3.2.1 Number of File ACCESS ACE's on NETLOGON on the DC [$ComputerName]" {
        #    @($NetLogonAccess).Count | Should Be @($reference).count
        #}
        #
        ## 3.2.2
        #It -name "3.2.2 Missing Identities for File Access on NETLOGON on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $NetLogonAccess -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
        
        # 3.2.3
        It -name "3.2.3 Extra   Identities for File Access on NETLOGON on the DC [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $NetLogonAccess -Property Identity -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context

    # 3.3
    Context "3.3 Has distinct NTFS permissions on NETLOGON on the DC [$ComputerName]" {

        # This is the list of Tier0 FilesystemRights
        $Tier0 = 'FullControl','TakeOwnership','ChangePermissions','Delete','Write','WriteAttributes','WriteExtendedAttributes',
            'AppendData','CreateDirectories','CreateFiles','WriteData','WriteAttributes'

        $NetLogonAccess = Get-ADSHShareFileAccess -Name NETLOGON

        $Tier0 | ForEach-Object {
            $FileSystemRights = $_ 

            $baselinepath = "..\Baselines\Host\Get-ADSHShareFileAccess-NETLOGON-${FileSystemRights}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHShareFileAccess -Name NETLOGON | Where-Object { $_.FileSystemRights -like "*${FileSystemRights}*" } | 
                    Select-Object -Property Identity -Unique | export-csv -path $baselinepath
            }

            $Access = $NetLogonAccess | Where-Object { $_.FileSystemRights -like "*${FileSystemRights}*" } | Select-Object -Property Identity -Unique
            $reference = Import-Csv -Path $baselinepath
            if (! $Access){$Access = ''}
            if (! $reference){$reference = ''}
            
            ## 3.3.1
            #It -name "3.3.1 Missing Identities with [${FileSystemRights}] File Access on NETLOGON on the DC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 3.3.2
            It -name "3.3.2 Extra   Identities with [${FileSystemRights}] File Access on NETLOGON on the DC [$ComputerName]" -test {
                $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
                $compare | should BeNullOrEmpty 
            }

        }#Foreach-Object(Tier0)
    }#Context

    # 3.4
    Context "3.4 Has distinct NTFS permissions on SYSVOL on the DC [$ComputerName]" {

        # This is the list of Tier0 FilesystemRights
        $Tier0 = 'FullControl','TakeOwnership','ChangePermissions','Delete','Write','WriteAttributes','WriteExtendedAttributes',
            'AppendData','CreateDirectories','CreateFiles','WriteData','WriteAttributes'

        $NetLogonAccess = Get-ADSHShareFileAccess -Name SYSVOL

        foreach ($FileSystemRights in $Tier0)
        {
            $baselinepath = "..\Baselines\Host\Get-ADSHShareFileAccess-SYSVOL-${FileSystemRights}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHShareFileAccess -Name SYSVOL | Where-Object { $_.FileSystemRights -like "*${FileSystemRights}*" } | 
                    Select-Object -Property Identity -Unique | export-csv -path $baselinepath
            }

            $Access = $NetLogonAccess | Where-Object { $_.FileSystemRights -like "*${FileSystemRights}*" } | Select-Object -Property Identity -Unique
            $reference = Import-Csv -Path $baselinepath
            if (! $Access){$Access = ''}
            if (! $reference){$reference = ''}
            
            ## 3.4.1
            #It -name "3.4.1 Missing Identities with [${FileSystemRights}] File Access on SYSVOL on the DC [$ComputerName]" -test {
            #   $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
            #   $compare | should BeNullOrEmpty 
            #}

            # 3.4.2
            It -name "3.4.2 Extra   Identities with [${FileSystemRights}] File Access on SYSVOL on the DC [$ComputerName]" -test {
               $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
               $compare | should BeNullOrEmpty 
            }

        }#Foreach(Tier0)
    }#Context
}#Describe

# 4.0 
Describe "Windows Service Access Info" -Fixture {

    $ServiceAccess = Get-ADSHServiceControlAccess
    
    # 4.1
    #Context "4.1 Has Windows Service Access on the DC [$ComputerName]" {
        
        #$ServiceAccessIdentities = $ServiceAccess | Select-Object -Property Identity -Unique
        #
        #$baselinepath = '..\Baselines\Host\Get-ADSHServiceControlAccess.csv'
        #
        ## capturebaseline
        #if ($CaptureBaseline)
        #{
        #    Get-ADSHServiceControlAccess | Select-Object -Property Identity -Unique | export-csv -path $baselinepath
        #}
        #
        #$reference = Import-Csv -Path $baselinepath

        ## 4.1.1
        #It -name "4.1.1 Number of Windows Service Access on the DC [$ComputerName]" {
        #    
        #    # This test maybe too difficult to baseline (considering some SID's)
        #    Write-Warning -Message 'This test maybe too difficult to baseline (considering some SIDs)'
        #    @($ServiceAccessIdentities).Count | Should Be @($reference).Count
        #}
        #
        ## 4.1.2
        #It -name "4.1.2 Missing Identities for Windows Service Access on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $ServiceAccessIdentities -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
        
        ## 4.1.3
        #It -name "4.1.3 Extra   Identities for Windows Service Access on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $ServiceAccessIdentities -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '=>' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}
    #}#Context


    Context "4.2 Has Distinct Windows Service Access on the DC [$ComputerName]" {
    
        # This is the list of Tier0 ServiceControlRights
        $tier0 = 'ChangeConfig','UserDefinedControl','WriteDac','WriteOwner','GenericAll','GenericWrite'

        $ServiceHash = $ServiceAccess | Group-Object -Property Name -AsHashTable -AsString
    
        $CheckCount = $ServiceHash.Keys.count * $tier0.count

        $i=0
        foreach ($ServiceAccessRight in $Tier0) 
        {
            foreach ($Service in $ServiceHash.Keys) 
            {
                
                $ServiceAccess = $ServiceHash[$Service]
                
                
                if ($OSVersion.Major -ge 6 -and $OSVersion.Minor -ge 2)
                {
                    Write-Warning -Message "Using 2012 R2 Baselines"
                    $baselinepath = "..\Baselines\Host\Service\2012R2\Get-ADSHServiceControlAccessDistinct-${Service}-${ServiceAccessRight}.csv"
                }
                else
                {
                    Write-Warning -Message "Using 2008 R2 Baselines"
                    $baselinepath = "..\Baselines\Host\Service\2008R2\Get-ADSHServiceControlAccessDistinct-${Service}-${ServiceAccessRight}.csv"
                }

                # capturebaseline
                if ($CaptureBaseline)
                {
                    $ServiceHash[$Service] | Where-Object { $_.AccessMask -like "*${ServiceAccessRight}*" } |
                        Export-Csv -Path $baselinepath
                }

                if (-not (Test-Path -Path $baselinepath))
                {
                    Write-Warning -Message "NO baseline found for service: $Service for ${ServiceAccessRight}, using defaults"
                    $baselinepath = "..\Baselines\Host\Service\2012r2\Get-ADSHServiceControlAccessDistinct-Default-${ServiceAccessRight}.csv"
                }

                
                $i++
                Write-Verbose -Message "Checking $i of $CheckCount service ACEs" -verbose
                
                $Baseline = Import-Csv -Path $baselinepath
    
                $Access = $ServiceAccess | Where-Object { $_.AccessMask -like "*${ServiceAccessRight}*" }
                $reference = $Baseline | Where-Object {$_.AccessMask -like "*${ServiceAccessRight}*"}
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
    
                ## 4.2.1
                #It -name "4.2.1 Missing Identities with [${ServiceAccessRight}] for Windows Service [${Service}] Access on the DC [${ComputerName}]" -test {
                #   $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
                #   $compare | should BeNullOrEmpty 
                #}
    
                # 4.2.2
                It -name "4.2.2 Extra   Identities with [${ServiceAccessRight}] for Windows Service [$Service] Access on the DC [$ComputerName]" -test {
                   $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property Identity -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
                   $compare | should BeNullOrEmpty 
                }
    
            }#Foreach(ServiceACE)
        }#Foreach(Tier0)
    
    }#Context


}#Describe

# 5.0
Describe "WSMAN Endpoint Info" -Fixture {

    # 5.1
    Context "5.1 All WSMAN Endpoint Names on the DC [$ComputerName]" {
        
        $WSMANEndpoints = Get-ADSHWSMANEndpoint
        
        $baselinePath = '..\Baselines\Host\Get-ADSHWSMANEndpoint-BaseEndpointNames.csv'

        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHWSMANEndpoint | Select-Object -Property Name | export-csv -path $baselinePath
        }

        $reference = Import-Csv -Path $baselinePath
        
        ## 5.1.1
        #It -name "5.1.1 Number of WSMAN Endpoints on the DC [$ComputerName]" {
        #    @($WSMANEndpoints).Count | Should Be @($reference).Count
        #}
        #
        ## 5.1.2
        #It -name "5.1.2 Missing WSMAN Endpoints on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $WSMANEndpoints -Property Name -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Name) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

        # 5.1.3
        It -name "5.1.3 Extra   WSMAN Endpoints on the DC [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $WSMANEndpoints -Property Name -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Name) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context

    # 5.2
    Context "5.2 Identities with WSMAN Endpoint Permissions on the DC [$ComputerName]" {
        
        $WSMANEndpointPermissions = Get-ADSHWSMANEndpointPermissions
        
        $baselinePath = '..\Baselines\Host\Get-ADSHWSMANEndpointPermissions.csv'

        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHWSMANEndpointPermissions | Where-Object { $_.Access -eq "AccessAllowed" } | 
                Select-Object -Property Identity -Unique | export-csv -path $baselinePath
        }

        $WSMANIdenityAllowed = $WSMANEndpointPermissions | Where-Object { $_.Access -eq "AccessAllowed" } | Select-Object -Property Identity -Unique

        $reference = Import-Csv -Path $baselinePath | Select-Object -Property Identity -Unique

        ## 5.2.1
        #It -name "5.2.1 Number of Identities with WSMAN Endpoint Permissions on the DC [$ComputerName]" {
        #    @($WSMANIdenityAllowed).Count | Should Be @($reference).Count
        #}
        #
        ## 5.2.2
        #It -name "5.2.2 Missing WSMAN Endpoint Identities on the DC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $WSMANIdenityAllowed -Property Identity -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

        # 5.2.3
        It -name "5.2.3 Has WinRM access permission on a domain controller [$ComputerName]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $WSMANIdenityAllowed -Property Identity -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context
}#Describe

# 6.0
Describe "Has User Right" -Fixture {
    
    $SecurityRights = ('SeTcbPrivilege','SeInteractiveLogonRight','SeRemoteInteractiveLogonRight','SeBackupPrivilege',
                                'SeSystemtimePrivilege','SeCreateTokenPrivilege','SeDebugPrivilege',
                                'SeEnableDelegationPrivilege','SeLoadDriverPrivilege','SeBatchLogonRight',
                                'SeServiceLogonRight','SeSecurityPrivilege','SeSystemEnvironmentPrivilege',
                                'SeManageVolumePrivilege','SeRestorePrivilege','SeSyncAgentPrivilege','SeRelabelPrivilege',
                                'SeTakeOwnershipPrivilege')

    Foreach ($SecurityRight in $SecurityRights)
    {
        # 6.1
        Context "6.1 Has User Right [${SecurityRight}] on the DC [$ComputerName]" {
        
            $IdentityRights = Get-ADSHLocalRight -SecurityRight $SecurityRight
        
            $baselinePath = "..\Baselines\Host\Get-ADSHLocalRight-${SecurityRight}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHLocalRight -SecurityRight $SecurityRight | Select-Object -Property Identity | Export-Csv -Path $baselinePath
            }

            $reference = Import-Csv -Path $baselinePath
            if (! $IdentityRights){$IdentityRights = ''}
            if (! $reference){$reference = ''}
        
            ## 6.1.1
            #It -name "6.1.1 Number of Identity rights for [${SecurityRight}] on the DC [$ComputerName]" {
            #    @($IdentityRights).Count | Should Be @($reference).Count
            #}
            #
            ## 6.1.2
            #It -name "6.1.2 Missing Identity rights for [${SecurityRight}] on the DC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $IdentityRights -Property Identity -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' }  | Select -expandproperty Identity) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 6.1.3
            It -name "6.1.2 Extra   Identity rights for [${SecurityRight}] on the DC [$ComputerName]" -test {
                $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $IdentityRights -Property Identity -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
                $compare | should BeNullOrEmpty 
            }

        }#Context
    }
}#Describe

# 7.0
Describe "Has User Write Permission on Registry" -Fixture {
    
    $RegistryKeys = ('HKLM:\SAM','HKLM:\SECURITY','HKLM:\SOFTWARE','HKLM:\SYSTEM','HKCC:','HKCU:','HKU:\.DEFAULT')
    
    # This is the list of Tier0 RegistryRights * not yet confirmed
    $tier0 = 'WriteKey','SetValue','FullControl','CreateSubKey','ChangePermissions'

    Foreach ($Key in $RegistryKeys)
    {
        $KeyRights = Get-ADSHRegKeyAccess -Key $Key
        $i=0    

        Foreach ($keyRight in $tier0)
        {
            $i++

            # 6.1
            Context "7.1 Has Write permission [${keyRight}] on key [${Key}] on the DC [$ComputerName]" {
                
                $KeyRights = $KeyRights | Where-Object { $_.RegistryRights -eq $KeyRight }
                
                $Name = $key -replace ':|\\','-'
                $baselinePath = "..\Baselines\Host\Registry\Get-RegKeyAccess-${KeyRight}-${Name}.csv"

                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHRegKeyAccess -Key $Key  | Where-Object { $_.RegistryRights -eq $KeyRight } | Export-Csv -Path $baselinePath
                }

                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $KeyRights){$KeyRights = ''}
                if (! $reference){$reference = ''}
        
                ## 7.1.1
                #It -name "7.1.1 Number of Write permissions [${keyRight}] on key [${Key}] on the DC [$ComputerName]" {
                #    @($KeyRights).Count | Should Be @($reference).Count
                #}
                #
                ## 7.1.2
                #It -name "7.1.2 Missing Write permissions [${keyRight}] on key [${Key}] on the DC [$ComputerName]" -test {
                #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $KeyRights -Property IdentityReference -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
                #    $compare | should BeNullOrEmpty 
                #}

                # 7.1.3
                It -name "7.1.2 Extra   Write permissions [${keyRight}] on key [${Key}] on the DC [$ComputerName]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $KeyRights -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Context
    }#Foreach(KeyRight)
    }#Foreach(Key)
}#Describe


# 8.0
Describe "Tier0 Account has logged on" -Fixture {

    $Tier0GroupsForest = ('Enterprise Admins','Schema Admins')
    $Tier0GroupsDomain = ('Domain Admins','Backup Operators','Administrators')
      
    Write-Warning -Message "This can take some time to scan Security logs."
    #$DCs = Get-ADSHDomainController | Foreach Hostname
    $Tier0Identity = Get-ADSHTier0Principle -Tier0GroupsDomain $Tier0GroupsDomain -Tier0GroupsForest $Tier0GroupsForest 
    $LogonEvents =  Get-ADSHTier0Login -Tier0Identity $Tier0Identity.Name | # Where {$_.DomainController -NotIn $DCs} |
                            Group-Object -AsHashTable -AsString -Property ComputerName

    Foreach ( $Logon in $LogonEvents.Keys )
    {

        $Logons = ($LogonEvents["$logon"] | Select-Object -ExpandProperty User -Unique) -join ','

        # 8.1
        Context "8.1 Tier0 Account has logged on [$Logons]" {
        
            $reference = ''

            # 8.1.1
            It -name "8.1.1 Tier0 Account has logged on [$Logons] [$ComputerName]" -test {
                $compare = Compare-Object -ReferenceObject $reference -DifferenceObject $logon  -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty InputObject
                $compare | should BeNullOrEmpty 
            }

        }#Context
    }
}#Describe


}#ModuleScope

