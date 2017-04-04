#Requires -Module Pester

<#
Set-Location -Path F:\Project\Tests
..\Scripts\Invoke-DomainTests.ps1
..\Scripts\Invoke-DomainTestsParallel.ps1
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
    $ModuleName = Import-Module -Name .\DirectoryControlTests.psm1 -Verbose -PassThru
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

if ($RootDomain.DistinguishedName -eq $DomainName.DistinguishedName)
{
    
    Write-Warning -Message "Using Root Domain Baselines"
    $Path = "..\Baselines\Domain-Root"
}
else
{
    Write-Warning -Message "Using Child Domain Baselines"
    $Path = "..\Baselines\Domain"
}

if (-not (Test-Path -Path $Path))
{
    New-Item -Path $Path -ItemType Directory
}

# 1.0
Describe "Principal has write permission on AD Container" -Fixture {

    $Containers = ('CN=Users','OU=Domain Controllers','CN=AdminSDHolder,CN=System','CN=System',
                    'CN=Computers','CN=Builtin','')
    
    if ($RootDomain.DistinguishedName -eq $DomainName.DistinguishedName)
    {
        Write-Warning -Message "Using Root Domain AD Containers"
        $Containers += ('CN=Configuration','CN=Schema,CN=Configuration','CN=Sites,CN=Configuration',
                    'CN=Services,CN=Configuration','CN=WellKnown Security Principals,CN=Configuration',
                    'CN=Public Key Services,CN=Services,CN=Configuration')
    }
    
    <#
    Foreach ($Container in $Containers)
    {
        # 1.1
        Context "1.1 Identity Access on [Domain Container] on the PDC [$ComputerName]" {
        
            $DomainContainerAccess = Get-ADSHDomainObjectAccess -Name $Container

            $baselinePath = "$Path\1.1Get-ADSHDomainObjectAccess-Container-${Container}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHDomainObjectAccess -Name $Container | select -Property IdentityReference -Unique | export-csv -notypeinformation -path $baselinePath
            }

            $ContainerIdentities = $DomainContainerAccess | Select -Property IdentityReference -Unique
            $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain

            ## 1.1.1
            #It -name "1.1.1 Number of Identity Access on [Domain Container] [${Container}] on PDC [$ComputerName]" -test {
            #    @($ContainerIdentities).Count | Should Be @($reference).Count
            #}

            ## 1.1.2
            #It -name "1.1.2 Missing Identity Access on [Domain Container] [${Container}] on PDC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $ContainerIdentities -Property IdentityReference -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 1.1.3
            #It -name "1.1.3 Principal has write permission on [${Container}] [$($DomainName.NetBIOSName)]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $ContainerIdentities -Property IdentityReference -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '=>' } | Select -expandproperty IdentityReference) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

        }#Context
        
    }#Foreach(Container)
    #>
    

    # 1.2
    Context "1.2 Principal has write permission on [Domain Container]" {

        # This is the list of Tier0 DirectoryControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $DomainAccountAccess = Get-ADSHDomainObjectAccess -Name $Containers

        foreach ($DirectoryAccessRight in $Tier0) 
        {
            Foreach ($Container in $Containers)
            {
                $DN = Get-ADSHDomainObject -Name $Container
                
                $Access = $DomainAccountAccess | Where-Object { $_.DistinguishedName -EQ $DN.DistinguishedName -and $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }
                    
                $baselinepath = "$Path\1.2Get-ADSHDomainObjectAccessDistinct-Container-${Container}-DirectoryAccessRight-${DirectoryAccessRight}.csv"

                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHDomainObjectAccess -Name $Container | 
                        Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                        #Select -Property IdentityReference -Unique
                        export-csv -notypeinformation -Path $baselinepath
                }              
                
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
                
                ## 1.2.1
                #It -name "1.2.1 Missing Identities with [${DirectoryAccessRight}] for IdentityReference on [Domain Container] [${Container}] on PDC [${ComputerName}]" -test {
                #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
                #    $compare | should BeNullOrEmpty 
                #}

                # 1.2.2
                It -name "1.2.2 Principal has write permission [${DirectoryAccessRight}] on [$Container] [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Container)
        }#Foreach(Tier0)
    }#Context

    # 1.3
    Context "1.3 Principal has write permission on [non default Domain Container with Tier0 Accounts]" {

        # This is the list of Tier0 DirectoryControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $Tier0GroupsForest = ('Enterprise Admins','Schema Admins')
        $Tier0GroupsDomain = ('Domain Admins','Backup Operators','Administrators')

        $Tier0PrincipleParentDistinguishedName = Get-ADSHTier0PrincipleParentDistinguishedName -Tier0GroupsForest $Tier0GroupsForest -Tier0GroupsDomain $Tier0GroupsDomain
        $AlreadyCheckedContainers = Get-ADSHDomainObject -Name $Containers
        $Newtier0ContainertoCheck = Compare-Object -ReferenceObject $AlreadyCheckedContainers -DifferenceObject $Tier0PrincipleParentDistinguishedName -Property DistinguishedName |
            where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty DistinguishedName

        # Use common baseline permission from the default 'CN=Users Controllers' OU.
        $Users = 'CN=Users'

        foreach ($DirectoryAccessRight in $Tier0) 
        {
            Foreach ($Container in $Newtier0ContainertoCheck)
            {
                $DomainAccountAccess = Get-ADSHDomainAccess -DistinguishedName $Container
                
                $Access = $DomainAccountAccess | Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }

                $baselinePath = "$Path\1.3Get-ADSHDomainObjectAccessDistinct-Container-${Users}-DirectoryAccessRight-${DirectoryAccessRight}.csv"
                
                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHDomainAccess -DistinguishedName $Container | 
                        Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                        export-csv -notypeinformation -Path $baselinepath
                }
                
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
                
                # 1.3.1
                It -name "1.3.1 Principal has write permission [${DirectoryAccessRight}] on [Tier0 Domain Container] [$Container] [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Container)
        }#Foreach(Tier0)
    }#Context

    # 1.4
    Context "1.4 Principal has write permission on [Group Policy attached to Domain Controller]" {

        # This is the list of Tier0 DirectoryControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $DomainControllerGroupPolicy = Get-ADSHDomainControllerGroupPolicy

        foreach ($DirectoryAccessRight in $Tier0) 
        {
            Foreach ($Policy in $DomainControllerGroupPolicy)
            {
                $PolicyDisplayName = $Policy.DisplayName
                
                $PolicyAccess = Get-ADSHDomainControllerGroupPolicyAccess -PolicyObject $Policy
                
                $Access = $PolicyAccess | Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }
                    
                $baselinepath = "$Path\1.4Get-ADSHDomainControllerGroupPolicyAccess-Policy-${PolicyDisplayName}-DirectoryAccessRight-${DirectoryAccessRight}.csv"

                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHDomainControllerGroupPolicyAccess -PolicyObject $Policy | 
                        Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                        #Select -Property IdentityReference -Unique
                        export-csv -notypeinformation -Path $baselinepath
                }           
                
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}

                # 1.4.1
                It -name "1.4.1 Principal has write permission [${DirectoryAccessRight}] to [Group Policy] [${PolicyDisplayName}] [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Container)
        }#Foreach(Tier0)
    }#Context

}#Describe

# 2.0
Describe "Principal has write permission on [Builtin/Group Account]" -Fixture {

    $Accounts = ('CN=Replicator,CN=Builtin','CN=Backup Operators,CN=Builtin','CN=Print Operators,CN=Builtin',
                'CN=Server Operators,CN=Builtin','CN=Account Operators,CN=Builtin','CN=Administrators,CN=Builtin')
    
    if ($RootDomain.DistinguishedName -eq $DomainName.DistinguishedName)
    {
        Write-Warning -Message "Using Root Domain Buitin Groups"
        $Accounts += ('CN=Enterprise Admins,CN=Users','CN=Schema Admins,CN=Users')
    }
    
    
    Foreach ($Account in $Accounts)
    {
        # 2.1
        Context "2.1 Principal has write permission on [Builtin/Group Account]" {
        
            $DomainAccountAccess = Get-ADSHDomainObjectAccess -Name $Account

            $baselinePath = "$Path\2.1Get-ADSHDomainObjectAccess-Account-${Account}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHDomainObjectAccess -Name $Account | Select-Object -Property IdentityReference -Unique | export-csv -notypeinformation -path $baselinePath
            }

            $AccountIdentities = $DomainAccountAccess | Select-Object -Property IdentityReference -Unique
            $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain

            ## 2.1.1
            #It -name "2.1.1 Number of Identity Access on [Builtin/Group Account] [${Account}] on PDC [$ComputerName]" {
            #    @($AccountIdentities).Count | Should Be @($reference).Count
            #}

            ## 2.1.2
            #It -name "2.1.2 Missing Identity Access on [Builtin/Group Account] [${Account}] on PDC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property IdentityReference -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 2.1.3
            It -name "2.1.3 Principal has write permission on [Builtin/Group Account] [${Account}] [$($DomainName.NetBIOSName)]" -test {
                $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property IdentityReference -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                $compare | should BeNullOrEmpty 
            }

        }#Context(2.1)
    }#Foreach(Account)

    # 2.2
    Context "2.2 Principal has write permission on [Builtin/Group Account]" {

        # This is the list of Tier0 ServiceControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $DomainAccountAccess = Get-ADSHDomainObjectAccess -Name $Accounts
        
        foreach ($DirectoryAccessRight in $Tier0) 
        {
            Foreach ($Account in $Accounts)
            {
                $DN = Get-ADSHDomainObject -Name $Account
                
                $Access = $DomainAccountAccess | Where-Object { $_.DistinguishedName -EQ $DN.DistinguishedName -and $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }
                
                $baselinepath = "$Path\2.2Get-ADSHDomainObjectAccessDistinct-Account-${Account}-DirectoryAccessRight-${DirectoryAccessRight}.csv"
        
                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHDomainObjectAccess -Name $Account | 
                        Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                        #Select -Property IdentityReference -Unique
                        export-csv -notypeinformation -Path $baselinepath
                }
                
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
                
                ## 2.2.1
                #It -name "2.2.1 Missing Identities with [${DirectoryAccessRight}] for IdentityReference on [Builtin/Group Account] [${Account}] on PDC [${ComputerName}]" -test {
                #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
                #    $compare | should BeNullOrEmpty 
                #}

                # 2.2.2
                It -name "2.2.1 Principal has write permission [${DirectoryAccessRight}] on [Builtin/Group Account] [$Account] [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Account)
        }#Foreach(Tier0)
    }#Context
}#Describe

# 3.0
Describe "Principal has write permission on AD Container" -Fixture {

    $Accounts = ('CN=Domain Computers,CN=Users',
                    'CN=Domain Users,CN=Users','CN=Domain Admins,CN=Users')
    
    if ($OSVersion.Major -ge 6 -and $OSVersion.Minor -ge 2)
    {
        $Accounts += ('CN=Cloneable Domain Controllers,CN=Users')
    }
    
    
    Foreach ($Account in $Accounts)
    {
        # 3.1
        Context "3.1 Principal has write permission on AD Container" {
        
            $DomainAccountAccess = Get-ADSHDomainObjectAccess -Name $Account

            $baselinePath = "$Path\3.1Get-ADSHDomainObjectAccess-Account-${Account}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHDomainObjectAccess -Name $Account | Select-Object -Property IdentityReference -Unique | export-csv -notypeinformation -path $baselinePath
            }

            $AccountIdentities = $DomainAccountAccess | Select-Object -Property IdentityReference -Unique
            $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain

            ## 3.1.1
            #It -name "3.1.1 Number of Identity Access on [AD Container] [${Account}] on DC [$ComputerName]" {
            #    @($AccountIdentities).Count | Should Be @($reference).Count
            #}

            ## 3.1.2
            #It -name "3.1.2 Missing Identity Access on [AD Container] [${Account}] on DC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property IdentityReference -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 3.1.3
            It -name "3.1.3 Principal has write permission on [AD Container] [${Account}] [$($DomainName.NetBIOSName)]" -test {
                $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property IdentityReference -IncludeEqual | 
                    where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                $compare | should BeNullOrEmpty 
            }

        }#Context
    }#Foreach(Container)

    # 3.2
    Context "3.2 Principal has write permission on AD Container" {

        # This is the list of Tier0 ServiceControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $DomainAccountAccess = Get-ADSHDomainObjectAccess -Name $Accounts
        
        foreach ($DirectoryAccessRight in $Tier0) 
        {
            Foreach ($Container in $Accounts)
            {
                $DN = Get-ADSHDomainObject -Name $Container
                
                $Access = $DomainAccountAccess | Where-Object { $_.DistinguishedName -EQ $DN.DistinguishedName -and $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }

                $baselinepath = "$Path\3.2Get-ADSHDomainObjectAccess-Container-${Container}-DirectoryAccessRight-${DirectoryAccessRight}.csv"

                # capturebaseline
                if ($CaptureBaseline)
                {
                    Get-ADSHDomainObjectAccess -Name $Container | 
                        Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                        #Select -Property IdentityReference -Unique
                        export-csv -notypeinformation -Path $baselinepath
                }
                    
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain 
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
                
                ## 3.2.1
                #It -name "3.2.1 Missing Identities with [${DirectoryAccessRight}] for IdentityReference on [AD Container] [${Container}] on PDC [${ComputerName}]" -test {
                #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
                #    $compare | should BeNullOrEmpty 
                #}

                # 3.2.2
                It -name "3.2.1 Principal has write permission [${DirectoryAccessRight}] on [AD Container] [$Container] [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Account)
        }#Foreach(Tier0)

    }#Context
}#Describe


# 4.0
Describe "Principal is member of Tier0 Group" -Fixture {

    $Accounts = ('Domain Admins','Server Operators',
                'Print Operators','Backup Operators','Administrators','Account Operators')
    
    if ($RootDomain.DistinguishedName -eq $DomainName.DistinguishedName)
    {
        Write-Warning -Message "Using Root Domain Tier0 Groups"
        $Accounts += ('Schema Admins','Enterprise Admins')
    }
    
    Foreach ($Account in $Accounts)
    {
        # 4.1
        Context "4.1 [Account Member] Access on the DC [$ComputerName]" {
        
            $AccountMemberAccess = Get-ADSHGroupMember -Name $Account

            $baselinePath = "$Path\4.1Get-ADSHGroupMember-Account-${Account}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                Get-ADSHGroupMember -Name $Account | Select-Object Identity -Unique | export-csv -notypeinformation -path $baselinePath
            }

            $AccountIdentities = $AccountMemberAccess | Select-Object -Property Identity -Unique
            $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
            # Update the Administrator account from the baselines to the correct Account Name
            $reference = $reference | Get-ADSHAdministratorAccountTranspose 
            
            if (! $AccountIdentities){$AccountIdentities = ''}
            if (! $reference){$reference = ''}

            ## 4.1.1
            #It -name "4.1.1 Number of [Account Member] on Account [${Account}] on DC [$ComputerName]" {
            #    @($AccountIdentities).Count | Should Be @($reference).Count
            #}

            ## 4.1.2
            #It -name "4.1.2 Missing [Account Member] on Account [${Account}] on DC [$ComputerName]" -test {
            #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property Identity -IncludeEqual | 
            #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Identity) -join ';'
            #    $compare | should BeNullOrEmpty 
            #}

            # 4.1.3
            It -name "4.1.3 Principal is member of [${Account}] [$($DomainName.NetBIOSName)]" -test {
                $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountIdentities -Property Identity -IncludeEqual | 
                    Where-Object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Identity) -join ';'
                $compare | should BeNullOrEmpty 
            }

        }#Context
    }#Foreach(Container)

    # 4.2
    Context "4.2 Principal is member of Administrators group" {
        
        $Administrator = Get-ADSHAdministratorAccount

        $baselinePath = "$Path\4.2Get-ADSHAdministratorAccount.csv"

        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHAdministratorAccount | Select-Object Name -Unique | Export-Csv -NoTypeInformation -path $baselinePath
        }

        $AccountName = $Administrator | Select-Object -Property Name -Unique
        $reference = Import-Csv -Path $baselinePath
            
        if (! $AccountName){$AccountName = ''}
        if (! $reference){$reference = ''}

        ## 4.2.1
        #It -name "4.2.1 Number of [Account is Administrator] on PDC [$ComputerName]" {
        #    @($AccountName).Count | Should Be @($reference).Count
        #}

        ## 4.2.2
        #It -name "4.2.2 Missing [Account is Administrator] on PDC [$ComputerName]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountName -Property Name -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty Name) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

        # 4.2.3
        It -name "4.2.3 Principal is member of Administrators group [$($DomainName.NetBIOSName)]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $AccountName -Property Name -IncludeEqual | 
                where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty Name) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context

       
}#Describe

# 5.0
Describe "Principal has write permission on Domain Controller Machine Objects" -Fixture {

    $DomainControllerObjectAccess = Get-ADSHDomainControllerObjectAccess

    # 5.1
    Context "5.1 Principal has write permission on Domain Controller Machine Objects" {
        
        $baselinePath = "$Path\5.1Get-ADSHDomainControllerObjectAccess.csv"

        # capturebaseline
        if ($CaptureBaseline)
        {
            Get-ADSHDomainControllerObjectAccess | Select-Object -property IdentityReference -Unique | 
                export-csv -notypeinformation -Path $baselinePath
        }

        $DomainControllerObjectAccessIdentities = $DomainControllerObjectAccess | Select-Object -Property IdentityReference -Unique
        $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain

        ## 5.1.1
        #It -name "5.1.1 Number of Identity Access on [Domain Controller Object] on PDC [$ComputerName]" {
        #    @($DomainControllerObjectAccessIdentities).Count | Should Be @($reference).Count
        #}

        ## 5.1.2
        #It -name "5.1.2 Missing Identity Access on [Domain Controller Object] on PDC [$ComputerName] [$($DomainName.NetBIOSName)]" -test {
        #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $DomainControllerObjectAccessIdentities -Property IdentityReference -IncludeEqual | 
        #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
        #    $compare | should BeNullOrEmpty 
        #}

        # 5.1.3
        It -name "5.1.3 Principal has write permission on Domain Controller Machine Objects [$($DomainName.NetBIOSName)]" -test {
            $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $DomainControllerObjectAccessIdentities -Property IdentityReference -IncludeEqual | 
                Where-Object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
            $compare | should BeNullOrEmpty 
        }

    }#Context
        

    # 5.2
    Context "5.2 Principal has write permission on Domain Controller Machine Objects" {

        # This is the list of Tier0 ServiceControlRights
        $tier0 = 'WriteProperty','WriteDacl','WriteOwner','GenericAll','GenericWrite'

        $DCHash = $DomainControllerObjectAccess | Group-Object -Property DistinguishedName -AsHashTable -AsString

        foreach ($DirectoryAccessRight in $Tier0) 
        {
            $baselinepath = "$Path\5.2Get-ADSHDomainControllerObjectAccess-DirectoryAccessRight-${DirectoryAccessRight}.csv"

            # capturebaseline
            if ($CaptureBaseline)
            {
                # Use the baseline from any single DC, permission should be the same on all DC's
                $Single = $DCHash.keys | Select-Object -First 1
                $DCHash[$Single] | Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" } |
                    #Select -Property IdentityReference -Unique
                    export-csv -notypeinformation -Path $baselinepath
            }

            Foreach ($DC in $DCHash.keys)
            {
                $DCAccess = $DCHash[$DC]
                
                $Access = $DCAccess | Where-Object { $_.ActiveDirectoryRights -like "*${DirectoryAccessRight}*" }              
                
                $reference = Import-Csv -Path $baselinePath | Get-ADSHBaseLineDomainTranspose -CurrentDomain $DomainName -RootDomain $RootDomain
                if (! $Access){$Access = ''}
                if (! $reference){$reference = ''}
                
                ## 5.2.1
                #It -name "1.2.1 Missing Identities with [${DirectoryAccessRight}] for IdentityReference on [Domain Container] [${Container}] on PDC [${ComputerName}]" -test {
                #    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                #        where-object { $_.sideindicator -eq '<=' } | Select -expandproperty IdentityReference) -join ';'
                #    $compare | should BeNullOrEmpty 
                #}

                # 5.2.2
                It -name "1.2.1 Principal has write permission [${DirectoryAccessRight}] on Domain Controller Machine Objects [$($DomainName.NetBIOSName)]" -test {
                    $compare = (Compare-Object -ReferenceObject $reference -DifferenceObject $Access -Property IdentityReference -IncludeEqual | 
                        where-object { $_.sideindicator -eq '=>' } | Select-Object -expandproperty IdentityReference) -join ';'
                    $compare | should BeNullOrEmpty 
                }

            }#Foreach(Container)
        }#Foreach(Tier0)
    }#Context

}#Describe
}#ModuleScope
