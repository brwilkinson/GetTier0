#requires -version 2.0

Function Get-ADSHAdministratorAccount {

    Get-ADGroup -Identity 'Domain Admins' | Get-ADGroupMember -Recursive | Where-Object { $_.SID -like 'S-1-5-*-500' }

}


Function Get-ADSHAdministratorAccountTranspose {
Param (
    [parameter(valuefrompipelinebypropertyname=$true)]
    [Object[]]$Identity
)

end {
    switch ($Input)
    {
        {$_.Identity -eq 'CN=BRW,CN=Users,DC=XYZ123,DC=com' -or $_.Identity -eq 'CN=BRW,CN=Users,DC=AA123,DC=XYZ123,DC=com'}{
                
                $DN = (Get-ADSHAdministratorAccount).distinguishedName

                New-Object -TypeName Psobject -Property @{Identity = $DN}
                
                Write-Verbose -Message "Administrator account was: CN=BRW,CN=Users,DC=CONTOSO,DC=com, now $DN" -verbose
            }
        Default { $_ }
    }
}#End
}#Get-ADSHAdministratorAccountTranspose



# Find the ACES on an Object based on DistinguishedName
Function Get-ADSHDomainAccess {
[cmdletbinding()]
param (
    [parameter(valuefrompipelinebypropertyname=$true,
               valuefrompipeline=$true)]
    [String[]]$DistinguishedName
)

begin {
        Try {
            # This has moved to the main script
            # now create the GC: Drive in the invoke-IndomainTests.ps1, so don't need it here.
            #$RootDomain = Get-ADSHDomainRoot
            #$PDC = $RootDomain.PDCEmulator
            #Import-Module -name ActiveDirectory
            #$GC = New-PSDrive -PSProvider ActiveDirectory -Name GC -Root "" -Server "${PDC}:3268" -ErrorAction SilentlyContinue
        }
        Catch {
            Write-Warning $_
            continue
        }
}#Begin
Process {
        $DistinguishedName | ForEach-Object {
            try {
            Push-Location
            Set-Location -Path GC:\
            Write-Verbose -Message $_
            $item = Get-Item -Path $_
            Get-Acl -Path $item.distinguishedname | ForEach-Object { $_.Access } | ForEach-Object {
            
                # Convert the SIDS to Identities
                if ($_.IdentityReference -match '^s-')
                {
                    $Identity = ($_.IdentityReference).value
                    $IdentityReference = Get-ADGroup  -Filter * | Where-Object {$_.SID -eq  $Identity} | 
                        ForEach-Object { $_.Name } | ForEach-Object { $_.Value }
                }
                else
                {
                    $IdentityReference =($_.IdentityReference).value
                }
            
                $_ | Select-Object -Property @{n="DistinguishedName";e={$item.distinguishedname}}, 
                                        @{n="IdentityReference";e={$IdentityReference}},ActiveDirectoryRights,AccessControlType
        
                }#Foreach-Object(ACL)
            
            }
            catch {
                write-warning $_
            }
            finally {
                Pop-Location
            }
        }#Foreach-Object(DistinguishedName)
}#Process
End {
    #Remove-PSDrive -Name GC -ErrorAction SilentlyContinue
}#End
}#Get-ADSHDomainAccess  -SearchBase ('CN=Builtin,' + $DN)


# Find the ACES on an Domain Controller Object
function Get-ADSHDomainControllerObjectAccess {
param (
    [String[]]$Name = '*'
    )

    Get-ADDomainController -Filter * | 
        Select-Object @{Name= 'DistinguishedName' ; Expression = { $_.ComputerObjectDN }} | 
            Get-ADSHDomainAccess
    
}


function Get-ADSHDomainObject {
[cmdletbinding()]
Param (
    [String[]]$Name,
    [String]$Domain
)

   $DN = (Get-ADDomain -Server $env:COMPUTERNAME | ForEach-Object { $_.DistinguishedName })

   $Name | ForEach-Object {

        $container = $_

        if ($container -eq $null -or $Container -eq "")
        {
            $Path = $DN   
        }
        else
        {
            $Path = $container, $DN -join ','
        }
        
        Write-Verbose -Message $Path
        New-Object -TypeName Psobject -Property @{'DistinguishedName'=$Path}

   }#Foreach-Object($ContainerName)
}


# Find the FQDN on a single Object based on the shortName, then call Get-ADSHDomainAccess
Function Get-ADSHDomainObjectAccess {
[cmdletbinding()]
param (
    [String[]]$Name = ('CN=Users','OU=Domain Controllers','CN=AdminSDHolder,CN=System','OU=Domain Controllers','CN=Computers','CN=Builtin')
)

        $Name | ForEach-Object {

            Get-ADSHDomainObject -Name $_ -ErrorAction SilentlyContinue | Get-ADSHDomainAccess

        }#Name


}#Get-ADSHDomainContainerAccess


# Find the FQDN of all child objects within single container based on the shortName, then call Get-ADSHDomainAccess
Function Get-ADSHDomainChildObjectAccess {
[cmdletbinding()]
param (
    [String[]]$Name = ('CN=Managed Service Accounts','OU=Domain Controllers')
)

    $Name | ForEach-Object {
        
        $Path = Get-ADSHDomainObject -Name $_ 
            
        Get-ChildItem -Path AD:\$($Path.distinguishedName) | Get-ADSHDomainAccess

    }#Name

}#Get-ADSHDomainContainerAccess


Function Get-ADSHGroupMember {
[cmdletbinding()]
param (
    [String[]]$Name = ('Administrators','Domain Admins','Schema Admins','Enterprise Admins','Domain Users','Server Operators','Print Operators','Backup Operators','Account Operators')
    )

    $Name | ForEach-Object {
        $Identity = $_

        Get-ADGroup -Identity $Identity -Verbose | Get-ADGroupMember | ForEach-Object {

            New-Object -TypeName psobject -Property @{
                Group    = $Identity
                Identity = $_.distinguishedName
                }
        }
    }#Foreach-object($Name)
}#Get-ADSHGroupMember


# Find any Group Policy Objects linked to a DistinguishedName
function  Get-ADSHGroupPolicy {
Param (
        [Parameter(valuefrompipelinebypropertyname=$true)]
        [String[]]$DistinguishedName
        )

Process {    
    
    $DistinguishedName | Foreach-Object {
        
        $IdentityInfo = Get-ADObject -Identity $_ -Properties gplink 

        if ($IdentityInfo.gplink -ne $null)
        {
            ( $IdentityInfo.gplink -split '\]\[' ) | foreach-object {

                    $clean = $_.trim( "\[|\]" )
                    
                    $PolicyDN = ($clean.Trim("LDAP://") -split ";")[0]

                    $ADObject = Get-ADObject -Identity $PolicyDN

                    Get-GPO -Guid $ADObject.Name | Select-Object * #DisplayName,ID,Owner,DomainName,Path
        
            }#Foreach-Object(GP)
        }
        else
        {
            Write-Warning -Message "No GPO linked to $_"
        }
    }#Foreach-Object(DistinguishedName)

}#Process
}#Get-ADSHDCGroupPolicy


# Find any Group Policy Objects linked to a Container in AD
function Get-ADSHDomainControllerGroupPolicyAccess {
param (
    [Parameter(valuefrompipeline=$true)]
    [Object[]]$PolicyObject
    )

Process {    
    $PolicyObject | Foreach-object {
        $_ | Select-Object -Property *,@{Name='DistinguishedName';Expression={$_.Path}} | Get-ADSHDomainAccess
     }
}#Process
}#Get-ADSHDomainControllerGroupPolicyAccess

# Find any Group Policy Objects linked to a Container in AD
function  Get-ADSHDomainControllerGroupPolicy {
Param (
        [String[]]$ContainerName = ('OU=Domain Controllers','CN=Users','CN=Builtin')
        )
    
    $ContainerName | ForEach-Object {
        
        Get-ADSHDomainObject -Name $_ | Get-ADSHGroupPolicy
    
    }#ContainerName
}


# Find any Group Policy Objects linked to a Container that contains Tier0 account
function  Get-ADSHDCTier0GroupPolicyAccess {

    Get-ADSHTier0PrincipleParentDistinguishedName | Get-ADSHGroupPolicy
}



Function Get-ADSHTier0PrincipleGroupObjectAccess {
param (
        [String[]]$Tier0GroupsForest = ('Enterprise Admins','Schema Admins'),
        [String[]]$Tier0GroupsDomain = ('Domain Admins','Backup Operators','Administrators')
        )

    Get-ADSHTier0Principle -Tier0GroupsDomain $Tier0GroupsDomain -Tier0GroupsForest $Tier0GroupsForest | 
        Get-ADSHGroupPolicy | Get-ADSHDomainAccess


}


## Find all $Tier0 accounts based on group membership
#function Get-ADSHGroup {
#param (
#        [Parameter(valuefrompipelinebypropertyName=$true)]
#        [String[]]$DistinguishedName
#        )
#End {
#        $Input | ForEach-Object {
#
#            Get-ADPrincipalGroupMembership -Identity $_ | 
#                Where {$_.Name -notin ('Domain Admins','Enterprise Admins','Schema Admins','Backup Operators','Administrators','Domain Users')}
#        
#        } | Select -Unique
#}#Process
#}#Get-ADSHGroup


Function Get-ADSHParentObjectDistinguishedName {
param (
        [Parameter(valuefrompipelinebypropertyName=$true)]
        [Object[]]$DistinguishedName
        )
Begin {
    # now create the GC: Drive in the invoke-IndomainTests.ps1, so don't need it here.
    #$RootDomain = Get-ADSHDomainRoot
    #$PDC = $RootDomain.PDCEmulator
    #Import-Module -name ActiveDirectory
    #$GC = New-PSDrive -PSProvider ActiveDirectory -Name GC -Root "" -Server "${PDC}:3268"  -ErrorAction SilentlyContinue
}
Process{

    $DistinguishedName | ForEach-Object {
        
        Try {
            Push-Location
            Set-Location -Path GC:\
            Write-Verbose -Message $_
            $Identity = Get-ADObject -Identity $_
            Write-Verbose -Message $Identity
            $PsParentPath = Get-Item -Path "GC:\$($Identity.DistinguishedName)" | Select-Object PSParentPath
            Get-Item -Path $PSParentPath.PSParentPath | Select-Object DistinguishedName
           }
           catch {
               write-warning $_
           }
           finally {
                Pop-Location
           }

    }#Foreach-Object(DistinguishedName)
}#Process
End {
    #Remove-PSDrive -Name GC -ErrorAction SilentlyContinue
}
}#Get-ADSHParentObject

# Find the unique OUs where the DC's located
Function Get-ADSHDomainControllerParentDistinguishedName {

    Get-ADDomainController -Filter * | Select-Object @{Name='DistinguishedName';Expression={$_.ComputerObjectDN}} | 
        Get-ADSHParentObjectDistinguishedName | Select-Object -Property DistinguishedName -Unique
}


# Find the unique OUs where the Tier0 Accounts are located
Function Get-ADSHTier0PrincipleParentDistinguishedName {
param (
        [String[]]$Tier0GroupsForest = ('Enterprise Admins','Schema Admins'),
        [String[]]$Tier0GroupsDomain = ('Domain Admins','Backup Operators','Administrators')
        )

    Get-ADSHTier0Principle -Tier0GroupsDomain $Tier0GroupsDomain -Tier0GroupsForest $Tier0GroupsForest | 
        Get-ADSHParentObjectDistinguishedName | Select-Object -Property DistinguishedName -Unique

}

<#
Name                                 GroupScope GroupCategory SID         
----                                 ---------- ------------- ---         
Server Operators                    DomainLocal      Security S-1-5-32-549
Account Operators                   DomainLocal      Security S-1-5-32-548
Incoming Forest Trust Builders      DomainLocal      Security S-1-5-32-557
Terminal Server License Servers     DomainLocal      Security S-1-5-32-561
Pre-Windows 2000 Compatible Access  DomainLocal      Security S-1-5-32-554
Windows Authorization Access Group  DomainLocal      Security S-1-5-32-560
Administrators                      DomainLocal      Security S-1-5-32-544
Users                               DomainLocal      Security S-1-5-32-545
Guests                              DomainLocal      Security S-1-5-32-546
Print Operators                     DomainLocal      Security S-1-5-32-550
Backup Operators                    DomainLocal      Security S-1-5-32-551
Replicator                          DomainLocal      Security S-1-5-32-552
Remote Desktop Users                DomainLocal      Security S-1-5-32-555
Network Configuration Operators     DomainLocal      Security S-1-5-32-556
Performance Monitor Users           DomainLocal      Security S-1-5-32-558
Performance Log Users               DomainLocal      Security S-1-5-32-559
Distributed COM Users               DomainLocal      Security S-1-5-32-562
IIS_IUSRS                           DomainLocal      Security S-1-5-32-568
Cryptographic Operators             DomainLocal      Security S-1-5-32-569
Event Log Readers                   DomainLocal      Security S-1-5-32-573
Certificate Service DCOM Access     DomainLocal      Security S-1-5-32-574
RDS Remote Access Servers           DomainLocal      Security S-1-5-32-575
RDS Endpoint Servers                DomainLocal      Security S-1-5-32-576
RDS Management Servers              DomainLocal      Security S-1-5-32-577
Hyper-V Administrators              DomainLocal      Security S-1-5-32-578
Access Control Assistance Operators DomainLocal      Security S-1-5-32-579
Remote Management Users             DomainLocal      Security S-1-5-32-580
#>

#Get-ADUser -Filter * | where { $_.sid -match 'S-1-5-32-544' }