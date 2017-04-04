#requires -version 2.0

# Find ALL of the Shares on the DC
function Get-ADSHComputerName {
[cmdletbinding()]
param()

    $env:ComputerName

}#Get-ADSHSComputerName

# Find the DC Domain, run against local machine
function Get-ADSHDomainName {
[cmdletbinding()]
param()

    Get-ADDomain -Server $env:COMPUTERNAME | 
        Select-Object Forest,NetBIOSName,DistinguishedName,PDCEmulator

}#Get-ADSHDomainName

# Find the Forest root Domain information
function Get-ADSHDomainRoot {
[cmdletbinding()]
param()

    $r = Get-ADForest | ForEach-Object { $_.RootDomain }
    Get-ADDomain -Identity $r | Select-Object Forest,NetBIOSName,DistinguishedName,PDCEmulator

}#Get-ADSHDomainName


# Find ALL of the domain controllers in the domain
function Get-ADSHDomainController {
[cmdletbinding()]
param()

    Get-ADDomainController -Filter * | Select-Object Name,HostName

}#Get-ADSHSComputerName


# Find ALL of the Shares on the DC
function Get-ADSHShare {
[cmdletbinding()]
param()
 
    Try {
        Get-WmiObject -Class Win32_share -ErrorAction Stop
    }
    Catch {
        Write-Warning $_
    }


<#
Name     Path                                 Description        
----     ----                                 -----------        
ADMIN$   C:\Windows                           Remote Admin       
C$       C:\                                  Default share      
D$       D:\                                  Default share      
F$       F:\                                  Default share      
IPC$                                          Remote IPC         
NETLOGON F:\SYSVOL\sysvol\Contoso.com\SCRIPTS Logon server share 
SYSVOL   F:\SYSVOL\sysvol                     Logon server share
#>
}#Get-ADSHShare


# Find the WSMAN Endpoint Details
Function Get-ADSHWSMANEndpoint {
Param (
    [String]$Name = '*'
    )

    Try {
        Get-PSSessionConfiguration -Name $Name -ErrorAction Stop
    }
    Catch {
        Write-Warning $_
    }

}


# Find the Registry Key Access
Function Get-ADSHRegKeyAccess {
Param (
       [String[]]$Key = ('HKLM:\SAM','HKLM:\SECURITY',
                         'HKLM:\SOFTWARE','HKLM:\SYSTEM',
                         'HKCC:','HKCU:','HKU:\.DEFAULT')
)

begin {
    $a = New-PSDrive -Name HKCC -Root 'HKEY_CURRENT_CONFIG' -PSProvider Registry
    $b = New-PSDrive -Name HKU -Root 'HKEY_USERS' -PSProvider Registry
}#begin
Process {

    $Key | ForEach-Object {

        Try {
        
            Get-ACL -Path $_ | ForEach-Object {$_.Access}

        }
        catch {
    
            Write-Warning $_
        }#Catch

    }#Foreach-Object(Key)

}#Process
end {
    Remove-PSDrive -Name HKCC
    Remove-PSDrive -Name HKU
}#End
}#Get-ADSHRegKeyAccess

<#
"CN=Enterprise Admins,CN=Users,DC=Contoso,DC=com"
"CN=Domain Admins,CN=Users,DC=AA,DC=XYZ,DC=com"
#>

# Update the domain name in DistinguishedName from the basline files 
Function Get-ADSHBaseLineDomainTranspose {
[cmdletbinding()]
param (
    [parameter(valuefrompipelinebypropertyname=$true,
               valuefrompipeline=$true)]
    [object[]]$Object,
    [String]$ChildDomainBaseline = 'AA123',
    [String]$RootDomainBaseline = 'XYZ123',
    [Object]$CurrentDomain,
    [Object]$RootDomain 
)
begin {
            $Root = "DC=$RootDomainBaseline,DC=com"
            $Child = "DC=$ChildDomainBaseline,DC=$RootDomainBaseline,DC=com"
}
Process {
    $Object | ForEach-Object {

        Switch ($_)
        {
            {$_.IdentityReference -match $Child}{
                Write-Verbose -Message ('IdentityReference: ' + $_.IdentityReference + "  CurrentDomain: " + $CurrentDomain.DistinguishedName) -Verbose
                $_.IdentityReference = ($_.IdentityReference -replace $Child,$CurrentDomain.DistinguishedName) 
                Continue
                }#IdentityReference

            {$_.IdentityReference -match $Root}{
                Write-Verbose -Message ('IdentityReference: ' + $_.IdentityReference + "  CurrentDomain: " + $CurrentDomain.DistinguishedName) -Verbose
                $_.IdentityReference = ($_.IdentityReference -replace $Root,$RootDomain.DistinguishedName)
                $_
                Continue 
                }#IdentityReference

            {$_.IdentityReference -match "$RootDomainBaseline\\"}{
                Write-Verbose -Message ('IdentityReference: ' + $_.IdentityReference + "  CurrentDomain: " + $CurrentDomain.NetBIOSName) -Verbose
                $_.IdentityReference = ($_.IdentityReference -replace "$RootDomainBaseline\\","$($RootDomain.NetBIOSName)\")
                Continue
                }#IdentityReference

            {$_.IdentityReference -match "$ChildDomainBaseline\\"}{
                Write-Verbose -Message ('IdentityReference: ' + $_.IdentityReference + "  CurrentDomain: " + $CurrentDomain.NetBIOSName) -Verbose
                $_.IdentityReference = ($_.IdentityReference -replace "$ChildDomainBaseline\\","$($CurrentDomain.NetBIOSName)\")
                Continue
                }#IdentityReference
 
            # Don't compare any DistinguishedNames, so don't need to convert.
            #{$_.DistinguishedName -match $BaseDomain}{
            #    Write-Verbose -Message ('DistinguishedName: ' + $_.DistinguishedName) -Verbose
            #    $_.DistinguishedName = ($_.DistinguishedName -replace $BaseDomain,$userDomain)
            #    }#DistinguishedName


            {$_.Identity -match $Child}{
                Write-Verbose -Message ('Identity: ' + $_.Identity + "  CurrentDomain: " + $CurrentDomain.DistinguishedName) -Verbose
                $_.Identity = ($_.Identity -replace $Child,$CurrentDomain.DistinguishedName)
                Continue
                }#Identity

            {$_.Identity -match $Root}{
                Write-Verbose -Message ('Identity: ' + $_.Identity + "  CurrentDomain: " + $CurrentDomain.DistinguishedName) -Verbose
                $_.Identity = ($_.Identity -replace $Root,$RootDomain.DistinguishedName)
                Continue 
                }#Identity

            {$_.Identity -match "$RootDomainBaseline\\"}{
                Write-Verbose -Message ('Identity: ' + $_.Identity + "  CurrentDomain: " + $CurrentDomain.NetBIOSName) -Verbose
                $_.Identity = ($_.Identity -replace "$RootDomainBaseline\\","$($RootDomain.NetBIOSName)\")
                Continue
                }#Identity

            {$_.Identity -match "$ChildDomainBaseline\\"}{
                Write-Verbose -Message ('Identity: ' + $_.Identity + "  CurrentDomain: " + $CurrentDomain.NetBIOSName) -Verbose
                $_.Identity = ($_.Identity -replace "$ChildDomainBaseline\\","$($CurrentDomain.NetBIOSName)\")
                Continue
                }#IdentityReference

        }#Switch

        $_
    }#Foreach-Object
}#Process
}#Get-ADSHBaseLineDomainTranspose


# Find the WSMAN Endpoint Permission Details
Function Get-ADSHWSMANEndpointPermissions {
[cmdletbinding()]
Param (
    [String]$Name = '*'
    )

    Try {
        Get-PSSessionConfiguration -Name $Name -ErrorAction Stop | Foreach-Object {
            $EndPoint = $_
            #Write-Verbose -Message $EndPoint.Name -Verbose
            
            $Permissions = $EndPoint.Permission -split ", "

            $Permissions | ForEach-Object {
            
                Write-Verbose -Message $EndPoint.Name
                Write-Verbose -Message $_
            
                $Access   = ($_ -split " ")[-1]
                $Identity = ($_ -split " ")[-10..-2] -join " "
                
                New-Object -TypeName psobject -Property @{
                    EndPointName  = $EndPoint.Name
                    Identity      = $Identity
                    Access        = $Access
                    IdentityAccess= $_
                    }
        
            }#Foreach-Object(Permissions)
        
        }#Foreach-Object(EndPoints)
    }
    Catch {
        Write-Warning $_
    }

}


# Find the Generic rights and Extended rights on ACL's
function Get-ADSHFileSystemRightsMapping {
<#
https://msdn.microsoft.com/en-us/library/aa379607(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/aa446632(v=vs.85).aspx
https://msdn.microsoft.com/en-us/library/aa374896(v=vs.85).aspx
#>

 param( 
        [psobject]$FileSystemRightsRaw 
    )

    Switch -Regex ($FileSystemRightsRaw)
    {
            # If it's a digit, check for extended file system rights
            "\d" {$FileSystemRights=[System.Security.AccessControl.FileSystemRights]

                 $GenericRights=@{
                     GENERIC_READ    = 0x80000000
                     GENERIC_WRITE   = 0x40000000
                     GENERIC_EXECUTE = 0x20000000
                     GENERIC_ALL     = 0x10000000
                     FILTER_GENERIC  = 0x0FFFFFFF
                     }
                 $MappedGenericRights=@{
                     FILE_GENERIC_EXECUTE = $FileSystemRights::ExecuteFile -bor $FileSystemRights::ReadPermissions -bor `
                                             $FileSystemRights::ReadAttributes -bor $FileSystemRights::Synchronize

                     FILE_GENERIC_READ    = $FileSystemRights::ReadAttributes -bor $FileSystemRights::ReadData -bor 
                                             $FileSystemRights::ReadExtendedAttributes -bor $FileSystemRights::ReadPermissions -bor `
                                             $FileSystemRights::Synchronize
 
                     FILE_GENERIC_WRITE   = $FileSystemRights::AppendData -bor $FileSystemRights::WriteAttributes -bor `
                                             $FileSystemRights::WriteData -bor $FileSystemRights::WriteExtendedAttributes -bor `
                                             $FileSystemRights::ReadPermissions -bor $FileSystemRights::Synchronize
 
                     FILE_GENERIC_ALL     = $FileSystemRights::FullControl
                     }

                    $MappedRights = New-Object -TypeName $FileSystemRights

                    if ($FileSystemRightsRaw -band $GenericRights.GENERIC_EXECUTE) 
                    {
                        $MappedRights=$MappedRights -bor $MappedGenericRights.FILE_GENERIC_EXECUTE
                    }

                    if ($FileSystemRightsRaw -band $GenericRights.GENERIC_READ) 
                    {
                        $MappedRights=$MappedRights -bor $MappedGenericRights.FILE_GENERIC_READ
                    }

                    if ($FileSystemRightsRaw -band $GenericRights.GENERIC_WRITE) 
                    {
                        $MappedRights=$MappedRights -bor $MappedGenericRights.FILE_GENERIC_WRITE
                    }

                    if ($FileSystemRightsRaw -band $GenericRights.GENERIC_ALL) 
                    {
                     $MappedRights=$MappedRights -bor $MappedGenericRights.FILE_GENERIC_ALL
                    }
 
                     (($FileSystemRightsRaw -bAND $GenericRights.FILTER_GENERIC) -bOR $MappedRights) -as $FileSystemRights
                     continue
                 }#(\d)
        # If it's a string, it's already human readable
        "[a-z]*" {$_ ; continue}

        # If it's something else return, however also add warning!!
        default  {$_ ; Write-Warning -Message "$_ FileSystemRights not listed"}
    }
 
}#Get-ADHSGenericFileSystemRights

# Look up the Service access rights from custom enumeration
Function Get-ADSHServiceRightsMapping {
#https://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx#access_rights_for_a_service
param (
    [String]$ServiceRightsRaw
)

Add-Type  @"
  [System.FlagsAttribute]
  public enum ServiceAccessFlags : uint
  {
      QueryConfig = 1,
      ChangeConfig = 2,
      QueryStatus = 4,
      EnumerateDependents = 8,
      Start = 16,
      Stop = 32,
      PauseContinue = 64,
      Interrogate = 128,
      UserDefinedControl = 256,
      Delete = 65536,
      ReadControl = 131072,
      WriteDac = 262144,
      WriteOwner = 524288,
      Synchronize = 1048576,
      AccessSystemSecurity = 16777216,
      GenericAll = 268435456,
      GenericExecute = 536870912,
      GenericWrite = 1073741824,
      GenericRead = 2147483648
  }
"@

[ServiceAccessFlags] $ServiceRightsRaw

}


# Convert the Win32_Trustee to readable string
Function Get-ADSHTrustee {
param (
    [psobject]$Trustee
)

    $UserName = $Trustee.Name  
    
    If ($Trustee.Domain -ne $Null) 
    {
        $UserName = "$($Trustee.Domain)\$UserName"
    }
    
    If ($Trustee.Name -eq $Null)   
    {
        $UserName = $Trustee.SIDString
        # Consider the need to do a sid lookup
    }
    
    $UserName
}


#Convert the AceType to readable string
Function Get-ADSHAceType {
Param (
    [ValidateSet(0,1,2)]
    [Int]$AceType
)

    Switch ($AceType) 
    { 
        0 { "Allow"} 
        1 { "Deny"} 
        2 { "Audit"}
        Default {''} 
    } 
}


# Find Share Access to the Non Hidden Shares on the DC
function Get-ADSHShareAccess { 
[cmdletbinding()] 
    Param( 
    [ValidateSet('NETLOGON','SYSVOL','%')]
    [String]$Name = '%'
    )
     
    Try {     
        Get-WmiObject -Filter "Name LIKE '$Name'" -Class Win32_LogicalShareSecuritySetting -ErrorAction stop | 
        ForEach-Object {
            $Shares = $_
            Write-Verbose "Share: $($Shares.name)" 
                
                $SecurityDescriptor = $ShareS.GetSecurityDescriptor() 
                 
                $SecurityDescriptor.Descriptor.DACL | ForEach-Object {
                    
                    # System.Management.ManagementBaseObject#\Win32_ACE
                    $ACE = $_
                    
                    Write-Verbose -Message $ACE.AccessMask 
                    
                    $AccessMask = Get-ADSHFileSystemRightsMapping -FileSystemRightsRaw $ACE.AccessMask

                    $AceType = Get-ADSHAceType -AceType $ACE.AceType
                    
                    $UserName = Get-ADSHTrustee -Trustee $ACE.Trustee  
                    

                    New-Object -TypeName psobject -Property @{
                        ComputerName = $env:COMPUTERNAME 
                        Name         = $Shares.Name 
                        Identity     = $UserName 
                        AceType      = $AceType 
                        AceTypeRaw   = $ACE.AceType 
                        AccessMask   = $AccessMask
                        AccessMaskRaw= $ACE.AccessMask
                        AceFlags     = $ACE.AceFlags
                        }

                    }#Foreach-Object(Descriptor.DACL) 
        }#Foreach-Object(LogicalShareSecuritySetting)
        }#Try                 
        Catch { 
                    New-Object -TypeName psobject -Property @{
                        ComputerName = $env:COMPUTERNAME 
                        Name         = ''
                        Identity     = ''
                        AceType      = ''
                        AccessMask   = ''
                        AccessMaskRaw= ''
                        }        
        }#Catch
<#
ComputerName Name     Identity               AceType AceTypeRaw AccessMask                  AccessMaskRaw AceFlags
------------ ----     --------               ------- ---------- ----------                  ------------- --------
DC1          NETLOGON Everyone               Allow            0 ReadAndExecute, Synchronize       1179817        0
DC1          NETLOGON BUILTIN\Administrators Allow            0 FullControl                       2032127        0
#>
}#Get-ADSHShareAccess


# Find File Access to Shares on the DC
function Get-ADSHShareFileAccess {
[cmdletbinding()]
param(
   [String]$Name = '%'
)

    Try {
        Get-WmiObject -Class Win32_Share -Filter "Name LIKE '$Name'" -ErrorAction Stop | 
        Where-Object { $_.Path -NE "" } | ForEach-Object {
            $Share = $_
    
            Get-ACL -Path $share.path -ErrorAction Stop | ForEach-Object { $_.Access } | 
            ForEach-Object { 
            $ACL = $_

            Write-Verbose -Message $acl.FileSystemRights
            
            $AccessMask = Get-ADSHFileSystemRightsMapping -FileSystemRightsRaw $acl.FileSystemRights
                
            New-Object -TypeName psobject -Property @{
                ComputerName       = $env:COMPUTERNAME               
                ShareName          = $Share.name 
                Path               = $share.path 
                Identity           = $acl.IdentityReference.value # System.Security.Principal.NTAccount
                FileSystemRights   = $AccessMask                  # System.Security.AccessControl.FileSystemRights
                FileSystemRightsRaw= $acl.FileSystemRights
                InheritanceFlags   = $acl.InheritanceFlags        # System.Security.AccessControl.InheritanceFlags
                }     
        }#Foreach-Object(ACL)
        }#Foreach-Object(Share)
    } 
    Catch { 
            Write-Warning $_

            New-Object -TypeName psobject -Property @{
                ComputerName     = $env:COMPUTERNAME               
                ShareName        = ''
                Path             = ''
                Identity         = ''
                FileSystemRights = ''
                FileSystemRightsRaw= ''
                InheritanceFlags   = ''
                }
    }#Catch                                                                                         

<#
ComputerName ShareName Path Identity                          FileSystemRights         FileSystemRightsRaw                InheritanceFlags
------------ --------- ---- --------                          ----------------         -------------------                ----------------
MS1          C$        C:\  CREATOR OWNER                          FullControl                   268435456 ContainerInherit, ObjectInherit
MS1          C$        C:\  NT AUTHORITY\SYSTEM                    FullControl                 FullControl ContainerInherit, ObjectInherit
MS1          C$        C:\  BUILTIN\Administrators                 FullControl                 FullControl ContainerInherit, ObjectInherit
MS1          C$        C:\  BUILTIN\Users                           AppendData                  AppendData                ContainerInherit
MS1          C$        C:\  BUILTIN\Users                          CreateFiles                 CreateFiles                ContainerInherit
MS1          C$        C:\  BUILTIN\Users          ReadAndExecute, Synchronize ReadAndExecute, Synchronize ContainerInherit, ObjectInherit
#>
<#
Name                           Value Binary                Hex
----                           ----- ------                ---
ListDirectory                      1 1                     1
ReadData                           1 1                     1
WriteData                          2 10                    2
CreateFiles                        2 10                    2
CreateDirectories                  4 100                   4
AppendData                         4 100                   4
ReadExtendedAttributes             8 1000                  8
WriteExtendedAttributes           16 10000                 10
Traverse                          32 100000                20
ExecuteFile                       32 100000                20
DeleteSubdirectoriesAndFiles      64 1000000               40
ReadAttributes                   128 10000000              80
WriteAttributes                  256 100000000             100
Write                            278 100010110             116
Delete                         65536 10000000000000000     10000
ReadPermissions               131072 100000000000000000    20000
Read                          131209 100000000010001001    20089
ReadAndExecute                131241 100000000010101001    200A9
Modify                        197055 110000000110111111    301BF
ChangePermissions             262144 1000000000000000000   40000
TakeOwnership                 524288 10000000000000000000  80000
Synchronize                  1048576 100000000000000000000 100000
FullControl                  2032127 111110000000111111111 1F01FF

https://msdn.microsoft.com/en-us/library/system.security.accesscontrol(v=vs.110).aspx
#>
}#Get-ADSHShareFileAccess


# Find ServiceController Access to services on the DC
function Get-ADSHServiceControlAccess { 
[cmdletbinding()] 
    Param( 
    [String]$Name = '%'
    )

    Try {
        Get-WmiObject -EnableAllPrivileges -Class Win32_Service -filter "Name LIKE '$Name'" | ForEach-Object {
            $Service = $_
            $ServiceName = $Service.Name
            $ServiceDisplayName = $Service.DisplayName
            Write-Verbose "ServiceName: $ServiceName"

            $Service.GetSecurityDescriptor() | ForEach-Object {

                $_.Descriptor.DACL | ForEach-Object {
                    $DACL = $_ 
            
                    $AccessMask = (Get-ADSHServiceRightsMapping -ServiceRightsRaw $DACL.AccessMask)

                    $Username = (Get-ADSHTrustee -Trustee $DACL.Trustee) 

                    $AceType = (Get-ADSHAceType -AceType $DACL.AceType)
                    
                    New-Object -TypeName psobject -Property @{
                        ComputerName = $env:COMPUTERNAME 
                        Name         = $ServiceName
                        DisplayName  = $ServiceDisplayName
                        Identity     = $UserName
                        AceType      = $AceType
                        AceTypeRaw   = $DACL.AceType 
                        AccessMask   = $AccessMask
                        AccessMaskRaw= $DACL.AccessMask
                        AceFlags     = $DACL.AceFlags
                        }
                    }#DACL 
            }#SecurityDescriptor
    }#Service
    }#Try
    Catch
    {
        Write-Warning $_
        New-Object -TypeName psobject -Property @{
                    ComputerName = $env:COMPUTERNAME 
                    Name         = $ServiceName
                    DisplayName  = $ServiceDisplayName
                    Identity     = $UserName
                    AceType      = $AceType
                    AceTypeRaw   = $DACL.AceType 
                    AccessMask   = $AccessMask
                    AccessMaskRaw= $DACL.AccessMask
                    AceFlags     = $DACL.AceFlags
                    }
    }#Catch

<#
ComputerName Name DisplayName                             Identity                 AceType AceTypeRaw AccessMask                                                             AccessMaskRaw AceFlags
------------ ---- -----------                             --------                 ------- ---------- ----------                                                             ------------- --------
MS1          BITS Background Intelligent Transfer Service NT AUTHORITY\SYSTEM      Allow            0 DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership        983551        2
MS1          BITS Background Intelligent Transfer Service BUILTIN\Administrators   Allow            0 DeleteSubdirectoriesAndFiles, Modify, ChangePermissions, TakeOwnership        983551        0
MS1          BITS Background Intelligent Transfer Service NT AUTHORITY\INTERACTIVE Allow            0 AppendData, WriteAttributes, Read                                             131469        0
MS1          BITS Background Intelligent Transfer Service NT AUTHORITY\SERVICE     Allow            0 AppendData, WriteAttributes, Read                                             131469        0
#>
}#Get-ADSHServiceControlAccess


# Find the Account Access Rights on Local System
function Get-ADSHLocalRight {
<#
*Privilege names are **case-sensitive**.* Valid privileges are documented on Microsoft's website: 
[Privilege Constants]    (http://msdn.microsoft.com/en-us/library/windows/desktop/bb530716.aspx)
[Account Right Constants](http://msdn.microsoft.com/en-us/library/windows/desktop/bb545671.aspx)
#>

[cmdletbinding()]
Param (
    [validateset('SeAssignPrimaryTokenPrivilege','SeAuditPrivilege','SeBackupPrivilege','SeBatchLogonRight',
    'SeChangeNotifyPrivilege','SeCreateGlobalPrivilege','SeCreatePagefilePrivilege','SeCreatePermanentPrivilege',
    'SeCreateSymbolicLinkPrivilege','SeCreateTokenPrivilege','SeDebugPrivilege','SeDenyBatchLogonRight',
    'SeDenyInteractiveLogonRight','SeDenyNetworkLogonRight','SeDenyRemoteInteractiveLogonRight',
    'SeDenyServiceLogonRight','SeEnableDelegationPrivilege','SeImpersonatePrivilege',
    'SeIncreaseBasePriorityPrivilege','SeIncreaseQuotaPrivilege','SeIncreaseWorkingSetPrivilege',
    'SeInteractiveLogonRight','SeLoadDriverPrivilege','SeLockMemoryPrivilege','SeMachineAccountPrivilege',
    'SeManageVolumePrivilege','SeNetworkLogonRight','SeProfileSingleProcessPrivilege','SeRelabelPrivilege',
    'SeRemoteInteractiveLogonRight','SeRemoteShutdownPrivilege','SeRestorePrivilege','SeSecurityPrivilege',
    'SeServiceLogonRight','SeShutdownPrivilege','SeSyncAgentPrivilege','SeSystemEnvironmentPrivilege',
    'SeSystemProfilePrivilege','SeSystemtimePrivilege','SeTakeOwnershipPrivilege','SeTcbPrivilege',
    'SeTimeZonePrivilege','SeTrustedCredManAccessPrivilege','SeUndockPrivilege','SeUnsolicitedInputPrivilege')]

    [String[]]$SecurityRight = ('SeTcbPrivilege','SeInteractiveLogonRight','SeRemoteInteractiveLogonRight','SeBackupPrivilege',
                                'SeSystemtimePrivilege','SeCreateTokenPrivilege','SeDebugPrivilege',
                                'SeEnableDelegationPrivilege','SeLoadDriverPrivilege','SeBatchLogonRight',
                                'SeServiceLogonRight','SeSecurityPrivilege','SeSystemEnvironmentPrivilege',
                                'SeManageVolumePrivilege','SeRestorePrivilege','SeSyncAgentPrivilege','SeRelabelPrivilege',
                                'SeTakeOwnershipPrivilege')
)

$c = @'
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.ComponentModel;

namespace LsaSecurity
{
    using LSA_HANDLE = IntPtr;

    class Program
    {
        static void Main(string[] args)
        {
            using (LsaSecurity.LsaWrapper lsa = new LsaSecurity.LsaWrapper())
            {
                Console.WriteLine("Enter the right");
                string p = Console.ReadLine();
                Console.WriteLine(p);
                System.Security.Principal.SecurityIdentifier[] result = lsa.ReadPrivilege(p);
                foreach (SecurityIdentifier i in result)
                {
                    string a = i.ToString();
                    Console.WriteLine(a);

                }
                Console.ReadLine();
            }
        }
    }


    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public LSA_HANDLE RootDirectory;
        public LSA_HANDLE ObjectName;
        public int Attributes;
        public LSA_HANDLE SecurityDescriptor;
        public LSA_HANDLE SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct LSA_UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_ENUMERATION_INFORMATION
    {
        public LSA_HANDLE PSid;
    }

    sealed public class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
                   SuppressUnmanagedCodeSecurityAttribute]
        public static extern uint LsaOpenPolicy(LSA_UNICODE_STRING[] SystemName,
                                                ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                                                int AccessMask,
                                                out LSA_HANDLE PolicyHandle);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true),
                   SuppressUnmanagedCodeSecurityAttribute]
        public static extern long LsaEnumerateAccountsWithUserRight(LSA_HANDLE PolicyHandle,
                                                                    LSA_UNICODE_STRING[] UserRights,
                                                                    out LSA_HANDLE EnumerationBuffer,
                                                                    out int CountReturned);

        [DllImport("advapi32")]
        public static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        public static extern int LsaClose(LSA_HANDLE PolicyHandle);

        [DllImport("advapi32")]
        public static extern int LsaFreeMemory(LSA_HANDLE Buffer);
    }

    public class LsaWrapper : IDisposable
    {
        public enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }

        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_NO_MORE_ENTRIES = 0xc000001A;

        LSA_HANDLE lsaHandle;

        public LsaWrapper()
            : this(null)
        { }

        // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = LSA_HANDLE.Zero;
            lsaAttr.ObjectName = LSA_HANDLE.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = LSA_HANDLE.Zero;
            lsaAttr.SecurityQualityOfService = LSA_HANDLE.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = LSA_HANDLE.Zero;

            LSA_UNICODE_STRING[] system = null;

            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr,
                                              (int)Access.POLICY_ALL_ACCESS,
                                              out lsaHandle);
            if (ret == 0) { return; }

            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public SecurityIdentifier[] ReadPrivilege(string privilege)
        {
            LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
            privileges[0] = InitLsaString(privilege);
            LSA_HANDLE buffer;
            int count = 0;
            long ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, privileges, out buffer, out count);

            if (ret == 0)
            {
                SecurityIdentifier[] sids = new SecurityIdentifier[count];

                for (long i = 0, elemOffs = (long)buffer; i < count; i++)
                {
                    LSA_ENUMERATION_INFORMATION lsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        (LSA_HANDLE)elemOffs, typeof(LSA_ENUMERATION_INFORMATION));

                    sids[i] = new SecurityIdentifier(lsaInfo.PSid);

                    elemOffs += Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION));
                }

                return sids;
            }

            if (ret == STATUS_ACCESS_DENIED)
            {
                throw new UnauthorizedAccessException();
            }
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY))
            {
                throw new OutOfMemoryException();
            }

            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != LSA_HANDLE.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = LSA_HANDLE.Zero;
            }
            GC.SuppressFinalize(this);
        }

        ~LsaWrapper()
        {
            Dispose();
        }

        public static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe)
                throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }
}
'@

    try {
        $t = [LsaSecurity.LsaWrapper]
    }
    catch {
       $t = Add-Type -TypeDefinition $c 
    }

    $d = New-Object -TypeName LsaSecurity.LsaWrapper
    
    
    $SecurityRight | Foreach-Object {
        $Right = $_
        try {
            $d.ReadPrivilege($Right) | ForEach-Object {
                
                $Current = $_.Translate([System.Security.Principal.NTAccount])

                New-Object -TypeName psobject -Property @{
                    SecurityRight= $Right
                    Identity     = $Current.value
                }
            }#Foreach-Object(NTAccount)
        }#Try
        Catch {
            Write-Warning -Message "No Identites with $Right"
        }#Catch


    }#Foreach-Object(SecurityRight)

}



# Find all $Tier0 accounts based on group membership 
# This checks both Root and Child Domain
function Get-ADSHTier0Principle {
param (
        [String[]]$Tier0GroupsForest = ('Enterprise Admins','Schema Admins'),
        [String[]]$Tier0GroupsDomain = ('Domain Admins','Backup Operators','Administrators')
        )

     
     #$DomainName = Get-ADSHDomainName
     $RootDomain = Get-ADSHDomainRoot
     
     [object[]]$domain = $Tier0GroupsDomain | ForEach-Object {
        
        Get-ADGroup -Identity $_ | Get-ADGroupMember -Recursive
        
        } | Select-Object -Unique | Foreach-object {

            Get-ADUser -Identity $_.distinguishedName -Server:"${Env:COMPUTERNAME}:3268" # -Properties *
        }
     
     [object[]]$child = $Tier0GroupsForest | ForEach-Object {
        
        Get-ADGroup -Identity $_ -Server:$RootDomain.PDCEmulator | Get-ADGroupMember -Recursive
        
        } | Select-Object -Unique | Foreach-object {

            Get-ADUser -Identity $_.distinguishedName -Server:"${Env:COMPUTERNAME}:3268" # -Properties *
        }

    $domain + $child | Get-Unique
}



# Find the computer accounts where Tier0 Account has logged on
Function Get-ADSHTier0Login {
[cmdletbinding()]
Param (
     [Parameter(valuefrompipelinebypropertyname=$true,
                valuefrompipeline=$true)]
     [Alias("Name")]
     [String[]]$Tier0Identity
    )
begin {
    $Oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1
    $Timespan = New-TimeSpan -Start ($Oldest.TimeCreated) -End (Get-Date)
}
process {

    $Tier0Identity | Select-Object -Unique | ForEach-Object {
        
        $Identity = $_
        Write-Verbose "Checking for Identity: $Identity" -Verbose

        Get-WinEvent -ErrorAction SilentlyContinue -LogName Security -FilterXPath @"
            *[
                System[EventID=4624] and
                EventData[Data[@Name='TargetUserName']='$Identity'] or
                System[EventID=528] and
                EventData[Data[@Name='TargetUserName']='$Identity'] or
                System[EventID=540] and
                EventData[Data[@Name='TargetUserName']='$Identity']
            ]
"@ | ForEach-Object {

    $EventLog= $_

    # Get the EventData from the XML and turn it into an psobject (from a hashtable)
    [xml]$b = $_.toxml()
    $c = $b.FirstChild.EventData
    $d = @{}
    $c.GetEnumerator() | ForEach-Object { $d[$_.Name] = $_.'#text' }
    $Event = New-Object psobject -Property $d

    # do a lookup on the logon type
    $LogonTypeText = Switch ($Event.LogonType)
    {
        2 {'Interactive'}
        3 {'Network'}
        4 {'Batch'}
        5 {'Service'}
        7 {'Unlock'}
        8 {'NetworkCleartext'}
        9 {'NewCredentials'}
        10{'RemoteInteractive'}
        11{'CachedInteractive'}
    }

    # Resolve the ComputerName or IP address.
    If ($event.WorkstationName)
    {
        $ComputerName = $event.WorkstationName
    }
    elseif ( $event.IpAddress -ne '-' )
    {
        Try {
                $NameResolution = ([System.Net.DNS]::GetHostByAddress($event.IpAddress)).HostName
                
                If ($NameResolution -eq $null -or $event.IpAddress -like "169.254.*") {
                    $ComputerName = "Unable to resolve."
                }
                elseIf ($event.IpAddress -eq "127.0.0.1") {
                    $ComputerName = $Env:COMPUTERNAME
                }
                else
                {
                    $ComputerName = $NameResolution
                }
         }#Try 
         Catch { 
                    if ($event.IpAddress -like "169.254.*")
                    {
                        $ComputerName = "Unable to resolve."
                    }
                    else
                    {
                        $ComputerName = $event.IpAddress
                    }
         }#Catch
    }
    else
    {
        $ComputerName = "Unable to resolve."
    }

    if ($computername -eq "Unable to resolve." -and $event.IpAddress -match "-")
    {
        Write-Verbose "ComputerName: $ComputerName"
        Write-Verbose "IPAddress:    $($event.IpAddress)"
    }
    else
    {
        # Put the pieces back together.
        New-Object psobject -Property @{
            User             = $Event.TargetUserName
            Domain           = $event.TargetDomainName
            DomainController = $Env:COMPUTERNAME
            IPAddress        = $event.IpAddress
            ComputerName     = $ComputerName
            LogonTime        = $EventLog.TimeCreated
            LogonType        = $Event.LogonType
            LogonTypeText    = $LogonTypeText
            ValidTimeSpanDays= [Int]$TimeSpan.TotalDays
            }
    }
} | Where-Object {$_.LogonType -ne "2"}
}#Foreach-Object(Identity)
}#Process

}#Get-ADSHTier0Login


# Find the computer accounts where Tier0 Account has logged on
Function Get-ADSHOSVersion {
[cmdletbinding()]
Param ()

    [environment]::OSVersion.Version

}


function fooADSH {

$SysVolAccess = Get-ADSHShareAccess -Name SYSVOL
$SysVolAccess | Select-Object -ExpandProperty Identity -Unique

}

