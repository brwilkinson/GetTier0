#requires -version 3.0

#
# GetPriv.psm1
#

# Find all of the Domains in the Forest
Function Get-ADSHDomain
{
	
<#.Synopsis
<!<SnippetShortDescription>!>
.DESCRIPTION
<!<SnippetLongDescription>!>
.EXAMPLE
<!<SnippetExample>!>
.EXAMPLE
<!<SnippetAnotherExample>!>
#>

    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        # <!<SnippetParam1Help>!>
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true,Position=0)]
        [String]$ForestName
    )


Begin
{
          
}# end begin

Process
{
    try{
        if($ForestName -ne "")
        {
            $addx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest", $ForestName)
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($addx)
        }
        else
        {
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

    }# end try
    Catch
    {
        Write-Warning -Message "$($_[0].Exception)"
    }

    return $Forest.Domains
          
}# end Process

End
{

}# end 

}# end function


# Test connectivity to DC's
function Test-ADHSDCConnection
{
	[cmdletbinding()]
	param (
        [System.DirectoryServices.ActiveDirectory.Domain[]]$Domain,
        [Switch]$PDCOnly
	)

	if ($PDCOnly)
    {
        $DCS = $Domain.PdcRoleOwner
    }
    else
    {
        $DCS = $Domain.DomainControllers
    }

    $DCs | Foreach-object {

        $DC = $_

        $props = @{
			"ForestName"        = $dc.Forest.Name
			"DomainName"        = $dc.Domain
			"DCName"            = $dc.name
			"TestWSManConnects" = $false
			"InvokeCommandConnects" = $false
			"WSManStackVersion" = $null
			"TNCRoundtrip"      = $null
		}

        $rObj = New-Object System.Management.Automation.PSObject -Property $props		
		
		$wsman = Test-WSMan -cn $dc.Name -ErrorAction SilentlyContinue
		
		if ($wsman -ne $null)
		{
			$v = @()
			
			$rObj.TestWSManConnects = $True
			
			foreach ($version in $wsman.ProductVersion)
			{
				$r = $version -match "stack: (\d.\d)"
				$v += $Matches[0]
			}
			
			$rObj.WSManStackVersion = $v
			
		}
		
		
  try
  {
    $InvokeResults = Invoke-command -cn $dc.Name -scriptblock { $env:computerName } -ErrorAction SilentlyContinue -ErrorVariable ivcErr
  }
  # NOTE: When you use a SPECIFIC catch block, exceptions thrown by -ErrorAction Stop MAY LACK
  # some InvocationInfo details such as ScriptLineNumber.
  # REMEDY: If that affects you, remove the SPECIFIC exception type [System.Management.Automation.ValidationMetadataException] in the code below
  # and use ONE generic catch block instead. Such a catch block then handles ALL error types, so you would need to
  # add the logic to handle different error types differently by yourself.
  catch [System.Management.Automation.ValidationMetadataException]
  {
    # get error record
    [Management.Automation.ErrorRecord]$e = $_

    # retrieve information about runtime error
    $info = [PSCustomObject]@{
      Exception = $e.Exception.Message
      Reason    = $e.CategoryInfo.Reason
      Target    = $e.CategoryInfo.TargetName
      Script    = $e.InvocationInfo.ScriptName
      Line      = $e.InvocationInfo.ScriptLineNumber
      Column    = $e.InvocationInfo.OffsetInLine
    }
    
    # output information. Post-process collected info, and log info (optional)
    $info
  }

        
        # Error variable is populated, something went wrong.
        if($ivcErr -ne $null)
        {
            $rObj.InvokeCommandConnects = "FALSE: $($Error[0].Exception.Message)"
        }
        else
        {
            $rObj.InvokeCommandConnects = $True 
        }
		
		
        $rObj.TNCRoundTrip = "{0} ms" -f ((Test-NetConnection -ComputerName $dc.Name -CommonTCPPort WINRM).PingReplyDetails.RoundTripTime)
		
        $rObj
		
	}#Foreach-object($DCs)
	
}


Function IsUserEnterpriseAdmin
{
    $CurrentUser = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    
    $Domain = $CurrentUser.Identity.Name | split-path -Parent

  
    foreach ($Group in $CurrentUser.Identity.Groups)
    {
        
        if($Group.Translate([System.Security.Principal.NTAccount]).Value -Like "$domain\Enterprise Admins")
        {
            return $True
        }
    }
    
    return $False    
}


# Find the online DC's per Domain or single PDC per Domain
Function Get-ADSHOnlineDC {
[cmdletbinding()]
param (
    [Switch]$PDCOnly,
    [String]$offlineDCReportLogPath = "..\Connectivity\"
)
#Is Member of Enterprise Admins
if(-NOT(IsUserEnterpriseAdmin))
{
    Throw "User not Enterprise Admin, exiting script"
}
else
{
    Write-Warning -Message "User is Enterprise Admin"
}

# Are we running elevated
if (-not `
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Throw
}
else
{
    Write-Warning -Message "User is running as admin (elevated)"
}

$CurrentForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
$ADSHDomains = Get-ADSHDomain -ForestName $CurrentForest

Write-Warning -Message "Checking for Domain Controller accessibility, this could take some time."

Test-ADHSDCConnection -Domain $ADSHDomains -PDCOnly:$PDCOnly | ForEach-Object {
    $Connection = $_

    # if we successully connected to the DC via Invoke-Command, create persistent 
    # session to server.
    # If false, we will log this fact to a log file.
    if($Connection.InvokeCommandConnects -eq $True)
    {
        # $RemoteConnections += New-PSSession -ComputerName $Connection.DCName
        foreach($name in $ADSHDomains)
        {
            
            $name.DomainControllers | Where-Object {$_.name -eq $Connection.DCName} 
        }
    }
    else
    {
        # export object to log (csv)
        $offlineDCFile = "{0:yyyy-MM-dd_hhmm}-{1}-{2}-Offline.csv" -f (Get-Date),$Connection.ForestName,$Connection.DomainName
        $offlineDCReportFilePath = Join-Path -Path $offlineDCReportLogPath -ChildPath $offlineDCFile
        $Connection | Export-Csv -Path $offlineDCReportFilePath -NoTypeInformation -Append
    }
}
}#Get-ADSHOnlineDC

# Run tests in parallel
Workflow ADHS {
Param (
    [String[]]$OnlineDC,
    [String]$Base,
    [String]$TestGroup,
    [String]$TestsPath,
    [String]$TestName = '*',
    [Switch]$Quiet
    )

    foreach -parallel ($Computer in $OnlineDC)
    {
        inlineScript
        {
            $Base = $Using:Base
            $TestsDir = "$Base\Tests"
            Set-Location -Path $TestsDir
            $ReportDir = "$Base\Reports"
            
            $CN = $using:Computer
            $S = New-PSSession -ComputerName $CN

            # Load all functions into the remote session
            Invoke-Command -Session $s -FilePath .\HostTests.ps1
            Invoke-Command -Session $s -FilePath .\DirectoryControlTests.ps1

            # Import all functions into the local session (Implicit remoting)
            $module = Import-PSSession -Session $s -CommandName *ADSH* -AllowClobber


            # Kick off the pester tests and output to XML and CSV files
            $FileNameXML = "{0:yyyy-MM-dd_hhmm}-{1}-{2}.xml" -f (Get-Date),$CN,$Using:TestGroup
            $FileNameCSVFail = "{0:yyyy-MM-dd_hhmm}-{1}-{2}-Fail.csv" -f (Get-Date),$CN,$Using:TestGroup
            $FileNameCSVAll = "{0:yyyy-MM-dd_hhmm}-{1}-{2}-All.csv" -f (Get-Date),$CN,$Using:TestGroup
    
            $ReportPathXML = Join-Path -Path $ReportDir -ChildPath $FileNameXML
            $ReportPathCSVFail = Join-Path -Path $ReportDir -ChildPath $FileNameCSVFail
            $ReportPathCSVAll = Join-Path -Path $ReportDir -ChildPath $FileNameCSVAll
    
            # Kick off the pester tests
            $Result = Invoke-Pester -PassThru -OutputFile $ReportPathXML -OutputFormat NUnitXml -Script @{
                Path = $Using:TestsPath; Parameters = @{ ModuleName = $module.Name }} -Quiet:$using:Quiet -TestName $Using:TestName

            # Export Tests that Fail
            $Properties = ('Describe','Context','Name','Passed','FailureMessage','StackTrace','ErrorRecord')
            $Fail = $Result | ForEach-Object testresult | Where-Object result -ne passed
            if ($Fail){ $Fail | Select-Object -Property $Properties | Export-Csv -Path $ReportPathCSVFail -NoTypeInformation}
    
            # Export all results
            $Result | ForEach-Object testresult | Export-Csv -Path $ReportPathCSVAll -NoTypeInformation

            # Cleanup the module that was used for implicit remoting
            Remove-Module $module.Name 

            # Cleanup the current pssession
            Remove-PSSession -Session $s

        }#InlineScript
    }#ForeachParallel
}#ADHS


# ADSH Report
Function Get-ADSHReport {
param (
    [String]$FailedReport,
    [String]$ReportDir,
    [ValidateSet('Host','Domain')]
    [String]$TestType
)

    $CSS = @"
        <style type="text/css">
            table {
    	    font-family: Verdana;
    	    border-style: dashed;
    	    border-width: 1px;
    	    border-color: #FFCC99;
    	    padding: 5px;
    	    background-color: #FFFFCC;
    	    table-layout: auto;
    	    text-align: left;
    	    font-size: 8pt;
            }

            table th {
    	    border-bottom-style: solid;
    	    border-bottom-width: 1px;
            font: bold
            }
            table td {
    	    border-top-style: solid;
    	    border-top-width: 1px;
            }
            
            tr:nth-child(even) {
            background: #FFCC99
            }            

            .style1 {
            font-family: Courier New, Courier, monospace;
            font-weight:bold;
            font-size:small;
            }
            </style>
"@

    $i=0
    $Table = Import-Csv -Path $FailedReport  |
    Where-Object {$_.failuremessage -match '{.+}'} | ForEach-Object {

        $raw = ($matches.0) -replace '\{|\}',''
        $_ | Add-Member -Name Tier0All -MemberType NoteProperty -Value $raw

        $_ | Where-Object {-not ($_.Tier0All -as [Int])} | Where-Object {$_.Name -notmatch 'Missing'}  | ForEach-Object {

            $i++
            $_ | Add-Member -Name Record -MemberType NoteProperty -Value $i

            $current = $_
            $_.Tier0All -split ';' | ForEach-Object {
            
                $current | Add-Member -Name Tier0 -MemberType NoteProperty -Value $_ -PassThru -Force

            }
        }
    } | Select-Object Tier0,@{Name='Tier-0 criteria';Expression={$_.Describe}},
                     @{Name='More Information';Expression={$_.Name}} | Sort-Object Tier0
    $group = $table | Group-Object Tier0 | Sort-Object -Property Count -Descending | Select-Object Count,Name | ConvertTo-Html -Fragment
    $Body = ("<H1>ADSH Report $(Get-Date) - $TestType Tests</H1>") + ("<H3>Tier0 principal summary</H3>") + $group + '</br>'
        
    $html = $table | ConvertTo-Html -Head $CSS -Title 'ADSH Report' -Body $Body -PreContent "<H3>Tier0 principal detail</H3>" -PostContent "<H5>Processed on $($env:COMPUTERNAME)</H5>"
    $html > $ReportDir\Summary-Latest-$TestType-Report.html
    Invoke-Item $ReportDir\Summary-Latest-$TestType-Report.html

}

# ADSH Report Engineer
Function Get-ADSHReportEngineer {
param (
    [String]$ReportPathXML,
    [String]$ReportDir,
    [ValidateSet('Host','Domain')]
    [String]$TestType,
    [String]$Base,
    [String]$HostName
)

if (Test-Path -Path $ReportDir\Latest-${TestType}-${HostName}.html)
{
    Remove-Item -Path $ReportDir\Latest-${TestType}-${HostName}.html
}

& "$Base\Tools\NUnitHTMLReportGenerator.exe" $ReportPathXML $ReportDir\Latest-$TestType-${HostName}.html

# still generate the tests, however don't open them
#Invoke-Item -Path $ReportDir\Latest-$TestType-${Host}.html

}