#requires -Version 5

Param (
        [String]$TestName = '*',
        [Switch]$Quiet,
        [Switch]$CaptureBaseline
        )

#-------------------
$Base = 'F:\Project'
#-------------------

$TestsDir = "$Base\Tests"
Set-Location -Path $TestsDir
$TestGroup = 'DomainTests'
$ReportDir = "$Base\Reports"
$ReportDirHTML = "$Base\ReportsHTML"
$TranscriptDir = "$Base\Transcript"
$TranscriptFile = "{0}-{1:yyyy-MM-dd_hhmm}-{2}.txt" -f $TestGroup,(Get-Date),'Series'
$TranscriptPath = Join-Path -Path $TranscriptDir -ChildPath $TranscriptFile
$FileNameCSVFail = "{0:yyyy-MM-dd_hhmm}-{1}-Fail.csv" -f (Get-Date),$TestGroup
$FileNameCSVAll = "{0:yyyy-MM-dd_hhmm}-{1}-All.csv" -f (Get-Date),$TestGroup
$ReportPathCSVFail = Join-Path -Path $ReportDir -ChildPath $FileNameCSVFail
$ReportPathCSVAll = Join-Path -Path $ReportDir -ChildPath $FileNameCSVAll
$psISE.PowerShellTabs.Files | Where-Object {$_.DisplayName -match 'Tests.*ps1\*' -and $_.FullPath -like "$Base*"} | ForEach-Object {$_.save()}
$Properties = 'Describe','Context','Name','Passed','FailureMessage','StackTrace','ErrorRecord'
Get-PSSession | Remove-PSSession

Import-Module -Name "..\Tools\Pester" -Force
Import-Module -Name "..\scripts\GetPriv.psm1" -Force

# Find all online PDC's in the forest (each domain)
$OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly 
$OnlineDC = $OnlineDCObjects.Name

Start-Transcript -Path $TranscriptPath
Write-Verbose -Message "Running tests against $($OnlineDC.count) Primary Domain Controllers" -Verbose
New-PSSession -ComputerName $OnlineDC -PipelineVariable session | ForEach-Object {
  $CN = $session.ComputerName
  $s = $session

    # Load all functions into the remote session
    Invoke-Command -Session $s -FilePath .\DirectoryControlTests.ps1
    Invoke-Command -Session $s -FilePath .\HostTests.ps1
    Invoke-Command -Session $s -ScriptBlock {

        # Explicitly import the AD/Group Modules to support PowerShell V2 + map the psdrive
        Import-Module -name ActiveDirectory -PassThru | select -Property Version,Name
        Import-Module -name GroupPolicy -PassThru | select -Property Version,Name

        # Load a Global Catalog Drive that can be used by any function.
        $RootDomain = Get-ADSHDomainRoot
        $PDC = $RootDomain.PDCEmulator
        $GC = New-PSDrive -PSProvider ActiveDirectory -Name GC -Root "" -Server "${PDC}:3268" -ErrorAction SilentlyContinue
    }

    # Import all functions into the local session (Implicit remoting)
    $module = Import-PSSession -Session $s -CommandName *ADSH* -AllowClobber

    Write-Host "--------------------------------------------" -ForegroundColor DarkYellow
    Write-Host "Module: $module" -ForegroundColor DarkYellow
    Write-Host "ComputerName: $CN" -ForegroundColor DarkYellow
    
    # Kick off the pester tests and output to XML and CSV files
    $FileNameXML = "{0:yyyy-MM-dd_hhmm}-{1}-{2}.xml" -f (Get-Date),$CN,$TestGroup
    $ReportPathXML = Join-Path -Path $ReportDir -ChildPath $FileNameXML
    
    # Kick off the pester tests
    $Result = Invoke-Pester @PSBoundParameters -PassThru -OutputFile $ReportPathXML -OutputFormat NUnitXml -Script @{
        Path       = '.\DirectoryControlTests.Tests.ps1' 
        Parameters = @{ ModuleName = $module.Name }
       }

    # Export Tests that Fail
    $Fail = $Result | ForEach-Object testresult | Where-Object result -NE passed
    if ($Fail){ $Fail | Select-Object -Property $Properties | Export-Csv -Path $ReportPathCSVFail -NoTypeInformation -Append }
    
    # Export all results
    $Result | ForEach-Object testresult | Export-Csv -Path $ReportPathCSVAll -NoTypeInformation -Append

    # Cleanup the module that was used for implicit remoting
    Remove-Module -Name $module.Name 

    # Cleanup the current pssession
    Remove-PSSession -Session $s

    # The following test will generate, however not open
    Get-ADSHReportEngineer -HostName $CN -ReportPathXML $ReportPathXML -ReportDir $ReportDirHTML -TestType Domain -Base $Base

}

if (Test-Path -Path $ReportPathCSVFail)
{
    Get-ADSHReport -FailedReport $ReportPathCSVFail -ReportDir $ReportDirHTML -TestType Domain
}
else
{
    Write-Warning -Message "No Domain Test Failures"
}

Stop-Transcript