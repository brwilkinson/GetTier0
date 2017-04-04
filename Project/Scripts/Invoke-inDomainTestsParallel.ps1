#requires -Module Pester
#requires -Version 5

Param (
        [String]$TestName = '*',
        [Switch]$Quiet
        )

$Base = 'F:\Project'
$TestsDir = "$Base\Tests"
Set-Location -Path $TestsDir
$TestGroup = 'HostTests'
$ReportDir = "$Base\Reports"
$TranscriptDir = "$Base\Transcript"
$TranscriptFile = "{0}-{1:yyyy-MM-dd_hhmm}-{2}.txt" -f $TestGroup,(Get-Date),'Parallel'
$TranscriptPath = Join-Path -Path $TranscriptDir -ChildPath $TranscriptFile
$psISE.PowerShellTabs.Files | Where {$_.DisplayName -match 'Tests.*ps1\*' -and $_.FullPath -like "$Base*"} | foreach {$_.save()}
Get-PSSession | Remove-PSSession

# Find all online DC's in the forest
Import-Module -Name "..\scripts\GetPriv.psm1" -Force
$OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly
$OnlineDC = $OnlineDCObjects.Name

Start-Transcript -Path $TranscriptPath
Write-Verbose -Message "Running tests against $($OnlineDC.count) Primary Domain Controllers" -Verbose
# Call the workflow to run tests in parallel
ADHS @PSBoundParameters -OnlineDC $OnlineDC -Base $Base -TestGroup $TestGroup -TestsPath '.\DirectoryControlTests.Tests.ps1'
Stop-Transcript


