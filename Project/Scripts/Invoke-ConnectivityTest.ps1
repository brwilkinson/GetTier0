#-------------------
$Base = 'F:\Project'
#-------------------

$TestsDir = "$Base\Tests"
Set-Location -Path $TestsDir

$onlineDCFile = "{0:yyyy-MM-dd_hhmm}-Online.csv" -f (Get-Date)
$DCReportLogPath = "..\Connectivity\"
$onlineDCReportFilePath = Join-Path -Path $DCReportLogPath -ChildPath $onlineDCFile

Import-Module -Name "..\scripts\GetPriv.psm1" -Force

# Find all online DC's in the forest
Get-ADSHOnlineDC | Select-Object -Property Forest,Name,Domain,IPAddress,SiteName |
Export-Csv -Path $onlineDCReportFilePath -NoTypeInformation