# ADSH Guidelines - Instructions

Friday, August 12, 2016

4:52 PM

## ADSH Pre-requisites.

- **Host Machine (where the tests are executed from)**
  - Powershell version 5.0 or 5.1
  - Pester Module
  - Windows 8/Windows Server 2012 or later
  - Domain Joined
  - Network access to the Domain Controllers
    - Enterprise Admin Credentials to execute discovery and other tests

- **Target Domain Controllers**
  - Server 2008R2 or later
    - ActiveDirectory PowerShell Module
  - PowerShell remoting Enabled
    - This is enabled by default on 2012 or later, however not on Server 2008 R2
      - You can enable this by running: **Enable-PsRemoting** on each server
        - It would be recommended to enable it via Group Policy

- There are two sets of tests, both sets of tests require access via TCP port 5895 via PowerShell Remoting
  - Host Tests
    - You need network access to every domain controller
  - Domain Tests
    - You need network access to each PDC in each domain

## ADSH Installation Instructions

- Copy the latest version of the Code to your machine
  - g. F:\2016-08-1\_Project\_Backup.zip
- Right click on the zip file, select properties and then Unblock File, then select Okay.
- Extract the contents of the Zip to a working directory, then copy out the Project Folder.
- F:\2016-08-1\_Project\_Backup\2016-08-1\_Project\_Backup --&gt; **F:\Project**
- Open the PowerShell (Integrated Scripting Environment) ISE running as Administrator
- Validate that you have PowerShell version 5
  - $psversiontable
- Validate that you have the Pester Module
  - Get-Module pester -ListAvailable
  - If not install it:
    - Get-Package -Name Pester -ForceBootstrap
    - Install-Module -name Pester -Force -Confirm:$False
    - * Confirm the Nuget install (optional)
- Validate that your PowerShell Execution Policy is not set to Restricted
  - Get-ExecutionPolicy
  - If it is set to restricted run the following
    - Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

- In the ISE select File, Open, --&gt; F:\Project\Scripts\Invoke-Tests.ps1
- In the ISE select File, Open, --&gt; F:\Project\Scripts\Invoke-inDomainTests.ps1
- In the ISE select File, Open, --&gt; F:\Project\Scripts\Invoke-ConnectivityTest.ps1