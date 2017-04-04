

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


## Running the Tests

1. **Invoke-connectivityTests**

1.
  1. Depending on the size of your environment this could take some time to run

1.
  1.
    1. Even several days.
  2. These are ready only tests for connectivity to the DC&#39;s and the Forest/Domain

1.
  1.
    1. You should be running as and Enterprise Admin
  2. Click F5 to run the tests or the Play button.
  3. Once the tests are complete the results will be in the following directory: F:\Project\Connectivity

1.
  1.
    1. One file for Online and one file for Offline.

**\* Note:**

- These tests are used for troubleshooting.
- These tests are also part of the other two tests.
  - If these tests took a long time to run, you should keep a manual list of your PDC&#39;s and your Hosts that you want to be part of the test, rather than executing this each time as part of the other two tests.
  - If the tests did not take a long time to run, then you don&#39;t need to make any modifications.

1. **Invoke-inDomainTests**

1.
  1. See the **Note** from the Invoke-ConnectivityTests

1. If you need to keep a Manual List you should replace the following lines in this script

| Before24     # Find all online PDC&#39;s in the forest (each domain)25     $OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly26     $OnlineDC = $OnlineDCObjects.Name  **Change 1 - command out line 25 by adding #** After25      #$OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly   **Change 2 - add the list of your DC&#39;s on line 26, every DC in the forest should be listed** After26       $OnlineDC = &#39;DC1&#39;,&#39;DC3&#39;,&#39;DC56&#39; Or alternatively, keep your PDC list in a text file and read that in After26       $OnlineDC = Get-Content -Path $Base\ComputersDomainTests.txt  |
| --- |

1. Click F5 to run the tests or the Play button.

1. Once the tests are complete the two reports will open

1.
  1. The Engineer Report (Latest-Domain-Report.html)
  2. The Summary Report (Latest-Domain.html)

1.
  1.
    1. These reports can also be found in the following directory: F:\Project\Reports
    2. Only the latest HTML reports are kept
    3. There is also raw reporting files in CSV format from Every single Run.

1. **Invoke-Tests**

1.
  1. See the Note from the Invoke-ConnectivityTests (above)

1.
  1.
    1. If you need to keep a Manual List you should replace the following lines in this script

| Before
24     # Find all online PDC&#39;s in the forest (each domain)25     $OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly26     $OnlineDC = $OnlineDCObjects.Name | select -last 1  **Change 1 - command out line 25 by adding #** After25      #$OnlineDCObjects = Get-ADSHOnlineDC   **Change 2 - add the list of your PDC&#39;s on line 26, you can select any/single Domain Controller from each Domain here, they do not have to be the PDC.** After26       $OnlineDC = &#39;DC1&#39;,&#39;DC3&#39;,&#39;DC4&#39;,&#39;DC5&#39; Or alternatively, keep your PDC list in a text file and read that in After26       $OnlineDC = Get-Content -Path $Base\ComputersHostTests.txt  |
| --- |

1. By default  the tests only run against 1 host, you need to make a change to fix this

| Before
24     # Find all online PDC&#39;s in the forest (each domain)25     $OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly26     $OnlineDC = $OnlineDCObjects.Name **| select -last 1**  Change 1 - remove the part that says  | select -last 1After26      $OnlineDC = $OnlineDCObjects.Name |
| --- |

1. Click F5 to run the tests or the Play button.

1.
  1. Note: These tests will take a long time to run, since it runs them against every Domain Controller

1. Once the tests are complete the two reports will open

1.
  1. The Engineer Report (Latest-Domain-Report.html)
  2. The Summary Report (Latest-Domain.html)

1.
  1.
    1. These reports can also be found in the following directory: F:\Project\Reports
    2. Only the latest HTML reports are kept
    3. There is also raw reporting files in CSV format from Every single Run.
