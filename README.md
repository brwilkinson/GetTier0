

# Tier0 Overview

- Get Tier0 refers to the process of identifying Tier0 accounts on your domain.
- The defintion of a Tier0 account is one that has control permission over Directory Services.
- This tool maybe used in conjunction with ActiveDirectory Services Hardening.
- This is the table of tests that are performed
  - [Tier0 Account Discovery Specifications](wiki/Tier0-Specifications---What-tests-are-performed%3F)

# Tier0 Guidelines - Instructions

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

### **Invoke-connectivityTests**

- Depending on the size of your environment this could take some time to run
  - Even several days.
- These are read-only tests for connectivity to the DC&#39;s and the Forest/Domain

- You should be running as and Enterprise Admin
- Click F5 (or the Play button) to run the tests  in the ISE.
- Once the tests are complete the results will be in the following directory: 
  - F:\Project\Connectivity
    - File for online DC's  E.g. 2016-05-11_0435-Online.csv
    - File for offline DC's E.g. 2016-05-13_0739-contoso.com-contoso.com-Offline.csv

**\* Note:**

- These tests can be used for identifying servers where WSMAN is unable to connect
- These steps are also performed as part of the other two (Domain and Host) tests.
  - If these tests took a long time to run, you should keep a manual list of your PDC&#39;s and your Hosts that you want to be part of the test, rather than executing this each time as part of the other two tests.
  - If the tests did not take a long time to run, then you don&#39;t need to make any modifications.

### **Invoke-inDomainTests**

- See the **Note** from the Invoke-ConnectivityTests (Above)

- If you need to keep a Manual List you should replace the following lines in this script

#### Before:
```
24     # Find all online PDC's in the forest (each domain)
25     $OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly
26     $OnlineDC = $OnlineDCObjects.Name
```

### Change 1 - comment out line 25 by adding #

#### After:
```
25      #$OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly 
```

### Change 2 - add the list of your DC's on line 26, every DC in the forest should be listed
#### After:
```
26       $OnlineDC = 'DC1','DC3','DC56'
```

  - Or alternatively, keep your PDC list in a text file and read that in
 
#### After:
```
26       $OnlineDC = Get-Content -Path $Base\ComputersDomainTests.txt
```

- Click F5 to run the tests or the Play button.
- Once the tests are complete the two reports will open
  - The Engineer Report (Latest-Domain-Report.html)
  - The Summary Report (Latest-Domain.html)
- These reports can also be found in the following directory: 
  - F:\Project\Reports
    - Only the latest HTML reports are kept
    - There is also raw reporting files in CSV format from Every single Run.

### **Invoke-Tests**

- See the Note from the Invoke-ConnectivityTests (above)
- If you need to keep a Manual List you should replace the following lines in this script

#### Before:
````
24     # Find all online PDC's in the forest (each domain)
25     $OnlineDCObjects = Get-ADSHOnlineDC -PDCOnly
26     $OnlineDC = $OnlineDCObjects.Name | select -last 1
````

### Change 1 - command out line 25 by adding #
#### After:
````
25      #$OnlineDCObjects = Get-ADSHOnlineDC 
````

### Change 2 - add the list of your PDC's on line 26
- you can select any/single Domain Controller from each Domain here
  - They do not have to be the PDC.

#### After:
```
26       $OnlineDC = 'DC1','DC3','DC4','DC5'
```

  - Or alternatively, keep your PDC list in a text file and read that in
 
#### After:
```
26       $OnlineDC = Get-Content -Path $Base\ComputersHostTests.txt
```

- Click F5 to run the tests or the Play button.
  - Note: These tests will take a long time to run, since it runs them against every Domain Controller
- Once the tests are complete the two reports will open
  - The Engineer Report (Latest-Domain-Report.html)
  - The Summary Report (Latest-Domain.html)
- These reports can also be found in the following directory: 
  - F:\Project\Reports
    - Only the latest HTML reports are kept
    - There is also raw reporting files in CSV format from Every single Run.
