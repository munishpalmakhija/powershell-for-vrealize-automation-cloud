Powershell for vRealize-Automation-Cloud


Powershell for vRealize-Automation-Cloud is a PowerShell module that abstracts the VMware vRealize Automation Cloud APIs to a set of easily used PowerShell functions. This tool provides a comprehensive command line environment for managing your VMware vRealize Automation Cloud environment. It is a.k.a PowervRACloud

This module is not supported by VMware, and comes with no warranties expressed or implied. Please test and validate its functionality before using this product in a production environment.

# Pre-requisities 

You need to have following pre-requisties 

1.	vRealize Automation Cloud API Token 
2.	PowerShellVersion = '6.0'

# Manual Download

Right now, PowervRACloud is a simple two-file module stored under module directory. To install it, download it to a PowerShell enabled machine and load it

1.	PowervRACloud.psd1
2.	PowervRACloud.psm1

# Usage

You can download ./doc/PowervRACloudDocumentation.html which has instructions for every command

| Example-1  |
| ------------- |
| Connect-vRA-Cloud -APIToken "APIToken" |

| Example-2  |
| ------------- |
| Get-vRA-CloudAccounts|

# License 

Powershell for vRealize-Automation-Cloud is licensed under <a href="https://github.com/munishpalmakhija/powershell-for-vrealize-automation-cloud/blob/master/LICENSE.txt">GPL v2</a> .