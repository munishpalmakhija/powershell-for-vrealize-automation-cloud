# Powershell for vRealize-Automation-Cloud


Powershell for vRealize-Automation-Cloud is a PowerShell module that abstracts the VMware vRealize Automation Cloud APIs to a set of easily used PowerShell functions. This tool provides a comprehensive command line environment for managing your VMware vRealize Automation Cloud environment. It is a.k.a PowervRACloud

This module is not supported by VMware, and comes with no warranties expressed or implied. Please test and validate its functionality before using this product in a production environment.

# Pre-requisities 

You need to have following pre-requisties 

1.	vRealize Automation Cloud API Token 
2.	PowerShellVersion = '6.0'

# Manual Download

It is a simple two-file module stored under module directory. 

1.	PowervRACloud.psd1
2.	PowervRACloud.psm1

To install it, download above 2 files to a PowerShell enabled machine and navigate to the folder and execute following command

| Import-Module .\PowervRACloud.psd1  |

# Getting Started

Quick Examples on how to get started 

| Example-1  |
| ------------- |
| Connect-vRA-Cloud -APIToken "APIToken" |

| Example-2  |
| ------------- |
| Get-vRA-CloudAccounts|


# Documentation

You can download the <a href="https://github.com/munishpalmakhija/powershell-for-vrealize-automation-cloud/blob/master/doc/PowervRACloudDocumentation.html">documentation</a> file which has instructions for every command

# License 

Powershell for vRealize-Automation-Cloud is licensed under <a href="https://github.com/munishpalmakhija/powershell-for-vrealize-automation-cloud/blob/master/LICENSE.txt">GPL v2</a> .