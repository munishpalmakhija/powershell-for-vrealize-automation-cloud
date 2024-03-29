#
# Module manifest for module 'PowervRACloud'
#
# Generated by: Munishpal Makhija
#
# Generated on: 6/4/2021
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'PowervRACloud.psm1'

# Version number of this module.
ModuleVersion = '1.5'

# Supported PSEditions
# CompatiblePSEditions = @()

# ID used to uniquely identify this module
GUID = 'd9487589-61e4-4236-af20-0af073a1f4d6'

# Author of this module
Author = 'Munishpal Makhija'

# Company or vendor of this module
CompanyName = 'VMware'

# Copyright statement for this module
Copyright = '(c) 2021 VMware. All rights reserved.'

# Description of the functionality provided by this module
Description = 'PowerShell Module for managing vRA Cloud & vRA 8.x'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '6.0'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Get-vRACloudCommands', 'Connect-vRA-Cloud', 'Connect-vRA-Server', 
               'Disconnect-vRA-Cloud', 'New-vRA-CloudAccount-vSphere', 
               'New-vRA-Server-CloudAccount-vSphere', 'New-vRA-CloudAccount-VMC', 
               'New-vRA-Server-CloudAccount-VMC', 
               'New-vRA-Server-CloudAccount-NSXT', 'New-vRA-CloudAccount-AWS', 
               'New-vRA-CloudAccount-NSXT', 'Get-vRA-CloudAccounts', 
               'Get-vRA-Machines', 'Get-vRA-MachineSnapshots', 'Get-vRA-Regions', 
               'Get-vRA-Datacollectors', 'New-vRA-FlavorProfiles-vSphere', 
               'New-vRA-FlavorProfiles-VMC', 'New-vRA-FlavorProfiles-AWS', 
               'New-vRA-ImageMapping', 'New-vRA-ImageMapping-VMC', 
               'New-vRA-ImageMapping-AWS', 'New-vRA-NetworkProfile', 
               'New-vRA-NetworkProfile-VMC', 'New-vRA-NetworkProfile-AWS', 
               'New-vRA-vSphereStorageProfile', 
               'New-vRA-vSphereStorageProfile-VMC', 'New-vRA-StorageProfile-AWS', 
               'Get-vRA-FlavorProfiles', 'Get-vRA-Flavors', 'Get-vRA-ImageProfiles', 
               'Get-vRA-FabricImages', 'Get-vRA-FabricImagesFilter', 
               'Get-vRA-FabricNetworks', 'Get-vRA-FabricNetworksFilter', 
               'Get-vRA-FabricvSphereDatastores', 
               'Get-vRA-FabricvSphereDatastoresFilter', 'Get-vRA-FabricFlavors', 
               'Get-vRA-FabricvSphereStoragePolicies', 'Get-vRA-Images', 
               'Get-vRA-Networks', 'Get-vRA-NetworkDomains', 
               'Get-vRA-SecurityGroups', 'Get-vRA-NetworkProfiles', 
               'Get-vRA-StorageProfiles', 'Get-vRA-Projects', 'New-vRA-Project', 
               'New-vRA-Project-With-Zone', 'Update-vRA-Project-ZoneConfig', 
               'Add-vRA-Project-Member', 'Add-vRA-Project-Administrator', 
               'Remove-vRA-Project-Member', 'Remove-vRA-Project-Administrator', 
               'Get-vRA-CloudZones', 'Get-vRA-Requests', 'Get-vRA-Tags', 
               'New-vRA-Blueprint', 'Get-vRA-Blueprints', 'Get-vRA-BlueprintDetails', 
               'Get-vRA-BlueprintInputSchema', 'Get-vRA-BlueprintVersions', 
               'Deploy-vRA-Blueprint', 'Get-vRA-Deployments', 
               'Remove-vRA-Deployment', 'Get-vRA-DeploymentFilters', 
               'Get-vRA-DeploymentFilterTypes', 'Get-vRA-DeploymentResources', 
               'Get-vRA-DeploymentActions', 'Change-vRA-DeploymentLease', 
               'Change-vRA-DeploymentOwner', 
               'Create-vRA-DeploymentResourceSnapshot', 
               'Delete-vRA-DeploymentResourceSnapshot', 
               'Get-vRA-DeploymentActionID', 'Get-vRA-DeploymentRequests', 
               'Get-vRA-DeploymentResourceActionID', 
               'Get-vRA-DeploymentResourceActions', 'Get-vRA-SingleDeployment', 
               'PowerOff-vRA-Deployment', 'PowerOff-vRA-DeploymentResource', 
               'PowerON-vRA-Deployment', 'PowerON-vRA-DeploymentResource', 
               'Reboot-vRA-DeploymentResource', 'Reset-vRA-DeploymentResource', 
               'Revert-vRA-DeploymentResourceSnapshot', 
               'Suspend-vRA-DeploymentResource', 'Get-vRA-CodeStreamPipelines', 
               'Get-vRA-CodeStreamPipelineByName', 
               'Get-vRA-CodeStreamPipelineById', 
               'Get-vRA-CodeStreamPipelineByProjectName', 
               'Get-vRA-CodeStreamPipelineExecution', 
               'Export-vRA-CodeStreamPipeline', 'Get-vRA-CodeStreamEndpoints', 
               'Get-vRA-CodeStreamEndpointByName', 
               'Get-vRA-CodeStreamEndpointById', 
               'Get-vRA-CodeStreamEndpointByProjectName', 
               'Import-vRA-CodeStreamPipeline', 'Delete-vRA-CodeStreamPipeline', 
               'Execute-vRA-CodeStreamPipeline'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
VariablesToExport = '*'

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = '*'

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        # Tags = @()

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        # ProjectUri = ''

        # A URL to an icon representing this module.
        # IconUri = ''

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        # ExternalModuleDependencies = @()

    } # End of PSData hashtable

} # End of PrivateData hashtable

# HelpInfo URI of this module
# HelpInfoURI = ''

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

