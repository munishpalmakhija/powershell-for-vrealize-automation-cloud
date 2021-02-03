#Author - Munishpal Makhija

#    ===========================================================================
#    Created by:    Munishpal Makhija
#    Release Date:  06/26/2020
#    Organization:  VMware
#    Version:       1.0
#    Blog:          http://bit.ly/MyvBl0g
#    Twitter:       @munishpal_singh
#    ===========================================================================


####################### Dont Modify anything below this line #########################

Import-CSV ./vrac-environment-vmc.csv | ForEach-Object { 
	$vmcapikey = $_.vmcapikey
	$cloudproxyname = $_.cloudproxyname
	$vmcsddcname = $_.sddcname
	$vCenterIP = $_.vc
	$vmcnsxip = $_.nsxip
	$cloudaccountname  = $_.cloudaccountname
	$projectname = $_.projectname
	$flavorprofilename = $_.flavorprofilename
	$flavorname = $_.flavorname
	$flavorcpu = $_.flavorcpu
	$flavormemory = $_.flavormemory
	$imageprofilename = $_.imageprofilename
	$imagename = $_.imagename
	$vcimage = $_.vcimage
	$networkprofilename = $_.networkprofilename
	$vcnetwork = $_.vcnetwork
	$storageprofilename = $_.storageprofilename
	$vcdatastore = $_.vcdatastore
	$blueprintname = $_.blueprintname
	$deploymentname = $_.deploymentname

	##### Add New Cloud Account #####

	$vccredential = Get-Credential

	$vmctoken = ConvertTo-SecureString $vmcapikey -AsPlainText -Force

	New-vRA-Server-CloudAccount-VMC -VMC_API_KEY $vmctoken -VMC_SDDC_Name $vmcsddcname -vCenterHostname $vCenterIP -Credential $vccredential -VMC_NSX_IP $vmcnsxip -CloudAccountName $cloudaccountname | Out-Null
	

	Write-Host "Creating New Cloud Account:  " $cloudaccountname -ForegroundColor Green
	
	Start-Sleep -Seconds 240	

	##### Add New Project #####

	Write-Host "Creating New Project:  " $projectname -ForegroundColor Green
	
	$cloudzone = Get-vRA-CloudZones | where {$_.name -match $cloudaccountname -and ($_.folder -eq "Workloads")}
	$cloudzonename = $cloudzone.name
	
	New-vRA-Project-With-Zone -ProjectName $projectname -Zonename $cloudzonename | Out-Null

	##### New vRA Flavor Profile for VMC #####
	
	Write-Host "Creating New vRA Flavor Profile for VMC:  " $flavorprofilename -ForegroundColor Green
	
	New-vRA-FlavorProfiles-VMC -ProfileName $flavorprofilename -FlavorName $flavorname -FlavorCpu $flavorcpu -FlavorMemory $flavormemory -RegionName $cloudaccountname | Out-Null


	##### New vRA ImageMapping Profile for VMC ####

	Write-Host "Creating New vRA Image Profile for VMC:  " $imageprofilename -ForegroundColor Green
	
	New-vRA-ImageMapping-VMC -ProfileName $imageprofilename -vRAImageName $imagename -CloudAccountName $cloudaccountname -VCImage $vcimage | Out-Null

	
	#### New vRA Network Profile for VMC #### 		
	
	Write-Host "Creating New vRA Network Profile for VMC:  " $networkprofilename -ForegroundColor Green
	
	New-vRA-NetworkProfile-VMC -ProfileName $networkprofilename -CloudAccountName $cloudaccountname -VCNetwork $vcnetwork | Out-Null


	#### New vRA Storage Profile for VMC ####	

	Write-Host "Creating New vRA Storage Profile for VMC:  " $storageprofilename -ForegroundColor Green
	
	New-vRA-vSphereStorageProfile-VMC -ProfileName $storageprofilename -CloudAccountName $cloudaccountname -VCDatastore $vcdatastore | Out-Null

	#### New vRA Blueprint ####

	Write-Host "Creating New vRA Blueprint:  " $blueprintname -ForegroundColor Green
	
	New-vRA-Blueprint -ProjectName $projectname -BlueprintName $blueprintname -FlavorName $flavorname -ImageName $imagename | Out-Null 

	#### Deploy vRA Blueprint ####

	Write-Host "Creating New vRA Deployment:  " $deploymentname -ForegroundColor Green
	
	Deploy-vRA-Blueprint -BlueprintName $blueprintname -DeploymentName $deploymentname

}
