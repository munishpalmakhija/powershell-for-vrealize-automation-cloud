#Author - Munishpal Makhija

#    ===========================================================================
#    Created by:    Munishpal Makhija
#    Release Date:  03/23/2020
#    Organization:  VMware
#    Version:       1.0
#    Blog:          http://bit.ly/MyvBl0g
#    Twitter:       @munishpal_singh
#    ===========================================================================


####################### Dont Modify anything below this line #########################

Import-CSV ./vrac-environment-vsphere.csv | ForEach-Object { 
	$cloudproxyname = $_.cloudproxyname
	$vCenterIP = $_.vc
	$vcenterdcname = $_.datacentername
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
	
	New-vRA-CloudAccount-vSphere -vCenterHostName $vCenterIP -Credential $vccredential -vCenterDCName $vcenterdcname -CloudProxyName $cloudproxyname -CloudAccountName $cloudaccountname | Out-Null

	Write-Host "Creating New Cloud Account:  " $cloudaccountname -ForegroundColor Green
	
	Start-Sleep -Seconds 15	

	##### Add New Project #####

	Write-Host "Creating New Project:  " $projectname -ForegroundColor Green
	
	$cloudzone = Get-vRA-CloudZones | where {$_.name -match $vCenterIP}
	$cloudzonename = $cloudzone.name
	
	New-vRA-Project-With-Zone -ProjectName $projectname -Zonename $cloudzonename | Out-Null

	##### New vRA Flavor Profile #####
	
	Write-Host "Creating New vRA Flavor Profile:  " $flavorprofilename -ForegroundColor Green
	
	New-vRA-FlavorProfiles-vSphere -ProfileName $flavorprofilename -FlavorName $flavorname -FlavorCpu $flavorcpu -FlavorMemory $flavormemory -RegionName $cloudaccountname | Out-Null


	##### New vRA ImageMapping Profile 

	Write-Host "Creating New vRA Image Profile:  " $imageprofilename -ForegroundColor Green
	
	New-vRA-ImageMapping -ProfileName $imageprofilename -vRAImageName $imagename -CloudAccountName $cloudaccountname -VCImage $vcimage | Out-Null

	
	#### New vRA Network Profile #### 		
	
	Write-Host "Creating New vRA Network Profile:  " $networkprofilename -ForegroundColor Green
	
	New-vRA-NetworkProfile -ProfileName $networkprofilename -CloudAccountName $cloudaccountname -VCNetwork $vcnetwork | Out-Null


	#### New vRA Storage Profile 	

	Write-Host "Creating New vRA Storage Profile:  " $storageprofilename -ForegroundColor Green
	
	New-vRA-vSphereStorageProfile -ProfileName $storageprofilename -CloudAccountName $cloudaccountname -VCDatastore $vcdatastore | Out-Null

	#### New vRA Blueprint ####

	Write-Host "Creating New vRA Blueprint:  " $blueprintname -ForegroundColor Green
	
	New-vRA-Blueprint -ProjectName $projectname -BlueprintName $blueprintname -FlavorName $flavorname -ImageName $imagename | Out-Null 

	#### Deploy vRA Blueprint ####

	Write-Host "Creating New vRA Deployment:  " $deploymentname -ForegroundColor Green
	
	Deploy-vRA-Blueprint -BlueprintName $blueprintname -DeploymentName $deploymentname

}

