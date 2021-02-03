# vRA Cloud Onboarding for vSphere

# Use Case 

Onboarding vSphere Cloud Account in vRA Cloud Environment / Org

# What Tasks does it perform 

It performs following configuration  

1.	Validate vCenter Details & Adds Cloud Account
2.	Create New vRA Project
3.	Create New vRA Flavor Profile
4.	Create New vRA Image Profile
5.	Create New vRA Network Profile
6.	Create New vRA Storage Profile
7.	Create New vRA Blueprint
8.	Create New vRA Deployment

# Pre-requisites 

1.	PowervRACloud Version 1.1 
2.	Connected to vRA Cloud using Connect-vRA-Cloud -APIToken $APIToken


# Usage

1.	Download the script & csv file in a Folder 
2.	Modify the csv file with your environment details 
3.	Execute ./vrac-onboarding-vsphere.ps1