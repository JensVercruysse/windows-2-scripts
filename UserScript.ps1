# Import the active directory module to use active directory functions
Import-Module activedirectory

# Path to where the csv file is stored
$CSVPath = "C:/Scripts/personeel.csv"

# Function that disables a given user and writes output to the terminal
Function Disable-User {
    Disable-ADAccount -identity $InvalidUser -Confirm:$false
    $DisabledUser = $InvalidUser.SamAccountName
    Write-Output "$DisabledUser has been disabled!"
}      

# Function that updates a user's groups
Function Update-Groups {
    # This function takes 2 mandatory parameters (AccountName and array of a user's groups)
    param([parameter(Mandatory)][String]$Account, [String[]]$GroupsArray)

    # Delete all groups from the user
    Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
        $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
    }
    # Add all groups the users is a member of
    foreach ($Group in $GroupsArray) {
        Add-ADGroupMember -Identity $Group -Members $Account
    }
}

# Function to update the users OU and write output to the terminal
Function Update-User {
    # This function takes 3 mandatory parameters (AccountName, the user's OU and an array of the user's groups)
    param([parameter(Mandatory)][String]$Account, [String]$OU, [String[]]$GroupsArray)

    $UserDN = (Get-ADUser -Identity $Account).distinguishedName

    # Move the user to the new OU
    Move-ADObject -Identity $UserDN -TargetPath "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"
    # Update the users groups 
    Update-Groups -Account $Account -GroupsArray $GroupsArray 

    Write-Output "$Account has been updated."
}

# Function to create a user and write output to the terminal
Function Initialize-User {
    # This function takes 5 mandatory parameters (Firstname, lastname, Accountname, the user's OU and an array of the user's groups)
    param([parameter(Mandatory)][String]$Voornaam, [string]$Naam, [String]$Account, [String]$OU, [String[]]$GroupsArray)

    # Create a few values needed to make a new ADUser
    $FullName = "$Voornaam $Naam"
    $Email = $Voornaam + "." + $Naam + "@CynMedJJE.be"
    # Set a default password that user has to change on next logon
    $Password = $Voornaam + "@CynMedJJE"

    # Create the new user with all properties
    New-ADUser `
        -Name $FullName `
        -GivenName $Voornaam `
        -Surname $Naam `
        -SamAccountName $Account `
        -EmailAddress $Email `
        -AccountPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force) `
        -Path "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"
    
    # Force user to change password at first logon
    Set-Aduser -Identity $Account -ChangePasswordAtLogon $true

    # Update the user's groups
    Update-Groups -Account $Account -GroupsArray $GroupsArray

    # Enable the user's account
    Enable-ADAccount -Identity $Account    
    Write-Output "[$Voornaam $Naam] has been created and added to the $OU OU."
}

# Import the csv file
$Personeel = Import-csv -Delimiter ";" -Path $CSVPath

# Initialize a few counters to keep track of what has changed
$NumberOfAdded = 0
$NumberOfUpdated = 0
$NumberOfEnabled = 0
$NumberOfDisabled = 0

# Create a list of users from the csv file and compare it to all ADUsers, then disable all ADUsers that are not in the csv file
$ValidUsers = Import-Csv -Delimiter ";" -Path $CSVPath | Select-Object -ExpandProperty Account
$InvalidUsers = Get-ADGroupMember "Domain Users" | Where-Object distinguishedName -like *OU=JJEAfdeling* | Where-Object { $ValidUsers -notcontains $_.SamAccountName }
foreach ($InvalidUser in $InvalidUsers) {

    # Check if the account is already disabled
    if ($(Get-ADUser -Identity $InvalidUser).enabled -eq $true) {
        # If the user was enabled, disable the user
        Disable-User
        $NumberOfDisabled++
    }
    # If the user was already disabled, do nothing
}

# Run this loop for all users in the csv file
foreach ($User in $Personeel) {

    # Get values from the csv 
    $Naam = $User.Naam
    $Voornaam = $User.Voornaam
    $Account = $User.Account
    $Manager = $User.Manager
    $IT = $User.IT
    $Boekhouding = $User.Boekhouding
    $Logistiek = $User.Logistiek
    $ImportExport = $User.ImportExport

    # Initialize variables so managers don't get overwritten 
    $OU = ""
    $ManagerOf = ""
    $GroupsArray = "" -split ","
    
    # If else loop that gets every user's OU, groups and checks if they are managers of any OU or security group
    # Managers are put in the managers OU, the other users are sorted into the correct OU
    if ($Manager -eq "X") {
        if ($IT -eq "X") {
            $OU = "Managers"
            $ManagerOf = "IT"
            $GroupsArray = "Managers,IT" -split ","
        }
        elseif ($Boekhouding -eq "X") {
            $OU = "Managers"
            $ManagerOf = "Boekhouding"
            $GroupsArray = "Managers,Boekhouding" -split ","
        }
        elseif ($Logistiek -eq "X") {
            $OU = "Managers"
            $ManagerOf = "Logistiek"
            $GroupsArray = "Managers,Logistiek" -split ","
        }
        elseif ($ImportExport -eq "X") {
            $OU = "Managers"
            $ManagerOf = "ImportExport"
            $GroupsArray = "Managers,ImportExport" -split ","
        }
        else {
            $OU = "Managers"
            $ManagerOf = "Managers"
            $GroupsArray = "Managers" -split ","
        }
    }
    else {
        if ($IT -eq "X") {
            $OU = "IT"
            $GroupsArray = "IT" -split ","
        }
        elseif ($Boekhouding -eq "X") {
            $OU = "Boekhouding"
            $GroupsArray = "Boekhouding" -split ","
        }
        elseif ($Logistiek -eq "X") {
            $OU = "Logistiek"
            $GroupsArray = "Logistiek" -split ","
        }
        elseif ($ImportExport -eq "X") {
            $OU = "ImportExport"
            $GroupsArray = "ImportExport" -split ","
        }
    }

    # Check if a user already exists in Active Directory
    if (Get-ADUser -F { SamAccountName -eq $Account }) {

        # If a user already exits check if the OU has changed, if so update the OU
        $User = Get-ADUser -Identity $Account -Properties DistinguishedName 
        $UserOU = ($User.DistinguishedName -split "=", 3)[-1]
        $OldOU = ($UserOU -split ",", 2)[0]
        
        # Check if a user that is in the csv file is disabled (might have been ill for a long time), 
        # if so enable the account and write feedback to the terminal
        if ($(Get-ADUser -Identity $Account).enabled -eq $false) {
            Enable-ADAccount -Identity $Account
            Write-Output "$Account has been enabled!"
            $NumberOfEnabled++
        }
        
        # If the OU has not been changed, write feedback to terminal and check next user
        if ($OldOU -eq $OU) {
            Write-Output "$Account is up to date."
        }
        # If the OU has changed, update the OU
        else {
            Update-User -Account $Account -OU $OU -GroupsArray $GroupsArray
            $NumberOfUpdated++
        }
    }
    else {
        # If the user does not exist yet, create the user
        Initialize-User -Voornaam $Voornaam -Naam $Naam -Account $Account -OU $OU -GroupsArray $GroupsArray
        $NumberOfAdded++
    }
    # Set the ManagedBy property of OU's and security groups to the correct manager
    if ($ManagerOf -ne "") {
        Set-ADOrganizationalUnit -Identity "OU=$ManagerOf, OU=JJEAfdeling, DC=CynMedJJE, DC=be" -ManagedBy $Account
        Set-ADGroup -Identity $ManagerOf -ManagedBy $Account
    }
}

# Write feedback to the terminal about all changes
Write-Output ""
Write-Output "$NumberOfAdded Account(s) added."
Write-Output "$NumberOfUpdated Account(s) updated."
Write-Output "$NumberOfEnabled Account(s) enabled."
Write-Output "$NumberOfDisabled Account(s) disabled."