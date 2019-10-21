Import-Module activedirectory

$CSVPath = "C:/Scripts/personeel.csv"

Function Disable-User {
    Disable-ADAccount -identity $InvalidUser -Confirm:$false
    $DisabledUser = $InvalidUser.SamAccountName
    Write-Output "$DisabledUser has been disabled!"
}      

Function Update-Groups {
    param([parameter(Mandatory)][String]$Account, [String[]]$GroupsArray)

    Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
        $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
    }
    foreach ($Group in $GroupsArray) {
        Add-ADGroupMember -Identity $Group -Members $Account
    }
}

Function Update-User {
    param([parameter(Mandatory)][String]$Account, [String]$OU, [String[]]$GroupsArray)

    $UserDN = (Get-ADUser -Identity $Account).distinguishedName

    Move-ADObject -Identity $UserDN -TargetPath "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"
    Update-Groups -Account $Account -GroupsArray $GroupsArray
    Enable-ADAccount -Identity $Account 
    Set-ADOrganizationalUnit -Identity "OU=$ManagerOf, OU=JJEAfdeling, DC=CynMedJJE, DC=be" -ManagedBy $Account

    Write-Output "$Account has been updated."
}

Function Initialize-User {
    param([parameter(Mandatory)][String]$Voornaam, [string]$Naam, [String]$Account, [String]$OU, [String[]]$GroupsArray)

    $FullName = "$Voornaam $Naam"
    $Email = $Voornaam + "." + $Naam + "@CynMedJJE.be"
    $Password = $Voornaam + "@CynMedJJE"

    New-ADUser `
        -Name $FullName `
        -GivenName $Voornaam `
        -Surname $Naam `
        -SamAccountName $Account `
        -EmailAddress $Email `
        -AccountPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force) `
        -ChangePasswordAtLogon: 1 `
        -Path "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"

    Update-Groups -Account $Account -GroupsArray $GroupsArray

    Enable-ADAccount -Identity $Account    
    Write-Output "[$Voornaam $Naam] has been created and added to the $OU OU."
}

$Personeel = Import-csv -Delimiter ";" -Path $CSVPath
$NumberOfAdded = 0
$NumberOfUpdated = 0
$NumberOfEnabled = 0
$NumberOfDisabled = 0

$ValidUsers = Import-Csv -Delimiter ";" -Path $CSVPath | Select-Object -ExpandProperty Account
$InvalidUsers = Get-ADGroupMember "Domain Users" | Where-Object distinguishedName -like *OU=JJEAfdeling* | Where-Object { $ValidUsers -notcontains $_.SamAccountName }
foreach ($InvalidUser in $InvalidUsers) {
    Disable-User
    $NumberOfDisabled++
}

foreach ($User in $Personeel) {

    $Naam = $User.Naam
    $Voornaam = $User.Voornaam
    $Account = $User.Account
    $Manager = $User.Manager
    $IT = $User.IT
    $Boekhouding = $User.Boekhouding
    $Logistiek = $User.Logistiek
    $ImportExport = $User.ImportExport

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

    if (Get-ADUser -F { SamAccountName -eq $Account }) {

        $User = Get-ADUser -Identity $Account -Properties DistinguishedName 
        $UserOU = ($User.DistinguishedName -split "=", 3)[-1]
        $OldOU = ($UserOU -split ",", 2)[0]
        
        if ($(Get-ADUser -Identity $Account).enabled -eq $false) {
            Enable-ADAccount -Identity $Account
            Write-Output "$Account has been enabled!"
            $NumberOfEnabled++
        }
        
        if ($OldOU -eq $OU) {
            Write-Output "$Account is up to date."
        }
        else {
            Update-User -Account $Account -OU $OU -GroupsArray $GroupsArray
            $NumberOfUpdated++
        }
    }
    else {
        Initialize-User -Voornaam $Voornaam -Naam $Naam -Account $Account -OU $OU -GroupsArray $GroupsArray
        $NumberOfAdded++
    }
    Set-ADOrganizationalUnit -Identity "OU=$ManagerOf, OU=JJEAfdeling, DC=CynMedJJE, DC=be" -ManagedBy $Account
    Set-ADGroup -Identity $ManagerOf -ManagedBy $Account
}

Write-Output ""
Write-Output "$NumberOfAdded Account(s) added."
Write-Output "$NumberOfUpdated Account(s) updated."
Write-Output "$NumberOfEnabled Account(s) enabled."
Write-Output "$NumberOfDisabled Account(s) disabled."