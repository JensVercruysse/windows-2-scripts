$CSVPath = "C:/Scripts/personeel.csv"

Import-Module activedirectory
function DisableInvalidUsers {
    $ValidUsers = Import-Csv -Delimiter ";" -Path $CSVPath | Select-Object -ExpandProperty Account
    $InvalidUsers = Get-ADGroupMember "Domain Users" | Where-Object distinguishedName -like *OU=JJEAfdeling* | Where-Object { $ValidUsers -notcontains $_.SamAccountName }
    foreach ($InvalidUser in $InvalidUsers) {
        Disable-ADAccount -identity $InvalidUser -Confirm:$false
        $DisabledUser = $InvalidUser.SamAccountName
        Write-Output "Disabled $DisabledUser in AD"
    }      
}

DisableInvalidUsers

$Personeel = Import-csv -Delimiter ";" -Path $CSVPath

foreach ($User in $Personeel) {
    $Naam = $User.Naam
    $Voornaam = $User.Voornaam
    $Account = $User.Account
    $Manager = $User.Manager
    $IT = $User.IT
    $Boekhouding = $User.Boekhouding
    $Logistiek = $User.Logistiek
    $ImportExport = $User.ImportExport
    $Email = $Voornaam + "." + $Naam + "@CynMedJJE.be"
    $FullName = "$Voornaam $Naam"

    if ($Voornaam.length -lt 3 -or $Naam.length -lt 3){
    $TempVoornaam = $Voornaam
    $TempNaam = $Naam
    Do{
    $TempVoornaam = $TempVoornaam + "+"
    $TempVoornaam = $TempVoornaam + "+"
    }
    Until($TempVoornaam -ge 3 -and $TempNaam -ge 3)
    $Password = $TempVoornaam.substring(0, 3) + "&" + $TempNaam.substring(0, 3)
    Write-Output "[$Voornaam $Naam] has a name shorter than 3 characters, standard password has been adjusted!"
    } else {
    $Password = $Voornaam.substring(0, 3) + "&" + $Naam.substring(0, 3)
    }

    if (Get-ADUser -F { SamAccountName -eq $Account }) {
        $UserDN = (Get-ADUser -Identity $Account).distinguishedName
        $OU = ""
        $GroupsArray = "" -split ","
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
            Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
                $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
            }
            foreach ($Group in $GroupsArray) {
                Add-ADGroupMember -Identity $Group -Members $Account
            }
            Move-ADObject -Identity $UserDN  -TargetPath "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"
            Write-Output "[$Voornaam $Naam] has been updated"
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
            Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
                $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
            }
            foreach ($Group in $GroupsArray) {
                Add-ADGroupMember -Identity $Group -Members $Account
            }
            Move-ADObject -Identity $UserDN -TargetPath "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"
            Write-Output "[$Voornaam $Naam] has been updated"
        }
    }          
    else {
        $OU = ""
        $GroupsArray = "" -split ","
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
            New-ADUser `
                -Name $FullName `
                -GivenName $Voornaam `
                -Surname $Naam `
                -SamAccountName $Account `
                -EmailAddress $Email `
                -AccountPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force) `
                -ChangePasswordAtLogon: 1 `
                -Path "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"

            Enable-ADAccount -Identity $Account    
            Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
                $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
            }  
            foreach ($Group in $GroupsArray) {
                Add-ADGroupMember -Identity $Group -Members $Account
            }
            Set-ADOrganizationalUnit -Identity "OU=$ManagerOf, OU=JJEAfdeling, DC=CynMedJJE, DC=be" -ManagedBy $Account
            Write-Output "[$Voornaam $Naam] has been created and added to the $OU OU"
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
            New-ADUser `
                -Name $FullName `
                -GivenName $Voornaam `
                -Surname $Naam `
                -SamAccountName $Account `
                -EmailAddress $Email `
                -AccountPassword (ConvertTo-SecureString -String $Password -AsPlainText -Force) `
                -ChangePasswordAtLogon: 1 `
                -Path "OU=$OU, OU=JJEAfdeling, DC=CynMedJJE, DC=be"

            Enable-ADAccount -Identity $Account    
            Get-ADUser -Identity $Account -Properties MemberOf | ForEach-Object {
                $_.MemberOf | Remove-ADGroupMember -Members $_.DistinguishedName -Confirm:$false
            } 
            foreach ($Group in $GroupsArray) {
                Add-ADGroupMember -Identity $Group -Members $Account
            }
            Write-Output "[$Voornaam $Naam] has been created and added to the $OU OU"
        }
    }          
}