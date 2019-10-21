Import-Module activedirectory

$Personeel = Import-csv -Delimiter ";" -Path "C:/Scripts/personeel.csv"

foreach ($User in $Personeel) {
    $Naam = $User.Naam
    $Voornaam = $User.Voornaam
    $Account = $User.Account

    Remove-ADUser -Identity $Account -Confirm:$false
    Write-Output "[$Voornaam $Naam] has been removed"

}
