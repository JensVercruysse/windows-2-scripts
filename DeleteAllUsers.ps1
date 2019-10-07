Import-Module activedirectory

$Personeel = Import-csv -Delimiter ";" -Path "C:/Scripts/personeel.csv"

foreach ($User in $Personeel) {
    $Naam = $User.Naam
    $Voornaam = $User.Voornaam
    $Account = $User.Account
    $Manager = $User.Manager
    $IT = $User.IT
    $Boekhouding = $User.Boekhouding
    $Logistiek = $User.Logistiek
    $ImportExport = $User.ImportExport
    $FullName = $Voornaam + $Naam

    Remove-ADUser -Identity $Account -Confirm:$false
    Write-Output "[$Voornaam $Naam] has been removed"

}