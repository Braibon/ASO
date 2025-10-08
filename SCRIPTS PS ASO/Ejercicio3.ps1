
Write-Host "Array con nombres"

$nombre = ("Leopoldo","Eusebio","Leonor","Josefina","Patricio")
foreach ($nom in $nombre){
    Write-Host " Hola $nom"
}


Write-Host "Array con nombres"

$numero = (1,2,3,4,5,6,7,8,9,10)
foreach ($num in $numero){
    $mult = $num*$num
    Write-Host "$num*$num = $mult"
}