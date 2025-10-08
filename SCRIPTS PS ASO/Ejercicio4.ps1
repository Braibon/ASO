$opcion=""

while ($opcion -ne "3") {
    Write-Host "Elige una de las siguientes opciones"
    Write-Host "Mostrar fecha actual"
    Write-Host "Mostrar usuario actual"
    Write-Host "Salir"
}

$opcion = Read-Host

Clear-Host
[double] $nota = Read-Host "Introduce tu nota: "
switch ($opcion) {
    {$nota -ge 9 -and $nota -le 10} {Write-Host "Sobresaliente"}
    {$nota -ge 7 -and $nota -le 8} {Write-Host "Notable"}
    {$nota -ge 5 -and $nota -le 6} {Write-Host "Aprobado"}
    {$nota -ge 0 -and $nota -le 4} {Write-Host "Suspenso"}
 
}