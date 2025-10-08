$numero = 5
Write-Host "Tabla de multiplicar del $numero`n"

# Crear una lista de objetos para la tabla
$tabla = @()
for ($i = 1; $i -le 10; $i++) {
    $tabla += [PSCustomObject]@{
        Multiplicando = $numero
        Multiplicador = $i
        Resultado     = $numero * $i
    }
}

# Mostrar como tabla
$tabla | Format-Table -AutoSize



Write-Host "Suma del 1 al 100"

for ($i = 1; $i -le 100; $i++) {
    $suma=$suma+$i
}

Write-Host "La suma de los 100 primeros numeros es $suma"