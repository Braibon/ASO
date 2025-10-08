$carpeta = if ($num % 2 -eq 0) { "Pares"} else {"Impares"}
$rutacarpeta = Join-Path $ruta $carpeta

if (-not (Test-Path $rutacarpeta)) {
    New-Item Directory -path $rutacarpeta -Force | Out-Null
    Write-Host "El número $num es $carpeta. Carpeta lista en $rutacarpeta"
}
