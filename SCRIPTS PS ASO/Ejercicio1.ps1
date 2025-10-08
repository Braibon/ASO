[int] $edad = Read-Host
if ($edad -lt 18) {
     Write-Host "Es menor (carsel instantanea)"
} 
else {
    Write-Host "Es mayor (legal)"
}

