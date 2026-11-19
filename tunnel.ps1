# CloudVault - Public HTTPS Tunnel Launcher
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " CloudVault - Public HTTPS Tunnel Launcher" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "`nConnecting your local CloudVault instance (http://localhost:8000) to the public web..." -ForegroundColor Yellow
Write-Host "Share the generated HTTPS URL to test on your phone, tablet, or external laptop.`n" -ForegroundColor Gray
Write-Host "Press Ctrl+C to terminate the tunnel at any time.`n" -ForegroundColor DarkGray

ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run

