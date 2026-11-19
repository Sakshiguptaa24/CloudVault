@echo off
echo ========================================================
echo  CloudVault - Public HTTPS Tunnel Launcher
echo ========================================================
echo.
echo Launching public HTTPS tunnel to http://localhost:8000 ...
echo Access the provided HTTPS URL on any phone, tablet or laptop.
echo Press Ctrl+C at any time to terminate the tunnel.
echo.
ssh -o StrictHostKeyChecking=no -R 80:localhost:8000 nokey@localhost.run

