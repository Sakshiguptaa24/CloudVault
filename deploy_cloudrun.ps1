# CloudVault - Google Cloud Run Deployment Script (PowerShell)
param(
    [Parameter(Mandatory=$false)]
    [string]$ProjectId = "",
    [Parameter(Mandatory=$false)]
    [string]$Region = "us-central1"
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " CloudVault - Google Cloud Run Deployment" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

if (-not $ProjectId) {
    $ProjectId = Read-Host "Enter your Google Cloud Project ID"
}

if (-not $ProjectId) {
    Write-Error "GCP Project ID is required. Exiting."
    exit 1
}

Write-Host "`n1. Setting GCP project to: $ProjectId" -ForegroundColor Yellow
gcloud config set project $ProjectId

Write-Host "`n2. Enabling required Google Cloud APIs (Cloud Run, Cloud Build, Container Registry)..." -ForegroundColor Yellow
gcloud services enable run.googleapis.com cloudbuild.googleapis.com containerregistry.googleapis.com

Write-Host "`n3. Building Docker image in Google Cloud Build..." -ForegroundColor Yellow
$ImageUri = "gcr.io/$ProjectId/cloudvault:latest"
gcloud builds submit --tag $ImageUri

Write-Host "`n4. Deploying container to Google Cloud Run (Region: $Region)..." -ForegroundColor Yellow
gcloud run deploy cloudvault `
    --image $ImageUri `
    --platform managed `
    --region $Region `
    --allow-unauthenticated `
    --port 8000 `
    --memory 512Mi `
    --cpu 1 `
    --set-env-vars "STORAGE_PROVIDER=mock,ALLOWED_ORIGINS=*"

Write-Host "`n Deployment complete! Use the Service URL provided above." -ForegroundColor Green

