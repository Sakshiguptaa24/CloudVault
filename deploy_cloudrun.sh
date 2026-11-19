#!/usr/bin/env bash
# CloudVault - Google Cloud Run Deployment Script (Bash)
set -e

echo "=========================================================="
echo " CloudVault - Google Cloud Run Deployment"
echo "=========================================================="

PROJECT_ID=${1:-$GCP_PROJECT_ID}
REGION=${2:-"us-central1"}

if [ -z "$PROJECT_ID" ]; then
    read -p "Enter your Google Cloud Project ID: " PROJECT_ID
fi

if [ -z "$PROJECT_ID" ]; then
    echo "Error: GCP Project ID is required."
    exit 1
fi

echo "1. Configuring gcloud project..."
gcloud config set project "$PROJECT_ID"

echo "2. Enabling GCP APIs..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com containerregistry.googleapis.com

IMAGE_URI="gcr.io/${PROJECT_ID}/cloudvault:latest"

echo "3. Building container with Cloud Build..."
gcloud builds submit --tag "$IMAGE_URI"

echo "4. Deploying to Cloud Run..."
gcloud run deploy cloudvault \
    --image "$IMAGE_URI" \
    --platform managed \
    --region "$REGION" \
    --allow-unauthenticated \
    --port 8000 \
    --memory 512Mi \
    --cpu 1 \
    --set-env-vars "STORAGE_PROVIDER=mock,ALLOWED_ORIGINS=*"

echo "Deployment complete!"

