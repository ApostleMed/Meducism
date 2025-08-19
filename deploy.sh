#!/bin/bash

# Deployment script for Meducism Platform
echo "🚀 Deploying Meducism Platform..."

# Add all files to git
git add .

# Commit changes
git commit -m "Deploy: Premium Meducism platform with royal blue design and dynamic animations"

# Add remote if it doesn't exist
git remote get-url origin 2>/dev/null || git remote add origin https://github.com/ApostleMed/MeducismPortal.git

# Push to GitHub
git push -u origin main

echo "✅ Successfully deployed to GitHub!"
echo "🌐 Repository: https://github.com/ApostleMed/MeducismPortal"
echo "📝 Next: Import this repository to Vercel for deployment"