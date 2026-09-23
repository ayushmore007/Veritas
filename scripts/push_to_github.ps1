# PowerShell Script to Create GitHub Repo and Push Veritas
# Usage: .\scripts\push_to_github.ps1 [-RepoName "Veritas"] [-Private]

param (
    [string]$RepoName = "Veritas",
    [switch]$Private = $false
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛰️  VERITAS SENTINEL — GITHUB REPOSITORY INITIALIZATION" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Stage all project files
Write-Host "`n[1/4] Staging project files..." -ForegroundColor Yellow
git add .

# 2. Commit changes
Write-Host "[2/4] Committing changes..." -ForegroundColor Yellow
git commit -m "feat: complete Veritas Sentinel security engine, web dashboard, and digital twin live scanner"

# Set branch to main
git branch -M main

# 3. Check if GitHub CLI (gh) is installed
$ghInstalled = Get-Command gh -ErrorAction SilentlyContinue

if ($ghInstalled) {
    Write-Host "[3/4] GitHub CLI detected. Creating repository on GitHub..." -ForegroundColor Yellow
    $visibility = if ($Private) { "--private" } else { "--public" }
    
    # Create repo and push via gh
    gh repo create $RepoName $visibility --source=. --remote=origin --push --description "Explainable AI defense, telemetry grounding, and real-time security dashboard for encrypted QUIC traffic."
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ Repository successfully created and pushed to GitHub!" -ForegroundColor Green
        Write-Host "View your repo at: https://github.com/$(gh api user -q .login)/$RepoName" -ForegroundColor Cyan
    } else {
        Write-Host "`nNote: If repo already exists, pushing directly..." -ForegroundColor Yellow
        git push -u origin main
    }
} else {
    Write-Host "[3/4] GitHub CLI (gh) not detected." -ForegroundColor Yellow
    Write-Host "`nTo link to an existing or new GitHub repository manually:" -ForegroundColor Cyan
    Write-Host "1. Create a repository on GitHub (https://github.com/new)" -ForegroundColor White
    Write-Host "2. Run the following commands in this terminal:" -ForegroundColor White
    Write-Host "   git remote add origin https://github.com/<YOUR_USERNAME>/$RepoName.git" -ForegroundColor Green
    Write-Host "   git push -u origin main" -ForegroundColor Green
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
