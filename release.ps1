$ErrorActionPreference = "Stop"

Write-Host "PMLio Helper Release Tool" -ForegroundColor Blue
Write-Host "--------------------------"

if (-not (Test-Path "package.json")) {
    Write-Host "Error: package.json not found. Run this script from pmlio-helper directory." -ForegroundColor Red
    exit 1
}

$pkg = Get-Content package.json | ConvertFrom-Json
Write-Host "Current version: $($pkg.version)" -ForegroundColor Yellow

Write-Host "Select release type:"
Write-Host "1) Patch (1.0.x)"
Write-Host "2) Minor (1.x.0)"
Write-Host "3) Major (x.0.0)"
Write-Host "4) Custom"
$type = Read-Host "Choice [1-4]"

switch ($type) {
    "1" { $null = npm version patch --no-git-tag-version }
    "2" { $null = npm version minor --no-git-tag-version }
    "3" { $null = npm version major --no-git-tag-version }
    "4" {
        $customV = Read-Host "Enter version (e.g. 1.0.5)"
        $null = npm version $customV --no-git-tag-version
    }
    default { Write-Host "Invalid choice" -ForegroundColor Red; exit 1 }
}

$newPkg = Get-Content package.json | ConvertFrom-Json
$newVersion = "v$($newPkg.version)"
Write-Host "New version: $newVersion" -ForegroundColor Green

git add package.json package-lock.json
git commit -m "chore: bump version to $newVersion"

Write-Host "Pushing tag to origin..." -ForegroundColor Blue
git tag $newVersion
git push origin main
git push origin $newVersion

Write-Host "`n✨ Release $newVersion triggered!" -ForegroundColor Green
Write-Host "Check GitHub Actions to monitor the build process."
