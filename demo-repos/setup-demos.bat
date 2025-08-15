@echo off
REM Semio Demo Repository Setup Script for Windows
REM This script helps you create separate demo repositories for GitLab and GitHub

setlocal enabledelayedexpansion

REM Colors for output (Windows 10+ supports ANSI colors)
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

REM Function to print colored output
:print_status
echo %BLUE%[INFO]%NC% %~1
goto :eof

:print_success
echo %GREEN%[SUCCESS]%NC% %~1
goto :eof

:print_warning
echo %YELLOW%[WARNING]%NC% %~1
goto :eof

:print_error
echo %RED%[ERROR]%NC% %~1
goto :eof

REM Function to check if command exists
:command_exists
where %1 >nul 2>&1
if %errorlevel% equ 0 (
    set "exists=true"
) else (
    set "exists=false"
)
goto :eof

REM Function to create demo repository
:create_demo_repo
set "demo_type=%~1"
set "repo_name=%~2"
set "source_dir=demo-repos\%demo_type%-demo"

call :print_status "Creating %demo_type% demo repository: %repo_name%"

REM Check if source directory exists
if not exist "%source_dir%" (
    call :print_error "Source directory %source_dir% not found!"
    exit /b 1
)

REM Create target directory
if exist "%repo_name%" (
    call :print_warning "Directory %repo_name% already exists. Overwriting..."
    rmdir /s /q "%repo_name%"
)

mkdir "%repo_name%"

REM Copy files
xcopy "%source_dir%\*" "%repo_name%\" /E /I /Y >nul

REM Initialize git repository
cd "%repo_name%"
git init

REM Create initial commit
git add .
git commit -m "Initial commit: Semio %demo_type% demo repository"

call :print_success "Created %demo_type% demo repository in %repo_name%"
call :print_status "Next steps:"
echo   1. Create a new repository on %demo_type%
echo   2. Add remote: git remote add origin ^<repository-url^>
echo   3. Push: git push -u origin main
echo   4. Set up CI variables/secrets
echo   5. Create a PR/MR to test the integration

cd ..
goto :eof

REM Main script
echo %GREEN%🚀 Semio Demo Repository Setup%NC%
echo ==================================
echo.

REM Check prerequisites
call :command_exists git
if "%exists%"=="false" (
    call :print_error "Git is not installed. Please install Git first."
    exit /b 1
)

REM Check if we're in the right directory
if not exist "demo-repos" (
    call :print_error "Please run this script from the Semio project root directory."
    exit /b 1
)

echo This script will create separate demo repositories for:
echo   • GitLab CI integration
echo   • GitHub Actions integration
echo.

REM Ask user for repository names
set /p gitlab_repo="Enter name for GitLab demo repository (default: semio-demo-gitlab): "
if "%gitlab_repo%"=="" set "gitlab_repo=semio-demo-gitlab"

set /p github_repo="Enter name for GitHub demo repository (default: semio-demo-github): "
if "%github_repo%"=="" set "github_repo=semio-demo-github"

echo.
call :print_status "Creating demo repositories..."

REM Create GitLab demo
call :create_demo_repo "gitlab" "%gitlab_repo%"

echo.

REM Create GitHub demo
call :create_demo_repo "github" "%github_repo%"

echo.
echo %GREEN%🎉 Demo repositories created successfully!%NC%
echo.
echo Summary:
echo   • GitLab demo: %gitlab_repo%
echo   • GitHub demo: %github_repo%
echo.
echo Next steps:
echo   1. Create repositories on GitLab and GitHub
echo   2. Push the demo code to the repositories
echo   3. Set up CI variables/secrets
echo   4. Test the integration with PRs/MRs
echo.
echo For detailed instructions, see the README files in each demo repository.

pause
