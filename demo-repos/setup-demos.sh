#!/bin/bash

# Semio Demo Repository Setup Script
# This script helps you create separate demo repositories for GitLab and GitHub

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to create demo repository
create_demo_repo() {
    local demo_type=$1
    local repo_name=$2
    local source_dir="demo-repos/${demo_type}-demo"
    
    print_status "Creating ${demo_type} demo repository: ${repo_name}"
    
    # Check if source directory exists
    if [ ! -d "$source_dir" ]; then
        print_error "Source directory $source_dir not found!"
        return 1
    fi
    
    # Create target directory
    if [ -d "$repo_name" ]; then
        print_warning "Directory $repo_name already exists. Overwriting..."
        rm -rf "$repo_name"
    fi
    
    mkdir -p "$repo_name"
    
    # Copy files
    cp -r "$source_dir"/* "$repo_name/"
    
    # Initialize git repository
    cd "$repo_name"
    git init
    
    # Create initial commit
    git add .
    git commit -m "Initial commit: Semio ${demo_type} demo repository"
    
    print_success "Created ${demo_type} demo repository in $repo_name"
    print_status "Next steps:"
    echo "  1. Create a new repository on ${demo_type}"
    echo "  2. Add remote: git remote add origin <repository-url>"
    echo "  3. Push: git push -u origin main"
    echo "  4. Set up CI variables/secrets"
    echo "  5. Create a PR/MR to test the integration"
    
    cd ..
}

# Main script
main() {
    echo -e "${GREEN}🚀 Semio Demo Repository Setup${NC}"
    echo "=================================="
    echo ""
    
    # Check prerequisites
    if ! command_exists git; then
        print_error "Git is not installed. Please install Git first."
        exit 1
    fi
    
    # Check if we're in the right directory
    if [ ! -d "demo-repos" ]; then
        print_error "Please run this script from the Semio project root directory."
        exit 1
    fi
    
    echo "This script will create separate demo repositories for:"
    echo "  • GitLab CI integration"
    echo "  • GitHub Actions integration"
    echo ""
    
    # Ask user for repository names
    read -p "Enter name for GitLab demo repository (default: semio-demo-gitlab): " gitlab_repo
    gitlab_repo=${gitlab_repo:-semio-demo-gitlab}
    
    read -p "Enter name for GitHub demo repository (default: semio-demo-github): " github_repo
    github_repo=${github_repo:-semio-demo-github}
    
    echo ""
    print_status "Creating demo repositories..."
    
    # Create GitLab demo
    create_demo_repo "gitlab" "$gitlab_repo"
    
    echo ""
    
    # Create GitHub demo
    create_demo_repo "github" "$github_repo"
    
    echo ""
    echo -e "${GREEN}🎉 Demo repositories created successfully!${NC}"
    echo ""
    echo "Summary:"
    echo "  • GitLab demo: $gitlab_repo"
    echo "  • GitHub demo: $github_repo"
    echo ""
    echo "Next steps:"
    echo "  1. Create repositories on GitLab and GitHub"
    echo "  2. Push the demo code to the repositories"
    echo "  3. Set up CI variables/secrets"
    echo "  4. Test the integration with PRs/MRs"
    echo ""
    echo "For detailed instructions, see the README files in each demo repository."
}

# Run main function
main "$@"
