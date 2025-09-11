"""
Sem.io CICD - AI Security Analysis Agent
Hugging Face Spaces Deployment Entry Point
"""

import os
import sys
import gradio as gr

# Add the backend directory to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

# Import the dashboard
from backend.app.dashboard import create_dashboard

def main():
    """Main entry point for Hugging Face Spaces"""
    
    # Set up environment variables for Hugging Face
    os.environ.setdefault('HUGGINGFACE_SPACE', 'True')
    
    # Create and launch the dashboard
    dashboard = create_dashboard()
    
    # Launch with Hugging Face Spaces configuration
    dashboard.launch(
        server_name="0.0.0.0",  # Required for Hugging Face Spaces
        server_port=7860,       # Default Hugging Face port
        share=False,            # Don't create public link (HF handles this)
        show_error=True,        # Show errors in the interface
        quiet=False             # Show startup messages
    )

if __name__ == "__main__":
    main()
