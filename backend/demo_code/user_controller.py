import subprocess
import os

def process_user_command(user_input):
    # Process user command - VULNERABLE
    if not user_input:
        return "No input provided"
    
    # VULNERABLE: Command injection via shell=True
    # This allows attackers to execute arbitrary commands
    subprocess.call(f"ls {user_input}", shell=True)  # Command injection
    
    # More processing...
    result = process_result(user_input)
    return result

def process_result(user_input):
    # Additional processing logic
    return f"Processed: {user_input}"

def safe_command(user_input):
    # SAFE: No shell=True, input validation
    if not user_input or ";" in user_input or "&" in user_input:
        return "Invalid input"
    
    try:
        result = subprocess.run(["ls", user_input], capture_output=True, text=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError:
        return "Command failed"
