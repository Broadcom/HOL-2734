#!/usr/bin/env python3
import os
import sys
import subprocess

def run_powershell_script():
    # Primary explicit path
    explicit_path = "/home/holuser/Documents/files/disable_vsan_apm.ps1"
    
    # Fallback to the directory where this Python file lives
    script_dir = os.path.dirname(os.path.abspath(__file__))
    fallback_path = os.path.join(script_dir, "disable_vsan_apm.ps1")

    # Path resolution logic
    if os.path.exists(explicit_path):
        target_script = explicit_path
    elif os.path.exists(fallback_path):
        target_script = fallback_path
    else:
        print(f"Error: Could not find 'disable_vsan_apm.ps1' at '{explicit_path}' or '{fallback_path}'.", file=sys.stderr)
        sys.exit(1)

    print(f"Targeting PowerShell Script: {target_script}")
    print("Starting execution...\n")

    # Detect execution binary (pwsh for Linux/macOS, powershell.exe for Windows)
    ps_executable = "pwsh" if sys.platform != "win32" else "powershell.exe"

    cmd = [
        ps_executable,
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", target_script
    ]

    try:
        # Executes pwsh and streams standard output/error live to console
        process = subprocess.run(cmd, check=True)
        
        print("\n======================================================================")
        print("Python Runner: PowerShell script completed successfully!")
        print("======================================================================")

    except subprocess.CalledProcessError as e:
        print(f"\nPython Runner Error: PowerShell script exited with error code {e.returncode}.", file=sys.stderr)
        sys.exit(e.returncode)
    except FileNotFoundError:
        print(f"Error: '{ps_executable}' executable not found in PATH. Ensure PowerCLI/PowerShell Core is installed.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    run_powershell_script()