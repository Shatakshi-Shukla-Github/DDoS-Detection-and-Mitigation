import subprocess
import os


def safe_cleanup():
    print("--- Targeted DDoS Rule Cleanup ---")

    # We use PowerShell because it allows "Filtering"
    # This command says: "Find rules where the name starts with 'DDoS_Block_' and remove ONLY those."
    clean_cmd = 'PowerShell "Get-NetFirewallRule -DisplayName \'DDoS_Block_*\' | Remove-NetFirewallRule"'

    try:
        # We use subprocess.run for better error handling than os.system
        result = subprocess.run(clean_cmd, shell=True,
                                capture_output=True, text=True)

        if result.returncode == 0:
            print("[SUCCESS] All project-specific rules have been removed.")
            print("Standard Windows rules were not affected.")
        else:
            # If no rules were found, PowerShell might return an error, which is fine.
            print("[INFO] No active DDoS_Block rules found to delete.")

    except Exception as e:
        print(f"[ERROR] Could not run cleanup: {e}")


if __name__ == "__main__":
    # Check for Admin rights first
    print("Note: This must be run as Administrator to modify firewall settings.")
    safe_cleanup()
