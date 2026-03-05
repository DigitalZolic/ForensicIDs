ForensicIDs Utility is an advanced hardware analysis powershell utility developed by DigitalZolic, released Open Source.

It is designed to reveal technical hardware serial details that are often difficult to access with standard tools or are often completely hidden. It runs locally and extracts a comprehensive hardware and firmware enumeration set, such as hardware serial numbers and other unique hardware identifiers from system hardware, firmware, bios, tpm, virtualization and other high security-related hardware. Often used by in-game Anti-Cheats to issue hardware bans. This utility is therefore vital when it comes to wanting to verify hardware changes / hardware virtualization made by other tools such as Hardware ID Spoofers or Hardware ID Virtualizers.

Run this script before using such tools, then run the script again. Cross-check the serials from before vs after.

If all hardware changed = Perfect.

If hardware did not change = Spoofer or Virtualizer you used, definently requires an update.

In order for ForensicIDs Utility to run, ensure you're setting System Scripts Execution Policy to Unrestricted.

Powershell as Administrator > Command: Set-ExecutionPolicy Unrestricted
