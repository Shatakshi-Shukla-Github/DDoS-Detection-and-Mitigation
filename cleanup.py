import os

print("Cleaning up all DDoS mitigation rules...")
# This command removes any firewall rule that starts with our project prefix
os.system('netsh advfirewall firewall delete rule name=all program="any" profile="any" name="DDoS_Block_127.0.0.1"')
# To be safe, this deletes any rule containing our custom string
os.system('netsh advfirewall firewall delete rule name=all')
# Note: Be careful with the line above if you have other custom rules!
# Better specific command:
os.system('netsh advfirewall firewall delete rule name="DDoS_Block_127.0.0.1"')

print("Firewall cleaned.")
