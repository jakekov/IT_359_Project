# IT_359_Project
This is our semester long project for IT359 we are creating our own automated penetration testing tool.

This script is a real-time intrusion detection + auto-blocking tool for SSH brute-force attacks. It watches your system logs, counts failed login attempts per IP, and then alerts or blocks attackers automatically using iptables.

Tested with Hydra ran with word list rockyou_1.txt
  (On attackers machine)
  sudo apt update
  sudo install Hydra

wordlist found
  https://github.com/dw0rsec/rockyou.txt
