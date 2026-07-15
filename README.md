# Home SOC Lab 🛡️

A hands on Security Operations Center (SOC) lab built from scratch to practice threat detection, alert triage, and incident response using free, open-source tools on a home PC.

## Overview

This project simulates a small SOC environment:
- A **Wazuh SIEM** server monitors and logs security events
- A **Kali Linux** attacker machine generates real attack traffic
- All activity is analyzed through the Wazuh dashboard, just like a real analyst would

Built entirely on a resource-constrained laptop (16GB RAM), which meant a lot of real-world troubleshooting - documented below.

## Architecture

| Component | Details |
|---|---|
| Hypervisor | Oracle VirtualBox |
| SIEM | Wazuh 4.14.6 (indexer + server + dashboard, all-in-one) |
| SIEM Host OS | Ubuntu Server 22.04 LTS |
| Attacker | Kali Linux 2025.4 |
| Network | Host-only adapter (lab isolation) + NAT (internet access) |

## Build Log

### Phase 1: Environment Setup
- Installed VirtualBox, created a Hostonly network for lab isolation
- Built Ubuntu Server VM (6GB RAM, 2 vCPU, 50GB disk)

### Phase 2: Wazuh Installation
This was the most challenging phase. Issues encountered and fixed:
- **No internet access**: Host-only network doesn't route to the internet by design. added a second NAT adapter for package downloads
- **Disk space errors**: Ubuntu's installer under-allocated the LVM logical volume (23GB used out of a 50GB disk)  resized with `lvextend` + `resize2fs`
- **Download timeouts**: Large indexer package (~874MB) timed out mid download, resolved with a retry
- **Port conflict**: A leftover process from a failed install held port 55000, identified with `lsof` and killed
- **API registration race condition**: Dashboard service started before the Wazuh API was fully initialized, required a clean reinstall after purging stale packages

After multiple attempts, the install completed successfully with all three components (indexer, manager, dashboard) running.

### Phase 3:  Dashboard Access & Verification
- Confirmed dashboard access via `https://<host-only-ip>`
- Reset admin credentials using Wazuh's built in `wazuh-passwords-tool.sh` after login issues

### Phase 4: Attack Simulation (Kali)
- Verified network connectivity between Kali and the Wazuh server (Host-only network)
- Ran an `nmap -sV` service-version scan against the Wazuh server
- Reviewed captured events in Wazuh's **Discover** tab confirmed the manager logs system-level activity (SSH logins, sudo usage, PAM authentication events)
- **Next**: simulate failed SSH login attempts to generate higher-severity authentication alerts

## Lessons Learned

- Host-only networks provide isolation but require a second adapter for internet access during setup
- Default Ubuntu LVM partitioning doesn't always use the full allocated disk, always verify with `df -h`
- Resource constrained VMs (6GB RAM) can cause install processes to fail unpredictably, patience and systematic log reading (`/var/log/wazuh-install.log`) were essential for diagnosing each failure, Wazuh's manager + agent cannot coexist on the same host in a standard install, a dedicated agent host is needed for full endpoint monitoring
- ## Screenshot
- ## Brute force SSH detection
- ![Wazuh alert showing failed SSH login attempts](wazuhbruteforcealert.png)


- *Wazuh Discover view showing captured autentication failure events (rule.level 10) after a stimulated SSH brute force attempt from kali Linux.*
