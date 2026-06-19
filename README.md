# Recon All-in-One Pipeline

This is a comprehensive, standalone Python pipeline that chains together 11 distinct recon and vulnerability scanning phases into a single automated workflow. It runs locally via CLI without requiring any Telegram integrations.

## Features & Phases

The pipeline runs sequentially (with error tolerance allowing it to skip phases safely):
1. **Masscan Port Scan:** Rapidly scans a list of IPs for open ports (requires `masscan.exe` or `masscan`).
2. **Web Checker:** Verifies live HTTP/HTTPS services and extracts server headers/titles.
3. **Reverse IP:** Discovers domains associated with the IPs using 11+ APIs.
4. **Subdomain Finder:** Enumerates subdomains for the discovered root domains.
5. **Domain → IP Resolution:** Resolves all newly discovered domains back to IPs.
6. **CMS Fingerprinting:** Detects WordPress, Joomla, and Drupal installations.
7. **Web Shell Detection:** Scans for hidden web shells, uploaders, and mailers across common paths.
8. **API Hunter (Secret Key Scanner):** Hunts for exposed `.env` files, API keys, and debug pages using advanced 403-bypass techniques.
9. **NLA Checker:** Validates RDP (port 3389) Network Level Authentication status.
10. **SSH Port Scan:** Identifies active SSH services on port 22.
11. **SSH Cracker:** Performs a dictionary attack using custom users/passwords lists (requires `sshcracker` binary).

## Requirements

- Python 3.8+
- Requirements listed in `bot.py` (e.g. `requests`, `beautifulsoup4`)
- Third-party binaries (must be in system PATH or the working directory):
  - `masscan` / `masscan.exe`
  - `sshcracker` / `sshcracker.exe` (Optional, only for Phase 11)

## Usage

1. Open your terminal.
2. Navigate to the `recon_all` directory.
3. Run the main script:
   ```bash
   python main.py
   ```
4. Follow the interactive CLI prompts to configure:
   - Targets file
   - Ports to scan
   - Masscan rate
   - Threads
   - Output folder name

The pipeline will execute, displaying real-time progress bars and saving organized results into the `recon_results/<your_output_folder>` directory.
