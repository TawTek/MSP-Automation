This repository contains a curated collection of PowerShell scripts designed for use with Remote Monitoring and Management (RMM) platforms in a Managed Service Provider (MSP) environment.

The goal is to provide reusable, well-documented automation that improves consistency, reduces technician toil, and standardizes how common tasks are executed across client endpoints.

> Target platforms: Windows 10/11 and Windows Server (PowerShell 5.1+ and/or PowerShell 7, depending on script).

## Purpose

- Centralize RMM-ready PowerShell scripts in one version-controlled location.
- Provide **idempotent**, **RMM‑safe** scripts that:
  - Exit with meaningful codes for policy / component success/failure.
  - Write clear, concise output to the RMM console.
  - Avoid leaving temp files, installers, or sensitive data on disk.
- Standardize **pre‑flight checks**, **remediation actions**, and **maintenance tasks** across all clients.
- Serve as a reference library for building new automations.

## Usage with RMM Platforms

These scripts are intended to be **RMM‑agnostic** and should work with most platforms (NinjaOne, DattoRMM, etc.) as long as they can execute PowerShell as SYSTEM or a privileged user.

## Local Testing

Before deploying through an RMM, test scripts locally:

```powershell
# Clone repo
git clone https://github.com/TawTek/RMM-PowerShell-Scripts.git
cd RMM-PowerShell-Scripts

# Run a script locally (example)
.\Scripts\Some-Script.ps1 -WhatIf
```
