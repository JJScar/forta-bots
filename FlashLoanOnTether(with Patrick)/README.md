# AAVE USDT Flashloan Monitor Bot
## Overview
This Forta bot monitors the AAVE protocol for flashloans performed using USDT. The bot is designed to flag any instances of USDT-based flashloans on AAVE, providing real-time alerts and events for protocol administrators and stakeholders.

## Configuration
This bot is configured to monitor the AAVE protocol for the following conditions:

- Flashloans performed using USDT as the loan asset
- Loan events emitted by the AAVE protocol
  
## Functionality
The bot uses Forta's blockchain monitoring capabilities to scan the AAVE protocol for flashloan events. When a flashloan event is detected, the bot triggers an alert and provides relevant details about the transaction, to your preferred use of communication, including:

- Transaction hash
- Block number
- Loan amount
- Loan asset (USDT)
- Deployment

## Requirements
- Python
- Forta Python SDK

This was a practice project, lead by Patrick Collins, in order to learn more about these bots. 