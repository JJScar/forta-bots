# Goal - Build a bot the detects a FlashLoan used with Tether

from typing import List
from forta_agent import transaction_event, Finding, FindingType, FindingSeverity

AAVE_V3_ADDRESS = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2".lower()
FLASH_LOAN_TOPIC = "0xefefaba5e921573100900a3ad9cf29f222d995fb3b6045797eaea7521bd8d6f0".lower()
TOKEN = "0xdac17f958d2ee523a2206206994597c13d831ec7".lower()
TOKEN_WATCHLIST = [TOKEN]
def handle_transaction(
        transaction_event: transaction_event.TransactionEvent) -> List[transaction_event.TransactionEvent]:
    """
    Handles a transaction event and returns a list of findings that have a flashloan.
    """
    findings: List[transaction_event.TransactionEvent] = []
    
    addresses_lower = [key.lower() for key in transaction_event.addresses.keys()]
    
    if AAVE_V3_ADDRESS not in addresses_lower:
        return findings
    
    flash_loan_events = []
    
    for log in transaction_event.logs:
        for topic in log["topics"]:
            if topic.lower() == FLASH_LOAN_TOPIC:
                flash_loan_events.append(log)   
    
    if len(flash_loan_events) == 0:
        return findings
    
    for address in TOKEN_WATCHLIST:
        if address in addresses_lower: 
            findings.append(Finding(
                {
                    "name": "Potential FlashLoan Attack",
                    "description": f"A user has performed a FlashLoan using USDT, detected with hash {transaction_event.hash}",
                    "alert_id": "TERA-6",
                    "protocol": "AAVE",
                    "type": FindingType.Suspicious,
                    "severity": FindingSeverity.Low,
                }))
    
    return findings
