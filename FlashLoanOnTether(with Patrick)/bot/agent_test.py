from unittest.mock import Mock
from forta_agent import create_transaction_event
from forta_agent.transaction_event import TransactionEvent
from typing import List
from agent import handle_transaction, AAVE_V3_ADDRESS, TOKEN, FLASH_LOAN_TOPIC

mock_tx_event: TransactionEvent = create_transaction_event(
    {"transaction": {"hash": "0x123"}, "address": {"0x159": True}}
)
mock_tx_event.filter_log = Mock()
class TestFlashLoanDetector:
    def test_returns_empty_if_aave_not_found(self):
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) == 0
    
    def test_returns_empty_if_flashloan_not_found(self):
        mock_tx_event.addresses = {AAVE_V3_ADDRESS: True}
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) == 0
    
    def test_returns_finding_in_flash_loan(self):
        mock_tx_event.addresses = {AAVE_V3_ADDRESS: True, TOKEN: True}
        mock_tx_event.logs = [{"topics": [FLASH_LOAN_TOPIC], "address": AAVE_V3_ADDRESS}]
        findings: List[TransactionEvent] = handle_transaction(mock_tx_event)
        assert len(findings) == 1
        