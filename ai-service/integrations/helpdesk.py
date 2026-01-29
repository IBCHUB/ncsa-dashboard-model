"""
HelpDesk Integration Client

Provides stub functionality to interact with THCert HelpDesk system.
This implements the TOR requirement for HelpDesk integration.

In production, this would send real HTTP requests to the HelpDesk API.
Currently, it logs the requests for demonstration purposes.
"""

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

# Configuration
HELPDESK_API_URL = os.getenv("HELPDESK_API_URL", "https://helpdesk.thcert.go.th/api")
HELPDESK_API_KEY = os.getenv("HELPDESK_API_KEY", "")  # Set in production
HELPDESK_MOCK_MODE = os.getenv("HELPDESK_MOCK_MODE", "true").lower() == "true"
HELPDESK_LOG_FILE = os.getenv("HELPDESK_LOG_FILE", "/tmp/helpdesk_tickets.jsonl")


@dataclass
class TicketRequest:
    """Represents a HelpDesk ticket creation request."""
    title: str
    description: str
    priority: str  # critical, high, medium, low
    category: str  # incident, threat, vulnerability
    ioc_value: str
    ioc_type: str
    threat_types: list
    risk_score: int
    severity: str
    source_system: str = "TCTI"
    created_at: str = ""
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.utcnow().isoformat() + "Z"


@dataclass
class TicketResponse:
    """Response from HelpDesk API."""
    success: bool
    ticket_id: Optional[str]
    message: str
    mock: bool = False


class HelpDeskClient:
    """
    Client for THCert HelpDesk integration.
    
    This class provides methods to:
    - Create incident tickets from detected threats
    - Log all requests for auditing
    
    In mock mode, requests are logged but not sent to the real API.
    """
    
    def __init__(
        self,
        api_url: str = HELPDESK_API_URL,
        api_key: str = HELPDESK_API_KEY,
        mock_mode: bool = HELPDESK_MOCK_MODE
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.mock_mode = mock_mode
        self._ticket_counter = 0
        
    def create_ticket(self, request: TicketRequest) -> TicketResponse:
        """
        Create a ticket in the HelpDesk system.
        
        Args:
            request: TicketRequest with incident details
            
        Returns:
            TicketResponse with result status
        """
        # Log request for auditing
        self._log_request(request)
        
        if self.mock_mode:
            return self._mock_create_ticket(request)
        else:
            return self._real_create_ticket(request)
    
    def _mock_create_ticket(self, request: TicketRequest) -> TicketResponse:
        """Create a mock ticket (for development/demo)."""
        self._ticket_counter += 1
        mock_id = f"TCTI-{datetime.now().strftime('%Y%m%d')}-{self._ticket_counter:04d}"
        
        logger.info(f"[MOCK] Created HelpDesk ticket: {mock_id}")
        logger.info(f"  Title: {request.title}")
        logger.info(f"  Priority: {request.priority}")
        logger.info(f"  IOC: {request.ioc_value} ({request.ioc_type})")
        
        return TicketResponse(
            success=True,
            ticket_id=mock_id,
            message="Ticket created successfully (mock mode)",
            mock=True
        )
    
    def _real_create_ticket(self, request: TicketRequest) -> TicketResponse:
        """Send real request to HelpDesk API."""
        import httpx
        
        if not self.api_key:
            logger.error("HELPDESK_API_KEY not configured")
            return TicketResponse(
                success=False,
                ticket_id=None,
                message="API key not configured"
            )
        
        try:
            response = httpx.post(
                f"{self.api_url}/tickets",
                json=asdict(request),
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=30.0
            )
            
            if response.status_code == 201:
                data = response.json()
                return TicketResponse(
                    success=True,
                    ticket_id=data.get("ticket_id"),
                    message="Ticket created successfully"
                )
            else:
                logger.error(f"HelpDesk API error: {response.status_code} - {response.text}")
                return TicketResponse(
                    success=False,
                    ticket_id=None,
                    message=f"API error: {response.status_code}"
                )
                
        except Exception as e:
            logger.error(f"HelpDesk connection error: {e}")
            return TicketResponse(
                success=False,
                ticket_id=None,
                message=f"Connection error: {str(e)}"
            )
    
    def _log_request(self, request: TicketRequest) -> None:
        """Log request to file for auditing."""
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "action": "create_ticket",
                "request": asdict(request)
            }
            
            with open(HELPDESK_LOG_FILE, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
                
        except Exception as e:
            logger.warning(f"Could not log request: {e}")


def create_incident_ticket(
    ioc_value: str,
    ioc_type: str,
    description: str,
    risk_score: int,
    severity: str,
    threat_types: list = None,
    threat_actors: list = None
) -> TicketResponse:
    """
    Convenience function to create an incident ticket.
    
    Args:
        ioc_value: The IOC (IP, domain, hash, etc.)
        ioc_type: Type of IOC
        description: Threat description
        risk_score: AI risk score (0-100)
        severity: Severity level (critical, high, medium, low)
        threat_types: Optional list of threat types
        threat_actors: Optional list of threat actors
        
    Returns:
        TicketResponse with result
    """
    threat_types = threat_types or []
    threat_actors = threat_actors or []
    
    # Determine priority from severity
    priority_map = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low"
    }
    priority = priority_map.get(severity.lower(), "medium")
    
    # Build title
    threat_str = ", ".join(threat_types[:2]) if threat_types else "Unknown Threat"
    title = f"[{severity.upper()}] {threat_str} - {ioc_type}: {ioc_value[:50]}"
    
    # Build detailed description
    detail_parts = [
        f"## Threat Intelligence Alert",
        f"",
        f"**IOC Value:** `{ioc_value}`",
        f"**IOC Type:** {ioc_type}",
        f"**Risk Score:** {risk_score}/100",
        f"**Severity:** {severity.upper()}",
        f"",
        f"**Threat Types:** {', '.join(threat_types) if threat_types else 'Not classified'}",
        f"**Threat Actors:** {', '.join(threat_actors) if threat_actors else 'Unknown'}",
        f"",
        f"## Description",
        f"{description}",
        f"",
        f"---",
        f"*Auto-generated by Thailand Cyber Threat Intelligence Platform (TCTI)*"
    ]
    full_description = "\n".join(detail_parts)
    
    request = TicketRequest(
        title=title,
        description=full_description,
        priority=priority,
        category="threat" if threat_types else "incident",
        ioc_value=ioc_value,
        ioc_type=ioc_type,
        threat_types=threat_types,
        risk_score=risk_score,
        severity=severity
    )
    
    client = HelpDeskClient()
    return client.create_ticket(request)
