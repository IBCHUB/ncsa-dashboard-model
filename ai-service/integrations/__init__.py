"""
Integrations module for AI Service.

Contains clients for external system integrations:
- HelpDesk: THCert HelpDesk ticket management
"""

from .helpdesk import (
    HelpDeskClient,
    TicketRequest,
    TicketResponse,
    create_incident_ticket
)

__all__ = [
    "HelpDeskClient",
    "TicketRequest", 
    "TicketResponse",
    "create_incident_ticket"
]
