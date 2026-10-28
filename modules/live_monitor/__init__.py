"""
AI SOC Assistant - Live Monitor Package
Provides normalized security event schemas, stateful sliding-window detection rules,
agent registration, Windows and Linux log collectors.
"""

from .event_schema import SecurityEvent, SecurityEventBatch, SecurityEventType, normalize_security_event
from .detection_rules import LiveDetectionEngine, DetectionRuleAlert
