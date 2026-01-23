"""Notification routing for event-to-channel mapping.

This module provides routing logic to determine which channels and targets
should receive notifications for specific event types.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Optional

from .types import ChannelType, NotificationPayload, NotificationPriority

logger = logging.getLogger(__name__)


class MatchType(str, Enum):
    """Type of pattern matching for routing rules."""

    EXACT = "exact"
    PREFIX = "prefix"
    REGEX = "regex"
    WILDCARD = "wildcard"


class RouteAction(str, Enum):
    """Action to take when a route matches."""

    DELIVER = "deliver"  # Deliver to the channels
    SUPPRESS = "suppress"  # Suppress the notification
    TRANSFORM = "transform"  # Transform the payload


@dataclass
class RoutingRule:
    """Rule for routing notifications to channels.

    Attributes:
        id: Unique rule identifier
        name: Human-readable rule name
        event_pattern: Pattern to match event types
        match_type: Type of pattern matching
        channels: Channels to route to
        priority: Priority for this channel
        action: Action to take
        conditions: Additional conditions for matching
        transformer: Optional payload transformer function
        is_active: Whether the rule is active
        order: Execution order (lower = earlier)
    """

    id: str
    name: str
    event_pattern: str
    channels: list[ChannelType]
    match_type: MatchType = MatchType.EXACT
    priority: NotificationPriority = NotificationPriority.NORMAL
    action: RouteAction = RouteAction.DELIVER
    conditions: dict[str, Any] = field(default_factory=dict)
    transformer: Optional[Callable[[NotificationPayload], NotificationPayload]] = None
    is_active: bool = True
    order: int = 100


@dataclass
class RouteMatch:
    """Result of a routing rule match."""

    rule: RoutingRule
    channels: list[ChannelType]
    priority: NotificationPriority
    action: RouteAction
    transformed_payload: Optional[NotificationPayload] = None


class NotificationRouter:
    """Router for determining notification delivery targets.

    The router evaluates rules in order and applies matching logic to
    determine which channels should receive notifications for each event.

    Example:
        router = NotificationRouter()

        # Add rules
        router.add_rule(RoutingRule(
            id="credential-revoked-urgent",
            name="Credential Revocation - All Channels",
            event_pattern="credential.revoked",
            channels=[ChannelType.FCM, ChannelType.WEBHOOK, ChannelType.EMAIL],
            priority=NotificationPriority.URGENT,
        ))

        router.add_rule(RoutingRule(
            id="usage-threshold",
            name="Usage Threshold - Dashboard Only",
            event_pattern="usage.*",
            match_type=MatchType.WILDCARD,
            channels=[ChannelType.SSE],
            priority=NotificationPriority.NORMAL,
        ))

        # Route an event
        matches = router.route("credential.revoked", payload)
    """

    def __init__(self):
        self._rules: list[RoutingRule] = []
        self._compiled_patterns: dict[str, re.Pattern] = {}

    def add_rule(self, rule: RoutingRule) -> None:
        """Add a routing rule.

        Args:
            rule: The routing rule to add
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.order)

        # Compile regex patterns
        if rule.match_type == MatchType.REGEX:
            try:
                self._compiled_patterns[rule.id] = re.compile(rule.event_pattern)
            except re.error as e:
                logger.error(f"Invalid regex pattern in rule {rule.id}: {e}")

        logger.debug(f"Added routing rule: {rule.name}")

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a routing rule by ID.

        Args:
            rule_id: ID of the rule to remove

        Returns:
            True if removed, False if not found
        """
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                self._rules.pop(i)
                self._compiled_patterns.pop(rule_id, None)
                return True
        return False

    def route(
        self,
        event_type: str,
        payload: NotificationPayload,
        context: Optional[dict[str, Any]] = None,
    ) -> list[RouteMatch]:
        """Route an event to matching channels.

        Args:
            event_type: The event type to route
            payload: The notification payload
            context: Optional context for condition evaluation

        Returns:
            List of RouteMatch results for matching rules
        """
        matches = []
        context = context or {}

        for rule in self._rules:
            if not rule.is_active:
                continue

            if self._matches_pattern(rule, event_type):
                if self._matches_conditions(rule, payload, context):
                    transformed = None
                    if rule.transformer and rule.action == RouteAction.TRANSFORM:
                        transformed = rule.transformer(payload)

                    match = RouteMatch(
                        rule=rule,
                        channels=rule.channels,
                        priority=rule.priority,
                        action=rule.action,
                        transformed_payload=transformed,
                    )
                    matches.append(match)

                    if rule.action == RouteAction.SUPPRESS:
                        # Stop processing on suppress
                        break

        return matches

    def get_channels_for_event(
        self,
        event_type: str,
        payload: Optional[NotificationPayload] = None,
    ) -> set[ChannelType]:
        """Get all channels that should receive an event.

        Args:
            event_type: The event type
            payload: Optional payload for condition matching

        Returns:
            Set of channels that match the event
        """
        if payload is None:
            # Create minimal payload for routing
            payload = NotificationPayload(
                event_type=event_type,
                title="",
                body="",
            )

        matches = self.route(event_type, payload)

        channels = set()
        for match in matches:
            if match.action == RouteAction.SUPPRESS:
                return set()
            if match.action in (RouteAction.DELIVER, RouteAction.TRANSFORM):
                channels.update(match.channels)

        return channels

    def _matches_pattern(self, rule: RoutingRule, event_type: str) -> bool:
        """Check if an event type matches a rule's pattern.

        Args:
            rule: The routing rule
            event_type: The event type to match

        Returns:
            True if the pattern matches
        """
        if rule.match_type == MatchType.EXACT:
            return event_type == rule.event_pattern

        elif rule.match_type == MatchType.PREFIX:
            return event_type.startswith(rule.event_pattern)

        elif rule.match_type == MatchType.WILDCARD:
            # Convert wildcard to regex
            # *.revoked matches credential.revoked, dsc.revoked, etc.
            # credential.* matches credential.issued, credential.revoked, etc.
            pattern = rule.event_pattern.replace(".", r"\.").replace("*", ".*")
            return bool(re.match(f"^{pattern}$", event_type))

        elif rule.match_type == MatchType.REGEX:
            compiled = self._compiled_patterns.get(rule.id)
            if compiled:
                return bool(compiled.match(event_type))
            return False

        return False

    def _matches_conditions(
        self,
        rule: RoutingRule,
        payload: NotificationPayload,
        context: dict[str, Any],
    ) -> bool:
        """Check if payload and context match rule conditions.

        Args:
            rule: The routing rule
            payload: The notification payload
            context: Additional context

        Returns:
            True if all conditions match
        """
        if not rule.conditions:
            return True

        for key, expected in rule.conditions.items():
            # Check in payload data
            if key in payload.data:
                if payload.data[key] != expected:
                    return False
            # Check in context
            elif key in context:
                if context[key] != expected:
                    return False
            else:
                # Condition key not found
                return False

        return True


def create_default_routing_rules() -> list[RoutingRule]:
    """Create default routing rules for common event types.

    Returns:
        List of default routing rules
    """
    return [
        # Credential events - high priority, all channels
        RoutingRule(
            id="credential-revoked",
            name="Credential Revocation Alert",
            event_pattern="credential.revoked",
            channels=[ChannelType.FCM, ChannelType.WEBHOOK, ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.URGENT,
            order=10,
        ),
        RoutingRule(
            id="credential-issued",
            name="Credential Issued Notification",
            event_pattern="credential.issued",
            channels=[ChannelType.FCM, ChannelType.WEBHOOK],
            priority=NotificationPriority.NORMAL,
            order=20,
        ),
        # Trust anchor events - urgent
        RoutingRule(
            id="trust-anchor-revoked",
            name="Trust Anchor Revocation",
            event_pattern="*.revoked",
            match_type=MatchType.WILDCARD,
            channels=[ChannelType.FCM, ChannelType.WEBHOOK, ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.URGENT,
            order=5,
        ),
        RoutingRule(
            id="trust-anchor-cascade",
            name="Trust Anchor Cascade Alert",
            event_pattern="trust_anchor.cascade",
            channels=[ChannelType.FCM, ChannelType.WEBHOOK, ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.URGENT,
            order=5,
        ),
        # Subscription events - normal priority
        RoutingRule(
            id="subscription-lifecycle",
            name="Subscription Lifecycle Events",
            event_pattern="subscription.*",
            match_type=MatchType.WILDCARD,
            channels=[ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.NORMAL,
            order=50,
        ),
        # Payment events
        RoutingRule(
            id="payment-failed",
            name="Payment Failed Alert",
            event_pattern="payment.failed",
            channels=[ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.HIGH,
            order=30,
        ),
        RoutingRule(
            id="payment-confirmed",
            name="Payment Confirmed",
            event_pattern="payment.confirmed",
            channels=[ChannelType.EMAIL],
            priority=NotificationPriority.LOW,
            order=60,
        ),
        # Usage alerts
        RoutingRule(
            id="usage-threshold",
            name="Usage Threshold Alerts",
            event_pattern="usage.*",
            match_type=MatchType.WILDCARD,
            channels=[ChannelType.EMAIL, ChannelType.SSE],
            priority=NotificationPriority.HIGH,
            order=40,
        ),
        # Trust registry updates - mobile wallet sync
        RoutingRule(
            id="trust-registry-delta",
            name="Trust Registry Delta Sync",
            event_pattern="trust_registry.delta",
            channels=[ChannelType.FCM],
            priority=NotificationPriority.NORMAL,
            order=70,
        ),
    ]
