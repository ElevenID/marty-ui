"""
Email Notification Service

Sends email notifications for application events when users don't have push enabled.
Integrates with existing email adapter.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def send_membership_notification(
    user_email: str,
    organization_name: str,
    status: str,  # "approved" or "rejected"
    rejection_reason: Optional[str] = None,
) -> bool:
    """Send email notification about membership request status.
    
    Args:
        user_email: Applicant's email
        organization_name: Organization name
        status: "approved" or "rejected"
        rejection_reason: Reason if rejected
        
    Returns:
        True if sent successfully
    """
    try:
        # Import email adapter
        from notifications_local.adapters.email import EmailAdapter, EmailConfig, EmailMessage
        
        # Create email adapter (in production, config would come from env vars)
        config = EmailConfig(
            provider="mock",  # Use mock for development
            from_email="notifications@marty.example.com",
            from_name="Marty Trust Services",
        )
        adapter = EmailAdapter(config)
        
        # Prepare email
        if status == "approved":
            subject = f"Welcome to {organization_name}!"
            body_text = f"""
Hello,

Great news! Your membership request to join {organization_name} has been approved.

You can now access your organization's resources and collaborate with your team.

Log in to get started: https://marty.app/login

Best regards,
The Marty Team
            """.strip()
            body_html = f"""
<html>
<body>
<h2>Welcome to {organization_name}!</h2>
<p>Great news! Your membership request has been approved.</p>
<p>You can now access your organization's resources and collaborate with your team.</p>
<p><a href="https://marty.app/login">Log in to get started</a></p>
<p>Best regards,<br>The Marty Team</p>
</body>
</html>
            """.strip()
        else:
            subject = f"Membership Request Update - {organization_name}"
            body_text = f"""
Hello,

We wanted to update you on your membership request to join {organization_name}.

Unfortunately, your request has been declined at this time.
"""
            if rejection_reason:
                body_text += f"\n\nReason: {rejection_reason}"
            
            body_text += """

If you have questions, please contact the organization administrator.

Best regards,
The Marty Team
            """.strip()
            
            body_html = f"""
<html>
<body>
<h2>Membership Request Update</h2>
<p>We wanted to update you on your membership request to join {organization_name}.</p>
<p>Unfortunately, your request has been declined at this time.</p>
"""
            if rejection_reason:
                body_html += f"<p><strong>Reason:</strong> {rejection_reason}</p>"
            
            body_html += """
<p>If you have questions, please contact the organization administrator.</p>
<p>Best regards,<br>The Marty Team</p>
</body>
</html>
            """.strip()
        
        # Create message
        message = EmailMessage(
            to=user_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        
        # Send (in mock mode, this just logs)
        result = await adapter.send(message)
        
        logger.info(
            "Sent membership %s notification to %s for org %s",
            status,
            user_email,
            organization_name,
        )
        
        return result.success
        
    except Exception as e:
        logger.error("Failed to send membership notification: %s", e)
        return False


async def send_credential_issued_notification(
    user_email: str,
    credential_type: str,
    organization_name: str,
) -> bool:
    """Send email notification when credential is issued.
    
    Args:
        user_email: Recipient email
        credential_type: Type of credential issued
        organization_name: Issuing organization
        
    Returns:
        True if sent successfully
    """
    try:
        from notifications_local.adapters.email import EmailAdapter, EmailConfig, EmailMessage
        
        config = EmailConfig(
            provider="mock",
            from_email="notifications@marty.example.com",
            from_name="Marty Trust Services",
        )
        adapter = EmailAdapter(config)
        
        subject = f"Your {credential_type} has been issued"
        body_text = f"""
Hello,

Good news! Your {credential_type} credential from {organization_name} has been issued.

The credential has been delivered to your Marty Authenticator app. If you don't have the app installed, you can download it from your app store.

Best regards,
The Marty Team
        """.strip()
        
        body_html = f"""
<html>
<body>
<h2>Credential Issued</h2>
<p>Good news! Your <strong>{credential_type}</strong> credential from {organization_name} has been issued.</p>
<p>The credential has been delivered to your Marty Authenticator app. If you don't have the app installed, you can download it from your app store.</p>
<p>Best regards,<br>The Marty Team</p>
</body>
</html>
        """.strip()
        
        message = EmailMessage(
            to=user_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        
        result = await adapter.send(message)
        
        logger.info(
            "Sent credential issued notification to %s",
            user_email,
        )
        
        return result.success
        
    except Exception as e:
        logger.error("Failed to send credential notification: %s", e)
        return False


async def send_application_status_notification(
    user_email: str,
    application_type: str,
    status: str,
    organization_name: str,
) -> bool:
    """Send email notification when application status changes.
    
    Args:
        user_email: Applicant email
        application_type: Type of application
        status: New status (approved, rejected, etc.)
        organization_name: Organization name
        
    Returns:
        True if sent successfully
    """
    try:
        from notifications_local.adapters.email import EmailAdapter, EmailConfig, EmailMessage
        
        config = EmailConfig(
            provider="mock",
            from_email="notifications@marty.example.com",
            from_name="Marty Trust Services",
        )
        adapter = EmailAdapter(config)
        
        subject = f"Application Status Update - {application_type}"
        
        if status == "approved":
            body_text = f"""
Hello,

Your application for {application_type} with {organization_name} has been approved!

You'll receive your credential shortly.

Best regards,
The Marty Team
            """.strip()
            body_html = f"""
<html>
<body>
<h2>Application Approved!</h2>
<p>Your application for <strong>{application_type}</strong> with {organization_name} has been approved!</p>
<p>You'll receive your credential shortly.</p>
<p>Best regards,<br>The Marty Team</p>
</body>
</html>
            """.strip()
        else:
            body_text = f"""
Hello,

Your application for {application_type} with {organization_name} has been updated.

Status: {status}

Log in to view more details: https://marty.app/applicant/applications

Best regards,
The Marty Team
            """.strip()
            body_html = f"""
<html>
<body>
<h2>Application Status Update</h2>
<p>Your application for <strong>{application_type}</strong> with {organization_name} has been updated.</p>
<p><strong>Status:</strong> {status}</p>
<p><a href="https://marty.app/applicant/applications">Log in to view more details</a></p>
<p>Best regards,<br>The Marty Team</p>
</body>
</html>
            """.strip()
        
        message = EmailMessage(
            to=user_email,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
        )
        
        result = await adapter.send(message)
        
        logger.info(
            "Sent application status notification to %s: %s",
            user_email,
            status,
        )
        
        return result.success
        
    except Exception as e:
        logger.error("Failed to send application notification: %s", e)
        return False
