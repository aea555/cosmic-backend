//! Email service using Mailtrap API.
//!
//! This module handles sending emails via Mailtrap's HTTP API.

use crate::config::Settings;
use crate::error::{AppError, AppResult};
use reqwest::Client;
use secrecy::ExposeSecret;
use serde::Serialize;

/// Mailtrap API endpoint for sending emails.
const MAILTRAP_API_URL: &str = "https://send.api.mailtrap.io/api/send";

/// Email address structure for Mailtrap API.
#[derive(Serialize)]
struct EmailAddress {
    email: String,
    name: Option<String>,
}

/// Email request body for Mailtrap API.
#[derive(Serialize)]
struct MailtrapEmail {
    from: EmailAddress,
    to: Vec<EmailAddress>,
    reply_to: Option<EmailAddress>,
    subject: String,
    text: String,
    html: String,
}

/// Sends a verification email to the user via Mailtrap API.
///
/// Params: Settings, recipient email, verification token.
/// Logic: Builds verification link, sends email via Mailtrap HTTP API.
/// Returns: Unit on success, error on failure.
pub async fn send_verification_email(
    settings: &Settings,
    to_email: &str,
    token: &str,
) -> AppResult<()> {
    let verification_link = format!(
        "{}/api/v1/auth/verify-redirect?token={}",
        settings.app_url, token
    );

    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Verify Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #333;">Welcome to {}</h1>
    <p>Thank you for registering. Please verify your email address by clicking the button below:</p>
    <p style="text-align: center; margin: 30px 0;">
        <a href="{}" style="background-color: #4f46e5; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block;">
            Verify Email
        </a>
    </p>
    <p>Or copy and paste this link into your browser:</p>
    <p style="word-break: break-all; color: #666;">{}</p>
    <p style="color: #999; font-size: 12px; margin-top: 30px;">
        This link will expire in 24 hours. If you did not create an account, you can safely ignore this email.
    </p>
</body>
</html>"#,
        settings.email_from_name, verification_link, verification_link
    );

    let plain_body = format!(
        "Welcome to {}!\n\n\
        Please verify your email address by visiting the following link:\n\n\
        {}\n\n\
        This link will expire in 24 hours.\n\n\
        If you did not create an account, you can safely ignore this email.",
        settings.email_from_name, verification_link
    );

    let email = MailtrapEmail {
        from: EmailAddress {
            email: settings.email_from_email.clone(),
            name: Some(settings.email_from_name.clone()),
        },
        to: vec![EmailAddress {
            email: to_email.to_string(),
            name: None,
        }],
        reply_to: Some(EmailAddress {
            email: settings.email_reply_to.clone(),
            name: None,
        }),
        subject: format!("Verify your {} account", settings.email_from_name),
        text: plain_body,
        html: html_body,
    };

    let client = Client::new();
    let response = client
        .post(MAILTRAP_API_URL)
        .header(
            "Authorization",
            format!("Bearer {}", settings.mailtrap_api_token.expose_secret()),
        )
        .header("Content-Type", "application/json")
        .json(&email)
        .send()
        .await
        .map_err(|e| AppError::Email(format!("Failed to send email request: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Mailtrap API error: {} - {}", status, body);
        return Err(AppError::Email(format!(
            "Mailtrap API returned error: {} - {}",
            status, body
        )));
    }

    tracing::info!("Verification email sent to {}", to_email);

    Ok(())
}

/// Sends an OTP email for account operations.
///
/// Params: Settings, recipient email, OTP code, action description.
/// Logic: Sends 6-digit OTP for account deletion, password change, or email change.
/// Returns: Unit on success, error on failure.
pub async fn send_otp_email(
    settings: &Settings,
    to_email: &str,
    otp: &str,
    action: &str,
) -> AppResult<()> {
    let html_body = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Your OTP Code</title>
</head>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h1 style="color: #333;">{}</h1>
    <p>You requested to {}. Use the following OTP code to confirm:</p>
    <p style="text-align: center; margin: 30px 0;">
        <span style="background-color: #f5f5f5; font-size: 32px; font-weight: bold; letter-spacing: 8px; padding: 15px 25px; border-radius: 8px; display: inline-block;">
            {}
        </span>
    </p>
    <p style="color: #666;">This code will expire in 15 minutes.</p>
    <p style="color: #999; font-size: 12px; margin-top: 30px;">
        If you did not request this action, please ignore this email and ensure your account is secure.
    </p>
</body>
</html>"#,
        settings.email_from_name, action, otp
    );

    let plain_body = format!(
        "{}\n\n\
        You requested to {}.\n\n\
        Your OTP code is: {}\n\n\
        This code will expire in 15 minutes.\n\n\
        If you did not request this action, please ignore this email.",
        settings.email_from_name, action, otp
    );

    let email = MailtrapEmail {
        from: EmailAddress {
            email: settings.email_from_email.clone(),
            name: Some(settings.email_from_name.clone()),
        },
        to: vec![EmailAddress {
            email: to_email.to_string(),
            name: None,
        }],
        reply_to: Some(EmailAddress {
            email: settings.email_reply_to.clone(),
            name: None,
        }),
        subject: format!("Your {} verification code", settings.email_from_name),
        text: plain_body,
        html: html_body,
    };

    let client = Client::new();
    let response = client
        .post(MAILTRAP_API_URL)
        .header(
            "Authorization",
            format!("Bearer {}", settings.mailtrap_api_token.expose_secret()),
        )
        .header("Content-Type", "application/json")
        .json(&email)
        .send()
        .await
        .map_err(|e| AppError::Email(format!("Failed to send OTP email request: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        tracing::error!("Mailtrap API error for OTP: {} - {}", status, body);
        return Err(AppError::Email(format!(
            "Mailtrap API returned error: {} - {}",
            status, body
        )));
    }

    tracing::info!("OTP email sent to {}", to_email);

    Ok(())
}
