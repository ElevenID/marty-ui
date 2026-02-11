<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: 'Roboto', 'Helvetica', 'Arial', sans-serif;
            line-height: 1.6;
            color: #333333;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        .email-container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .email-header {
            background: linear-gradient(135deg, #1976d2 0%, #115293 100%);
            color: #ffffff;
            padding: 32px;
            text-align: center;
        }
        .email-header h1 {
            margin: 0;
            font-size: 24px;
            font-weight: 500;
        }
        .email-header .logo {
            font-size: 48px;
            margin-bottom: 16px;
        }
        .email-body {
            padding: 32px;
        }
        .email-body h2 {
            color: #1976d2;
            font-size: 20px;
            margin-top: 0;
        }
        .email-body p {
            margin: 16px 0;
            color: rgba(0, 0, 0, 0.87);
        }
        .button {
            display: inline-block;
            background-color: #1976d2;
            color: #ffffff !important;
            padding: 12px 32px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: 500;
            text-transform: uppercase;
            font-size: 14px;
            letter-spacing: 0.02857em;
            margin: 24px 0;
            box-shadow: 0px 3px 1px -2px rgba(0,0,0,0.2), 0px 2px 2px 0px rgba(0,0,0,0.14), 0px 1px 5px 0px rgba(0,0,0,0.12);
        }
        .button:hover {
            background-color: #115293;
        }
        .email-footer {
            background-color: #f5f5f5;
            padding: 24px 32px;
            text-align: center;
            font-size: 12px;
            color: rgba(0, 0, 0, 0.6);
        }
        .email-footer a {
            color: #1976d2;
            text-decoration: none;
        }
        .code-box {
            background-color: #f5f5f5;
            border: 1px solid #e0e0e0;
            border-radius: 4px;
            padding: 16px;
            text-align: center;
            font-family: monospace;
            font-size: 24px;
            letter-spacing: 0.2em;
            margin: 24px 0;
        }
        .warning {
            background-color: #fff4e5;
            border-left: 4px solid #ed6c02;
            padding: 16px;
            margin: 16px 0;
            border-radius: 0 4px 4px 0;
        }
        .info {
            background-color: #e5f6fd;
            border-left: 4px solid #0288d1;
            padding: 16px;
            margin: 16px 0;
            border-radius: 0 4px 4px 0;
        }
    </style>
</head>
<body>
    <div class="email-container">
        <div class="email-header">
            <div class="logo">✈️</div>
            <h1>Marty Trust Services</h1>
        </div>
        <div class="email-body">
            ${kcSanitize(msg("emailBody"))?no_esc}
        </div>
        <div class="email-footer">
            <p>&copy; ${.now?string('yyyy')} Marty Trust Services. All rights reserved.</p>
            <p>This email was sent by <a href="${realmUrl}">${realmName}</a></p>
        </div>
    </div>
</body>
</html>
