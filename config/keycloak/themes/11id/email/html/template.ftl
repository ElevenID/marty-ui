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
            width: 48px;
            height: 48px;
            margin-bottom: 16px;
            display: inline-block;
            border-radius: 12px;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0' y1='0' x2='1' y2='1'%3E%3Cstop offset='0%25' stop-color='%231976d2'/%3E%3Cstop offset='100%25' stop-color='%23115293'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect rx='14' width='64' height='64' fill='url(%23g)'/%3E%3Cpath d='M32 10l18 8v14c0 11.2-7.7 19.8-18 22-10.3-2.2-18-10.8-18-22V18l18-8z' fill='%23fff' fill-opacity='.95'/%3E%3Cpath d='M32 18l10 4.6v8.8c0 6.8-4 12.1-10 14.2-6-2.1-10-7.4-10-14.2v-8.8L32 18z' fill='url(%23g)'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-size: cover;
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
            <div class="logo"></div>
            <h1>ElevenID LLC Trust Services</h1>
        </div>
        <div class="email-body">
            ${kcSanitize(msg("emailBody"))?no_esc}
        </div>
        <div class="email-footer">
            <p>&copy; ${.now?string('yyyy')} ElevenID LLC Trust Services. All rights reserved.</p>
            <p>This email was sent by <a href="${realmUrl}">${realmName}</a></p>
        </div>
    </div>
</body>
</html>
