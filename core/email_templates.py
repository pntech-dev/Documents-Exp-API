EMAIL_VERIFICATION_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Code</title>
    <style>
        body {{
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
            color: #333;
        }}
        .container {{
            max-width: 600px;
            margin: 40px auto;
            background-color: #ffffff;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }}
        .header {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #CC3333;
            font-size: 24px;
            margin: 0;
        }}
        .content {{
            text-align: center;
            margin-bottom: 30px;
        }}
        .content p {{
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 20px;
        }}
        .code-container {{
            background-color: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            display: inline-block;
        }}
        .code {{
            font-family: 'Courier New', Courier, monospace;
            font-size: 32px;
            font-weight: bold;
            color: #CC3333;
            letter-spacing: 4px;
        }}
        .footer {{
            text-align: center;
            font-size: 12px;
            color: #999;
            border-top: 1px solid #eee;
            padding-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Please use the verification code below to complete your action:</p>
            <div class="code-container">
                <span class="code">{code}</span>
            </div>
            <p>This code will expire in {expire_minutes} minutes.</p>
            <p>If you did not request this code, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>&copy; Documents Exp API. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""