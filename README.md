# Computer Access Control Policy Management System

A Flask-based application for managing and enforcing computer access control policies with advanced security features.

## Features

- Multi-Factor Authentication (MFA) with OTP
- Role-Based Access Control (RBAC)
- Policy Management System
  - Password Policy
  - Failed Login Attempt Policy
  - IP Address Restriction
  - Time-based Access Restriction
- Policy Violation Monitoring and Alerts
- Admin Dashboard for Policy Management
- Automated Email Notifications
- Policy Violation Reports

## Setup Instructions

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a .env file with the following variables:
```
SECRET_KEY=your_secret_key
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
DATABASE_URL=sqlite:///policy_app.db
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
```

5. Run the application:
```bash
flask run
```

## Security Features

- Strong Password Requirements
- OTP Authentication
- IP Address Restriction
- Time-based Access Control
- Failed Login Attempt Monitoring
- Policy Violation Alerts
- Role-based Access Control

## Admin Features

- User Management
- Policy Creation and Editing
- Policy Violation Reports
- System Monitoring
- Alert Management 