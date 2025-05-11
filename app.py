from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from datetime import datetime, timedelta
import pyotp
import bcrypt
import logging
from models import db, User, Policy, PolicyViolation, IPRestriction, LoginAttempt, UserGroup, PolicyVersion, PolicySchedule, Notification, Report, SystemActivity, PolicyGroupAssignment, UserPolicyAssignment, UserGroupMembership, RegistrationRequest
from config import Config
import re
from functools import wraps
import random
import string
from sqlalchemy import func
import ipaddress
from pytz import timezone
import json
from sqlalchemy.orm.attributes import flag_modified
from statistics import mean, stdev
from views.it_admin import bp as it_admin_bp
from views.qa import bp as qa_bp
from forms import ChangePasswordForm

app = Flask(__name__)
app.config.from_object(Config)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
mail = Mail(app)
csrf = CSRFProtect(app)  # Add CSRF protection

# Register blueprints
app.register_blueprint(it_admin_bp)
app.register_blueprint(qa_bp)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or (current_user.role != 'admin' and current_user.role != 'it_admin'):
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_otp_email(user, otp):
    try:
        print(f"Attempting to send OTP email to {user.email}")
        print(f"Using SMTP server: {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        print(f"Using email account: {app.config['MAIL_USERNAME']}")
        
        msg = Message('Your OTP Code',
                      sender=app.config['MAIL_DEFAULT_SENDER'],
                      recipients=[user.email])
        msg.body = f'Your OTP code is: {otp}\nThis code will expire in 2 minutes.'
        
        print("Sending email...")
        mail.send(msg)
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Failed to send OTP email: {str(e)}")
        app.logger.error(f"Failed to send OTP email: {str(e)}")
        return False

def validate_email(email):
    """Validate email format using regex pattern."""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_pattern, email) is not None

def check_password_strength(password):
    """Check password strength and return list of errors if any."""
    errors = []
    
    # Check minimum length (8 characters)
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long')
    
    # Check for uppercase letters
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter')
    
    # Check for lowercase letters
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter')
    
    # Check for numbers
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one number')
    
    # Check for special characters
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character')
    
    # Check for common patterns
    common_patterns = ['password', '123456', 'qwerty', 'admin']
    if any(pattern in password.lower() for pattern in common_patterns):
        errors.append('Password contains common patterns that are not allowed')
    
    return errors


def validate_ip_address(ip_address):
    """Validate and normalize IP address."""
    try:
        # Handle CIDR notation
        if '/' in ip_address:
            network = ipaddress.ip_network(ip_address, strict=False)
            return str(network)
        # Handle single IP
        ip = ipaddress.ip_address(ip_address)
        return str(ip)
    except ValueError:
        return None

def check_ip_restriction(ip_address, allowed_ips):
    """Check if IP is allowed based on CIDR notation and single IPs."""
    if not allowed_ips:
        return True
        
    client_ip = ipaddress.ip_address(ip_address)
    
    for allowed_ip in allowed_ips:
        try:
            if '/' in allowed_ip:  # CIDR notation
                network = ipaddress.ip_network(allowed_ip, strict=False)
                if client_ip in network:
                    return True
            else:  # Single IP
                if client_ip == ipaddress.ip_address(allowed_ip):
                    return True
        except ValueError:
            continue
        return False

def get_current_time(timezone_name='UTC'):
    """Get current time in specified timezone."""
    tz = timezone(timezone_name)
    return datetime.now(tz)

def check_time_restriction(working_hours_start, working_hours_end, working_days, timezone_name='UTC'):
    """Check if current time is within working hours."""
    current_time = get_current_time(timezone_name)
    
    # Convert working hours to datetime for comparison
    start_time = datetime.strptime(working_hours_start, '%H:%M').time()
    end_time = datetime.strptime(working_hours_end, '%H:%M').time()
    
    # Check if current day is a working day
    if current_time.weekday() + 1 not in working_days:
        return False
        
    # Check if current time is within working hours
    current_time_only = current_time.time()
    return start_time <= current_time_only <= end_time

def check_policy_violations(user, action_type, details=None):
    """Check for policy violations based on the action type and user."""
    violations = []
    
    # Get all active policies with priority
    active_policies = Policy.query.filter_by(is_active=True).order_by(Policy.priority.desc()).all()
    
    for policy in active_policies:
        # Skip if policy is not applicable to the user
        if not is_policy_applicable_to_user(policy, user):
            continue
            
        if policy.type == 'password' and action_type == 'password_change':
            # Check password policy violations
            if not check_password_strength(details['new_password']):
                violations.append({
                    'policy_id': policy.id,
                    'violation_type': 'password',
                    'details': 'Password does not meet complexity requirements',
                    'severity': policy.settings.get('severity', 'medium'),
                    'priority': policy.priority
                })
        
        elif policy.type == 'login' and action_type == 'login_attempt':
            # Check login policy violations
            if user.failed_login_attempts >= policy.settings.get('max_attempts', 10):
                violations.append({
                    'policy_id': policy.id,
                    'violation_type': 'login',
                    'details': f'Exceeded maximum login attempts ({policy.settings.get("max_attempts", 10)})',
                    'severity': policy.settings.get('severity', 'high'),
                    'priority': policy.priority
                })
        
        elif policy.type == 'ip' and action_type == 'access_attempt':
            # Check IP restriction violations
            allowed_ips = policy.settings.get('allowed_ips', [])
            if not check_ip_restriction(request.remote_addr, allowed_ips):
                violations.append({
                    'policy_id': policy.id,
                    'violation_type': 'ip',
                    'details': f'Access attempt from unauthorized IP: {request.remote_addr}',
                    'severity': policy.settings.get('severity', 'high'),
                    'priority': policy.priority
                })
        
        elif policy.type == 'time' and action_type == 'access_attempt':
            # Check time-based access violations
            timezone_name = policy.settings.get('timezone', 'UTC')
            working_hours_start = policy.settings.get('working_hours_start', '09:00')
            working_hours_end = policy.settings.get('working_hours_end', '17:00')
            working_days = policy.settings.get('working_days', [1, 2, 3, 4, 5])
            
            if not check_time_restriction(working_hours_start, working_hours_end, working_days, timezone_name):
                violations.append({
                    'policy_id': policy.id,
                    'violation_type': 'time',
                    'details': 'Access attempt outside allowed working hours',
                    'severity': policy.settings.get('severity', 'medium'),
                    'priority': policy.priority
                })
    
    # Sort violations by priority and severity
    violations.sort(key=lambda x: (x['priority'], x['severity']), reverse=True)
    return violations

def is_policy_applicable_to_user(policy, user):
    """Check if a policy is applicable to a user."""
    # Check direct user assignments
    if user in policy.users:
        return True
        
    # Check group assignments
    for group in user.groups:
        if group in policy.groups:
            return True
            
    # Check policy schedules
    current_time = get_current_time()
    for schedule in policy.schedules:
        if schedule.is_active and schedule.start_time <= current_time <= schedule.end_time:
            return True
            
    return False

def record_policy_violations(user, violations):
    """Record policy violations in the database and notify admins."""
    admin_emails = []
    try:
        admins = User.query.filter_by(role='admin', is_active=True).all()
        admin_emails = [admin.email for admin in admins if admin.email] 
    except Exception as e:
        app.logger.error(f"Error fetching admin emails for violation notification: {str(e)}")
        
    new_violations = []
    notifications_to_add = []
    
    for violation_data in violations:
        # Create the PolicyViolation record
        policy_violation = PolicyViolation(
            user_id=user.id,
            policy_id=violation_data['policy_id'],
            violation_type=violation_data['violation_type'],
            details=violation_data['details'],
            severity=violation_data['severity'], # Use severity from check_policy_violations
            timestamp=datetime.utcnow() # Store timestamp
        )
        new_violations.append(policy_violation)
        db.session.add(policy_violation)
    
        # Create notification for the violating user if severity is high
        if violation_data['severity'] == 'high':
            user_notification = Notification(
                user_id=user.id,
                title='High Severity Policy Violation Detected',
                message=f"Policy violation detected: {violation_data['details']}",
                type='violation',
                related_id=policy_violation.id, # Temporarily None, updated after commit
                related_type='policy_violation'
            )
            notifications_to_add.append(user_notification)
            db.session.add(user_notification)

    # Commit first to get IDs for violation records if needed for notifications
    try:
        db.session.commit()
        # Update related_id for user notifications now that policy_violation has an ID
        # (This requires re-fetching or careful handling, simpler to link conceptually)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error recording policy violations: {str(e)}")
        return # Stop if we can't even record the violation
        
    # --- Send Email to Admins --- 
    if admin_emails:
        for violation_instance in new_violations: # Iterate through the SAVED violation objects
            try:
                # Fetch related policy for email details
                policy = Policy.query.get(violation_instance.policy_id)
                policy_name = policy.name if policy else "Unknown Policy"
                
                subject = f"Policy Violation Alert: {user.username} - {policy_name}"
                body = f"""
Policy violation detected:

User: {user.username} (ID: {user.id})
Policy: {policy_name} (ID: {violation_instance.policy_id})
Violation Type: {violation_instance.violation_type}
Severity: {violation_instance.severity.upper()}
Timestamp: {violation_instance.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Details: {violation_instance.details}

Please review the violation details in the admin panel.
"""
                # Consider adding a direct link if admin_violations route exists
                # body += f"\nView Violation: {url_for('admin_violations', _external=True)}#violation-{violation_instance.id}"
                
                msg = Message(subject,
                              sender=app.config['MAIL_DEFAULT_SENDER'],
                              recipients=admin_emails) # Send to all admins
                msg.body = body
                mail.send(msg)
                app.logger.info(f"Sent policy violation email notification to admins for violation ID {violation_instance.id}")
            except Exception as mail_e:
                app.logger.error(f"Failed to send policy violation email to admins: {str(mail_e)}")
                # Continue attempting to send emails for other violations if multiple occurred

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        print(f"Login attempt for user: {username}")
        user = User.query.filter_by(username=username).first()
        
        # Check for policy violations before proceeding
        if user:
            print(f"User found: {user.username}")
            violations = check_policy_violations(user, 'access_attempt')
            if violations:
                record_policy_violations(user, violations)
                flash('Access denied due to policy violations.', 'error')
                return redirect(url_for('login'))
            
            if user.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                violations = check_policy_violations(user, 'login_attempt')
                if violations:
                    record_policy_violations(user, violations)
                flash('Account locked due to too many failed attempts.', 'error')
                return redirect(url_for('login'))
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            print("Password verified successfully")
            if user.failed_login_attempts >= app.config['MAX_LOGIN_ATTEMPTS']:
                flash('Account locked due to too many failed attempts.', 'error')
                return redirect(url_for('login'))
            
            otp = user.get_otp()
            print(f"Generated OTP: {otp}")
            if send_otp_email(user, otp):
                print("Redirecting to OTP verification")
                return redirect(url_for('verify_otp', user_id=user.id))
            else:
                flash('Failed to send OTP email. Please check your email configuration or try again later.', 'error')
                return redirect(url_for('login'))
        else:
            if user:
                user.failed_login_attempts += 1
                violations = check_policy_violations(user, 'login_attempt')
                if violations:
                    record_policy_violations(user, violations)
                db.session.commit()
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

MIN_LOGIN_HISTORY = 6 # Minimum successful logins needed to check for anomaly
ANOMALY_HOURS_UTC = range(1, 2)  # 00:00 to 05:59 UTC considered potentially anomalous
ANOMALY_THRESHOLD = 0.15  # If less than 15% of logins occur during these hours, consider it anomalous

def notify_anomalous_login(user, current_hour_utc, ip_address):
    """Send email notifications about anomalous login attempts to admins and create system notifications."""
    try:
        # Get admin emails
        admins = User.query.filter_by(role='admin', is_active=True).all()
        admin_emails = [admin.email for admin in admins if admin.email]

        # Prepare email content
        subject = f'Anomalous Login Alert - {user.username}'
        body = f"""Anomalous login detected:

User: {user.username}
Email: {user.email}
Time: {current_hour_utc:02d}:00 UTC
IP Address: {ip_address}
Location: {request.headers.get('X-Real-IP', ip_address)}

This login occurred during unusual hours based on the user's historical login patterns.

Please review this activity in the admin dashboard.
"""

        # Send email to admins
        msg = Message(subject,
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=admin_emails)
        msg.body = body
        mail.send(msg)

        # Create system notification for admins
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                title='Anomalous Login Detected',
                message=f'Unusual login activity detected for user {user.username} at {current_hour_utc:02d}:00 UTC',
                type='security_alert',
                related_id=user.id,
                related_type='user'
            )
            db.session.add(notification)

        db.session.commit()
        app.logger.info(f'Sent anomalous login notifications for user {user.username}')

    except Exception as e:
        app.logger.error(f'Error sending anomaly notifications: {str(e)}\n{traceback.format_exc()}')
        db.session.rollback()

def check_login_time_anomaly(user):
    """Check if the current login time is unusual for the user based on login history.
    
    The function analyzes the user's login patterns to detect potentially suspicious
    login attempts during unusual hours. It considers both the general time window
    (defined by ANOMALY_HOURS_UTC) and the user's personal login patterns.
    """
    try:
        # Get recent successful login timestamps (UTC)
        recent_logins = LoginAttempt.query.filter_by(user_id=user.id, success=True)\
                                        .order_by(LoginAttempt.attempt_time.desc())\
                                        .limit(50).all()  # Look at last 50 logins

        if len(recent_logins) < MIN_LOGIN_HISTORY:
            app.logger.info(f"Not enough login history for user {user.username} to determine anomaly")
            return False

        current_hour_utc = datetime.utcnow().hour
        login_hours_utc = [login.attempt_time.hour for login in recent_logins]

        # Only proceed with anomaly check if current login is during unusual hours
        if current_hour_utc in ANOMALY_HOURS_UTC:
            # Calculate frequency of logins during anomaly hours
            unusual_hours_logins = sum(1 for hour in login_hours_utc if hour in ANOMALY_HOURS_UTC)
            unusual_login_frequency = unusual_hours_logins / len(login_hours_utc)

            # Check if this login is anomalous based on user's pattern
            if unusual_login_frequency < ANOMALY_THRESHOLD:
                app.logger.warning(
                    f"Anomalous login detected for {user.username}:\n"
                    f"Current time: {current_hour_utc:02d}:00 UTC\n"
                    f"Historical unusual hour logins: {unusual_login_frequency:.1%}"
                )
                # Send notifications about the anomalous login
                notify_anomalous_login(user, current_hour_utc, request.remote_addr)
                return True
            else:
                app.logger.info(
                    f"Login during unusual hours for {user.username}, but matches historical pattern"
                )

        return False

    except Exception as e:
        app.logger.error(
            f"Error in anomaly detection for {user.username}:\n"
            f"Error: {str(e)}\n"
            f"Stack trace: {traceback.format_exc()}"
        )
        return False  # Fail safe, don't block login

@app.route('/verify-otp/<int:user_id>', methods=['GET', 'POST'])
def verify_otp(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        otp = request.form.get('otp')
        
        # Debug logging
        print(f"User OTP Secret: {user.otp_secret}")
        print(f"Current OTP: {user.get_otp()}")
        print(f"Submitted OTP: {otp}")
        print(f"Verification Result: {user.verify_otp(otp)}")
        
        if user.verify_otp(otp):
            login_user(user)
            user.failed_login_attempts = 0
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Record successful login attempt
            login_attempt = LoginAttempt(
                user_id=user.id,
                ip_address=request.remote_addr,
                success=True,
                attempt_time=datetime.utcnow() # Ensure consistent time
            )
            db.session.add(login_attempt)
            
            # Reset failed attempts and update last login AFTER recording attempt
            user.failed_login_attempts = 0
            user.last_login = login_attempt.attempt_time # Use attempt time
            
            # --- Anomaly Check --- 
            is_anomalous = check_login_time_anomaly(user)
            if is_anomalous:
                try:
                    # 1. Log System Activity
                    activity = SystemActivity(
                        user_id=current_user.id, # User who logged in
                        action='anomalous_login_time',
                        details=f'Login detected at unusual time: {datetime.utcnow().strftime("%H:%M:%S UTC")}'
                    )
                    db.session.add(activity)
                    
                    # 2. Notify User
                    user_subject = "Security Alert: Unusual Login Time Detected"
                    user_body = f"""
Hello {user.username},

We detected a login to your account at an unusual time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}.

If this was you, you can safely ignore this message.

If this was not you, please change your password immediately and contact support.

IP Address: {request.remote_addr}
"""
                    user_msg = Message(user_subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
                    user_msg.body = user_body
                    mail.send(user_msg)
                    app.logger.info(f"Sent anomalous login time alert to user {user.username}")

                    # 3. Notify Admins
                    admins = User.query.filter_by(role='admin', is_active=True).all()
                    admin_emails = [admin.email for admin in admins if admin.email]
                    if admin_emails:
                        admin_subject = f"Security Alert: Anomalous Login Time for {user.username}"
                        admin_body = f"""
Anomalous login time detected:

User: {user.username} (ID: {user.id})
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
IP Address: {request.remote_addr}

Please review user activity if suspicious.
"""
                        admin_msg = Message(admin_subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=admin_emails)
                        admin_msg.body = admin_body
                        mail.send(admin_msg)
                        app.logger.info(f"Sent anomalous login time alert to admins for user {user.username}")

                except Exception as notify_e:
                    app.logger.error(f"Error sending anomalous login notification for user {user.id}: {str(notify_e)}")
                    # Don't prevent login if notification fails
            
            # Commit all changes (login attempt, user updates, activity log)
            try:
                db.session.commit()
            except Exception as commit_e:
                 db.session.rollback()
                 app.logger.error(f"Error committing login updates for user {user.id}: {str(commit_e)}")
                 flash('An error occurred during login. Please try again.', 'error')
                 return redirect(url_for('login'))
                
            return redirect(url_for('dashboard'))
        else:
            # Handle invalid OTP
            user.failed_login_attempts += 1
            # Potentially check/record login policy violation here based on attempts
            db.session.commit()
            flash('Invalid OTP. Please try again.', 'error')
            # Don't redirect, show OTP page again
            return render_template('verify_otp.html', user=user)
    
    # Handle GET request for OTP page
    return render_template('verify_otp.html', user=user)

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Keep the rest of the logic:
        violations = PolicyViolation.query.filter_by(user_id=current_user.id).all()
        recent_violations = PolicyViolation.query.filter_by(user_id=current_user.id).order_by(PolicyViolation.timestamp.desc()).limit(5).all()
        
        # Get user's directly assigned policies
        user_policies = [assignment.policy for assignment in current_user.user_policy_assignments if assignment.policy]
        
        # Get policies assigned through user groups
        group_policies = []
        for group in current_user.groups:
            group_assignments = PolicyGroupAssignment.query.filter_by(group_id=group.id).all()
            for assignment in group_assignments:
                policy = Policy.query.get(assignment.policy_id)
                if policy and policy.is_active:
                    group_policies.append(policy)
        
        # Combine all policies and remove duplicates
        all_policies = list(set(user_policies + group_policies))
        
        # Get recent system activities
        recent_activities = SystemActivity.query.filter_by(user_id=current_user.id).order_by(SystemActivity.timestamp.desc()).limit(5).all()
        
        # Get unread notifications
        notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).all()
        
        return render_template('dashboard.html',
                             policies=all_policies,
                             violations=violations,
                             recent_violations=recent_violations,
                             recent_activities=recent_activities,
                             notifications=notifications)
    except Exception as e:
        app.logger.error(f"Error loading dashboard: {str(e)}")
        flash('An error occurred while loading the dashboard.', 'error')
        return redirect(url_for('index'))

@app.route('/admin/users', methods=['POST'])
@login_required
@admin_required
def create_user():
    try:
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'user')
        
        # Validate required fields
        if not all([username, email, password]):
            return jsonify({'success': False, 'error': 'All fields are required'}), 400
            
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            return jsonify({'success': False, 'error': 'Username already taken'}), 400
        if User.query.filter_by(email=email).first():
            return jsonify({'success': False, 'error': 'Email already registered'}), 400
            
        # Create new user
        user = User(
            username=username,
            email=email,
            role=role,
            is_active=True
        )
        
        # Set password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user.password_hash = hashed_password
        
        # Add to database
        db.session.add(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User created successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept') == 'application/json':
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [{
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active
            } for user in users]
        })
    return render_template('admin/users.html', users=User.query.all())

@app.route('/admin/users/<int:user_id>', methods=['PUT', 'DELETE', 'PATCH', 'GET'])
@login_required
@admin_required
def manage_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'DELETE':
        try:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'message': 'User deleted successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
        
    elif request.method == 'PUT':
        try:
            # Get form data instead of JSON
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            role = request.form.get('role')
            is_active = request.form.get('is_active') == 'on'
            
            # Update username if changed
            if username and username != user.username:
                if User.query.filter_by(username=username).first():
                    return jsonify({'success': False, 'error': 'Username already taken'}), 400
                user.username = username
                
            # Update email if changed
            if email and email != user.email:
                if User.query.filter_by(email=email).first():
                    return jsonify({'success': False, 'error': 'Email already registered'}), 400
                user.email = email
                
            # Update password if provided
            if password:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                user.password_hash = hashed_password
            
            # Update role
            if role and role in ['user', 'admin', 'it_admin']:
                user.role = role
                if role == 'it_admin':
                    activity_action = 'promote_to_it_admin'
                    activity_details = f'Promoted user {user.username} to IT Admin'
                else:
                    activity_action = 'update_user_role'
                    activity_details = f'Updated role for user {user.username} to {role}'
            else:
                return jsonify({'success': False, 'error': 'Invalid role'}), 400
            
            # Update active status
            user.is_active = is_active
            
            db.session.commit()
            
            # Log the activity
            activity = SystemActivity(
                user_id=current_user.id,
                action=activity_action,
                details=activity_details
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'User updated successfully'})
        except Exception as e:
            db.session.rollback()
            print(f"Error updating user: {str(e)}")  # Add debug logging
            return jsonify({'success': False, 'error': str(e)}), 500

    elif request.method == 'PATCH':
        try:
            data = request.get_json()
            action = data.get('action')
            
            if action == 'archive':
                user.is_active = False
                user.is_archived = True
                activity_action = 'archive_user'
                activity_details = f'Archived user: {user.username}'
            else:
                return jsonify({'success': False, 'error': 'Invalid action'}), 400
            
            db.session.commit()
            
            # Log the activity
            activity = SystemActivity(
                user_id=current_user.id,
                action=activity_action,
                details=activity_details
            )
            db.session.add(activity)
            db.session.commit()
            
            return jsonify({'success': True, 'message': f'User {action}d successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500

    elif request.method == 'GET':
        try:
            return jsonify({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'is_active': user.is_active,
                'is_archived': user.is_archived
            })
        except Exception as e:
            app.logger.error(f"Error fetching user {user_id}: {str(e)}")
            return jsonify({'error': str(e)}), 500

@app.route('/admin/policies')
@login_required
def admin_policies():
    if current_user.role != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    policies = Policy.query.all()
    users = User.query.all()
    groups = UserGroup.query.all()
    return render_template('admin/policies.html', policies=policies, users=users, groups=groups)

@app.route('/admin/violations')
@login_required
@admin_required
def admin_violations():
    violations = PolicyViolation.query.order_by(PolicyViolation.timestamp.desc()).all()
    return render_template('admin/violations.html', violations=violations)

@app.route('/admin/violations/<int:violation_id>')
@login_required
@admin_required
def get_violation_details(violation_id):
    violation = PolicyViolation.query.get_or_404(violation_id)
    return jsonify({
        'id': violation.id,
        'timestamp': violation.timestamp.isoformat(),
        'user': {'username': violation.user.username},
        'policy': {'name': violation.policy.name},
        'violation_type': violation.violation_type,
        'details': violation.details,
        'is_resolved': violation.is_resolved,
        'resolved_at': violation.resolved_at.isoformat() if violation.resolved_at else None
    })

@app.route('/admin/violations/<int:violation_id>/resolve', methods=['POST'])
@login_required
@admin_required
def resolve_violation(violation_id):
    """Mark a policy violation as resolved."""
    try:
        violation = PolicyViolation.query.get_or_404(violation_id)

        if violation.is_resolved:
            return jsonify({'success': False, 'message': 'Violation already resolved.'}), 400

        violation.is_resolved = True
        violation.resolved_at = datetime.utcnow()
        violation.resolved_by_id = current_user.id

        db.session.commit()
        
        # --- Notify the user whose violation was resolved --- 
        try:
            # Fetch details needed for notification message
            user_to_notify = User.query.get(violation.user_id)
            policy_name = violation.policy.name if violation.policy else "a policy"
            
            if user_to_notify:
                notification = Notification(
                    user_id=user_to_notify.id,
                    title="Policy Violation Resolved",
                    message=f"The violation regarding '{policy_name}' that occurred on {violation.timestamp.strftime('%Y-%m-%d %H:%M')} has been marked as resolved by an administrator.",
                    type='violation_resolved',
                    related_id=violation.id,
                    related_type='policy_violation'
                )
                db.session.add(notification)
                # Commit notification separately or together with activity log
                # db.session.commit() # Option 1: Commit here
                app.logger.info(f"Created resolution notification for user {user_to_notify.username} regarding violation {violation.id}")
            else:
                 app.logger.warning(f"Could not find user with ID {violation.user_id} to notify about resolved violation {violation.id}")
                 
        except Exception as notify_e:
            app.logger.error(f"Error creating user notification for resolved violation {violation.id}: {str(notify_e)}")
            # Don't rollback the resolution if notification fails

        # Log the resolution action (already exists)
        try:
            activity = SystemActivity(
                user_id=current_user.id,
                action='resolve_violation',
                details=f'Resolved violation ID: {violation.id} (User: {violation.user.username}, Policy: {violation.policy.name})'
            )
            db.session.add(activity)
            db.session.commit() # Commit activity log (and notification if not committed above)
        except Exception as log_e:
            app.logger.error(f"Error logging violation resolution: {str(log_e)}")

        return jsonify({
            'success': True, 
            'message': 'Violation marked as resolved.',
            'resolved_at': violation.resolved_at.strftime('%Y-%m-%d %H:%M:%S'),
            'resolved_by': current_user.username
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resolving violation {violation_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/violations/export')
@login_required
@admin_required
def export_violations():
    violations = PolicyViolation.query.order_by(PolicyViolation.timestamp.desc()).all()
    # Implementation for exporting violations to CSV/Excel
    return "Export functionality to be implemented"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/admin/groups')
@login_required
@admin_required
def admin_groups():
    groups = UserGroup.query.all()
    return render_template('admin/groups.html', groups=groups)

@app.route('/admin/groups', methods=['POST'])
@login_required
@admin_required
def create_group():
    try:
        data = request.form
        group = UserGroup(
            name=data['name'],
            description=data.get('description')
        )
        db.session.add(group)
        db.session.commit()
        return jsonify({'message': 'Group created successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/user-groups/<int:group_id>', methods=['PUT'])
@login_required
@admin_required
def update_group(group_id):
    try:
        # Get the group
        group = UserGroup.query.get_or_404(group_id)
        
        # Get JSON data
        data = request.get_json()
        
        # Log the incoming data
        app.logger.debug(f"Updating group {group_id} with data: {data}")
        
        # Get data from JSON
        name = data.get('name')
        description = data.get('description')
        
        # Validate required fields
        if not name:
            return jsonify({'success': False, 'error': 'Group name is required'}), 400
            
        # Check if name is already taken by another group
        existing_group = UserGroup.query.filter(UserGroup.name == name, UserGroup.id != group_id).first()
        if existing_group:
            return jsonify({'success': False, 'error': 'A group with this name already exists'}), 400
            
        # Update group
        group.name = name
        group.description = description
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='update_group',
            details=f'Updated group: {group.name}'
        )
        db.session.add(activity)
        
        # Commit changes
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group updated successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating group {group_id}: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/groups/<int:group_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_group(group_id):
    try:
        group = User.query.get_or_404(group_id)
        db.session.delete(group)
        db.session.commit()
        return jsonify({'message': 'Group deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>/versions')
@login_required
@admin_required
def policy_versions(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    versions = PolicyVersion.query.filter_by(policy_id=policy_id).order_by(PolicyVersion.version_number.desc()).all()
    return render_template('admin/policy_versions.html', policy=policy, versions=versions)

@app.route('/admin/policies/<int:policy_id>/versions', methods=['POST'])
@login_required
@admin_required
def create_policy_version(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        data = request.form
        
        # Get the latest version number
        latest_version = PolicyVersion.query.filter_by(policy_id=policy_id).order_by(PolicyVersion.version_number.desc()).first()
        version_number = (latest_version.version_number + 1) if latest_version else 1
        
        version = PolicyVersion(
            policy_id=policy_id,
            version_number=version_number,
            name=data['name'],
            description=data.get('description'),
            settings=data.get('settings'),
            created_by_id=current_user.id
        )
        
        db.session.add(version)
        db.session.commit()
        return jsonify({'message': 'Policy version created successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>/versions/<int:version_id>/restore', methods=['POST'])
@login_required
@admin_required
def restore_policy_version(policy_id, version_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        version = PolicyVersion.query.get_or_404(version_id)
        
        # Restore policy settings from version
        policy.name = version.name
        policy.description = version.description
        policy.settings = version.settings
        
        db.session.commit()
        return jsonify({'message': 'Policy version restored successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>/schedules')
@login_required
@admin_required
def policy_schedules(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    schedules = PolicySchedule.query.filter_by(policy_id=policy_id).all()
    return render_template('admin/policy_schedules.html', policy=policy, schedules=schedules)

@app.route('/admin/policies/<int:policy_id>/schedules', methods=['POST'])
@login_required
@admin_required
def create_policy_schedule(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        data = request.form
        
        schedule = PolicySchedule(
            policy_id=policy_id,
            start_time=datetime.strptime(data['start_time'], '%Y-%m-%dT%H:%M'),
            end_time=datetime.strptime(data['end_time'], '%Y-%m-%dT%H:%M'),
            is_active=True,
            created_by_id=current_user.id
        )
        
        db.session.add(schedule)
        db.session.commit()
        return jsonify({'message': 'Policy schedule created successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>/schedules/<int:schedule_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_policy_schedule(policy_id, schedule_id):
    try:
        schedule = PolicySchedule.query.get_or_404(schedule_id)
        db.session.delete(schedule)
        db.session.commit()
        return jsonify({'message': 'Policy schedule deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/activity-log')
@login_required
def view_activity_log():
    user_activities = SystemActivity.query.filter_by(user_id=current_user.id).order_by(SystemActivity.timestamp.desc()).all()
    return render_template('activity_log.html', activities=user_activities)

@app.route('/violations')
@login_required
def view_violations():
    user_violations = PolicyViolation.query.filter_by(user_id=current_user.id).order_by(PolicyViolation.timestamp.desc()).all()
    return render_template('violations.html', violations=user_violations)

@app.route('/notifications')
@login_required
def view_notifications():
    # Mark all notifications as read when viewed
    Notification.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True, 'read_at': datetime.utcnow()})
    db.session.commit()
    
    # Fetch all notifications for the user, newest first
    all_notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).all()
    
    return render_template('notifications.html', notifications=all_notifications)

@app.route('/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    try:
        notification = Notification.query.get_or_404(notification_id)
        if notification.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403
            
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'message': 'Notification marked as read'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/notifications/read-all', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id, is_read=False).update({
            'is_read': True,
            'read_at': datetime.utcnow()
        })
        db.session.commit()
        return jsonify({'message': 'All notifications marked as read'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    show_archived = request.args.get('show_archived', 'false').lower() == 'true'
    if show_archived:
        reports = Report.query.order_by(Report.created_at.desc()).all()
    else:
        reports = Report.query.filter_by(is_archived=False).order_by(Report.created_at.desc()).all()
    return render_template('admin/reports.html', reports=reports, show_archived=show_archived)

@app.route('/admin/reports', methods=['POST'])
@login_required
@admin_required
def create_report():
    try:
        data = request.get_json()
        name = data.get('name')
        report_type = data.get('type')
        parameters = data.get('parameters', {})
        schedule = data.get('schedule')
        is_active = data.get('is_active', True)

        # Validate required fields
        if not name or not report_type:
            return jsonify({'success': False, 'error': 'Name and type are required'}), 400

        # Validate report type
        if report_type not in ['violation', 'compliance', 'audit']:
            return jsonify({'success': False, 'error': 'Invalid report type'}), 400

        # Validate parameters based on report type
        if report_type == 'violation':
            if 'start_date' in parameters:
                try:
                    datetime.strptime(parameters['start_date'], '%Y-%m-%d')
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid start date format. Use YYYY-MM-DD'}), 400
            if 'end_date' in parameters:
                try:
                    datetime.strptime(parameters['end_date'], '%Y-%m-%d')
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid end date format. Use YYYY-MM-DD'}), 400
            if 'status' in parameters and parameters['status'] not in ['open', 'resolved']:
                return jsonify({'success': False, 'error': 'Invalid status. Must be open or resolved'}), 400
            if 'policy_id' in parameters:
                try:
                    policy_id = int(parameters['policy_id'])
                    if not Policy.query.get(policy_id):
                        return jsonify({'success': False, 'error': 'Invalid policy ID'}), 400
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid policy ID format'}), 400

        elif report_type == 'compliance':
            if 'policy_type' in parameters and parameters['policy_type'] not in ['access', 'security', 'data']:
                return jsonify({'success': False, 'error': 'Invalid policy type'}), 400
            if 'is_active' in parameters:
                if not isinstance(parameters['is_active'], bool):
                    return jsonify({'success': False, 'error': 'is_active must be a boolean'}), 400

        elif report_type == 'audit':
            if 'start_date' in parameters:
                try:
                    datetime.strptime(parameters['start_date'], '%Y-%m-%d')
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid start date format. Use YYYY-MM-DD'}), 400
            if 'end_date' in parameters:
                try:
                    datetime.strptime(parameters['end_date'], '%Y-%m-%d')
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid end date format. Use YYYY-MM-DD'}), 400
            if 'action' in parameters and parameters['action'] not in ['create', 'update', 'delete', 'login', 'logout']:
                return jsonify({'success': False, 'error': 'Invalid action type'}), 400
            if 'user_id' in parameters:
                try:
                    user_id = int(parameters['user_id'])
                    if not User.query.get(user_id):
                        return jsonify({'success': False, 'error': 'Invalid user ID'}), 400
                except ValueError:
                    return jsonify({'success': False, 'error': 'Invalid user ID format'}), 400

        # Create the report
        report = Report(
            name=name,
            type=report_type,
            parameters=parameters,
            schedule=schedule,
            created_by_id=current_user.id,
            is_active=is_active
        )
        db.session.add(report)
        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Report created successfully',
            'report': {
                'id': report.id,
                'name': report.name,
                'type': report.type,
                'schedule': report.schedule,
                'parameters': report.parameters,
                'is_active': report.is_active,
                'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating report: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/reports/<int:report_id>', methods=['GET'])
@login_required
@admin_required
def get_report_details(report_id):
    """Fetch details for a single report for editing."""
    try:
        report = Report.query.get_or_404(report_id)
        return jsonify({
            'success': True,
            'report': {
                'id': report.id,
                'name': report.name,
                'type': report.type,
                'description': report.description or '',
                'parameters': report.parameters or {},
                'schedule': report.schedule or '',
                'is_active': report.is_active
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching report details for ID {report_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to load report data.'}), 500

@app.route('/admin/reports/<int:report_id>', methods=['PUT'])
@login_required
@admin_required
def update_report(report_id):
    """Update an existing report."""
    try:
        report = Report.query.get_or_404(report_id)
        data = request.get_json()

        name = data.get('name')
        report_type = data.get('type') # Type generally shouldn't change, but check data
        parameters = data.get('parameters', {})
        schedule = data.get('schedule')
        description = data.get('description')
        is_active = data.get('is_active', True)

        # Basic Validation
        if not name or not report_type:
            return jsonify({'success': False, 'error': 'Name and type are required'}), 400
        if report.type != report_type:
             # Prevent changing report type via edit, should delete and recreate if needed
             return jsonify({'success': False, 'error': 'Cannot change report type after creation.'}), 400

        # Update fields
        report.name = name
        report.description = description
        report.parameters = parameters # Assume parameters are validated client-side or reuse validation logic
        report.schedule = schedule
        report.is_active = is_active
        # report.type remains unchanged

        # Flag parameters if it's a JSON field and handled via mutation
        if db.session.is_modified(report):
             flag_modified(report, "parameters")

        db.session.commit()

        return jsonify({
            'success': True, 
            'message': 'Report updated successfully',
            'report': {
                 'id': report.id,
                 'name': report.name,
                 'type': report.type,
                 'schedule': report.schedule,
                 'is_active': report.is_active,
                 'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S') # Return updated info
             }
        })

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating report {report_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/reports/<int:report_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_report(report_id):
    """Delete a report."""
    try:
        report = Report.query.get_or_404(report_id)
        report_name = report.name # Get name for logging before deleting
        db.session.delete(report)
        db.session.commit()

        # Log the activity
        try:
            activity = SystemActivity(
                user_id=current_user.id,
                action='delete_report',
                details=f'Deleted report: {report_name} (ID: {report_id})'
            )
            db.session.add(activity)
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"Error logging report deletion: {str(log_e)}")

        return jsonify({'success': True, 'message': 'Report deleted successfully'})

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting report {report_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/audit-logs')
@login_required
@admin_required
def admin_audit_logs():
    activities = SystemActivity.query.order_by(SystemActivity.timestamp.desc()).all()
    return render_template('admin/audit_logs.html', activities=activities)

# Add new routes for dashboard features
@app.route('/admin/roles')
@login_required
@admin_required
def admin_roles():
    return render_template('admin/roles.html')

@app.route('/admin/audit_trail')
@login_required
@admin_required
def admin_audit_trail():
    return render_template('admin/audit_trail.html')

@app.route('/admin/export_data')
@login_required
@admin_required
def admin_export_data():
    return render_template('admin/export_data.html')

@app.route('/admin/notifications')
@login_required
@admin_required
def admin_notifications():
    return render_template('admin/notifications.html')

@app.route('/admin/alerts')
@login_required
@admin_required
def admin_alerts():
    return render_template('admin/alerts.html')

@app.route('/admin/monitoring')
@login_required
@admin_required
def admin_monitoring():
    return render_template('admin/monitoring.html')

@app.route('/admin/policies', methods=['POST'])
@login_required
@admin_required
def create_policy():
    """Create a new policy, handling settings based on type."""
    try:
        # Get form data
        name = request.form.get('name')
        policy_type = request.form.get('type')
        description = request.form.get('description', '')
        is_active = request.form.get('is_active') == 'true'

        # Basic Validation
        if not name or not policy_type:
            return jsonify({'success': False, 'error': 'Name and type are required'}), 400
        if Policy.query.filter_by(name=name).first():
            return jsonify({'success': False, 'error': 'Policy name already exists'}), 400

        # Build settings dict based on type
        settings = {}
        if policy_type == 'password':
            settings['require_upper'] = request.form.get('require_upper') == 'on'
            settings['require_lower'] = request.form.get('require_lower') == 'on'
            settings['require_numbers'] = request.form.get('require_numbers') == 'on'
            settings['require_special'] = request.form.get('require_special') == 'on'
            try: settings['min_length'] = int(request.form.get('min_length', 8))
            except ValueError: settings['min_length'] = 8
        elif policy_type == 'login':
            try: settings['max_attempts'] = int(request.form.get('max_attempts', 3))
            except ValueError: settings['max_attempts'] = 3
            try: settings['lockout_time'] = int(request.form.get('lockout_time', 30))
            except ValueError: settings['lockout_time'] = 30
        elif policy_type == 'ip':
            settings['allowed_ips'] = [ip.strip() for ip in request.form.get('allowed_ips', '').split('\n') if ip.strip()]
        elif policy_type == 'session':
            try: settings['max_concurrent_sessions'] = int(request.form.get('max_concurrent_sessions', 1))
            except ValueError: settings['max_concurrent_sessions'] = 1
            try: settings['session_timeout'] = int(request.form.get('session_timeout', 30))
            except ValueError: settings['session_timeout'] = 30
            settings['force_logout'] = request.form.get('force_logout') == 'on'
            settings['track_activity'] = request.form.get('track_activity') == 'on'
            
        # Create new policy object
        policy = Policy(
            name=name,
            type=policy_type,
            description=description,
            is_active=is_active,
            settings=settings
        )
        
        db.session.add(policy)
        db.session.commit()
        
        # Log activity
        try:
            activity = SystemActivity(user_id=current_user.id, action='create_policy', details=f'Created policy: {policy.name}')
            db.session.add(activity)
            db.session.commit()
        except Exception as log_e:
            app.logger.error(f"Error logging policy creation: {str(log_e)}")
        
        return jsonify({'success': True, 'message': 'Policy created successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating policy: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>', methods=['GET'])
@login_required
def get_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)

        # Security Check: Allow admins OR users if the policy is assigned to them
        is_admin = current_user.role == 'admin'
        is_assigned = False
        if not is_admin:
            # Check direct assignment
            if UserPolicyAssignment.query.filter_by(user_id=current_user.id, policy_id=policy.id).first():
                is_assigned = True
            else:
                # Check group assignment
                user_group_ids = [group.id for group in current_user.groups]
                if user_group_ids:
                    if PolicyGroupAssignment.query.filter(
                        PolicyGroupAssignment.policy_id == policy.id,
                        PolicyGroupAssignment.group_id.in_(user_group_ids)
                    ).first():
                        is_assigned = True

        if not is_admin and not is_assigned:
            return jsonify({'success': False, 'error': 'Access Denied: Policy not assigned to user.'}), 403

        # If admin or assigned, return details
        return jsonify({
            'success': True,
            'policy': {
                'id': policy.id,
                'name': policy.name,
                'type': policy.type,
                'description': policy.description,
                'is_active': policy.is_active,
                'settings': policy.settings or {},
                'priority': policy.priority
                # Consider excluding sensitive settings if necessary for non-admins
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching policy {policy_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>', methods=['PUT'])
@login_required
@admin_required
def update_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        
        if request.is_json:
            data = request.get_json()
        else:
            # This branch might need adjustment if you ever use form-data for PUT
            data = request.form.to_dict()
        
        # Update basic fields
        policy.name = data.get('name', policy.name)
        policy.type = data.get('type', policy.type)
        policy.description = data.get('description', policy.description)
        policy.is_active = data.get('is_active', False)
        # Update priority, default to existing or 0
        try:
            policy.priority = int(data.get('priority', policy.priority or 0))
        except ValueError:
            policy.priority = policy.priority or 0 # Keep existing on error
        
        # Update settings based on policy type
        settings = policy.settings or {}
        
        if policy.type == 'password':
            settings['require_upper'] = data.get('require_upper', False)
            settings['require_lower'] = data.get('require_lower', False)
            settings['require_numbers'] = data.get('require_numbers', False)
            settings['require_special'] = data.get('require_special', False)
            if 'min_length' in data:
                try: settings['min_length'] = int(data['min_length'])
                except (ValueError, TypeError): settings['min_length'] = settings.get('min_length', 8)
            else: settings['min_length'] = settings.get('min_length', 8)
                 
        elif policy.type == 'login':
            if 'max_attempts' in data:
                try: settings['max_attempts'] = int(data['max_attempts'])
                except (ValueError, TypeError): settings['max_attempts'] = settings.get('max_attempts', 3)
            else: settings['max_attempts'] = settings.get('max_attempts', 3)
            if 'lockout_time' in data:
                 try: settings['lockout_time'] = int(data['lockout_time'])
                 except (ValueError, TypeError): settings['lockout_time'] = settings.get('lockout_time', 30)
            else: settings['lockout_time'] = settings.get('lockout_time', 30)
                
        elif policy.type == 'ip':
            if 'allowed_ips' in data and isinstance(data['allowed_ips'], list):
                settings['allowed_ips'] = [str(ip).strip() for ip in data['allowed_ips'] if str(ip).strip()]
            else: settings['allowed_ips'] = settings.get('allowed_ips', [])
                
        elif policy.type == 'session':
            if 'max_concurrent_sessions' in data: settings['max_concurrent_sessions'] = int(data['max_concurrent_sessions'])
            else: settings['max_concurrent_sessions'] = settings.get('max_concurrent_sessions', 1)
            if 'session_timeout' in data: settings['session_timeout'] = int(data['session_timeout'])
            else: settings['session_timeout'] = settings.get('session_timeout', 30)
            if 'force_logout' in data: settings['force_logout'] = data['force_logout'] == 'on'
            else: settings['force_logout'] = settings.get('force_logout', False)
            if 'track_activity' in data: settings['track_activity'] = data['track_activity'] == 'on'
            else: settings['track_activity'] = settings.get('track_activity', False)
        
        policy.settings = settings
        flag_modified(policy, "settings")
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Policy updated successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating policy: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/policies/<int:policy_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        policy.is_archived = True
        policy.is_active = False  # Also deactivate the policy when archiving
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='archive_policy',
            details=f'Archived policy: {policy.name}'
        )
        db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Policy archived successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        try:
            current_password = form.current_password.data
            new_password = form.new_password.data
            
            # Verify current password
            if not current_user.check_password(current_password):
                flash('Current password is incorrect.', 'error')
                return redirect(url_for('change_password'))

            # Check for password policy violations
            violations = check_policy_violations(current_user, 'password_change', {
                'new_password': new_password
            })
            
            if violations:
                # Record the violation(s)
                record_policy_violations(current_user, violations)
                # Construct error message from violation details
                violation_details = "; ".join([v['details'] for v in violations])
                flash(f'New password violates policy: {violation_details}', 'error')
                return redirect(url_for('change_password'))
            
            # All checks passed, update the password
            try:
                current_user.set_password(new_password)
                # Commit the password change FIRST
                db.session.commit()
                
                # Log the activity (separate commit is fine here)
                try:
                    activity = SystemActivity(
                        user_id=current_user.id,
                        action='password_changed',
                        details='User changed their own password.'
                    )
                    db.session.add(activity)
                    db.session.commit()
                except Exception as log_e:
                    app.logger.error(f"Error logging password change activity for user {current_user.id}: {str(log_e)}")
                    # Don't rollback the password change if only logging failed

                flash('Password updated successfully!', 'success')
                return redirect(url_for('dashboard')) # Redirect to dashboard on success
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error changing password for user {current_user.id}: {str(e)}")
                flash('An error occurred while changing the password. Please try again.', 'error')
                return redirect(url_for('change_password'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Error changing password: {str(e)}")
            flash('An error occurred while changing the password. Please try again.', 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html', form=form)

@app.route('/admin/policies/<int:policy_id>/assign', methods=['POST'])
@login_required
@admin_required
def assign_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        data = request.get_json()
        
        if data.get('assign_type') == 'user':
            user_id = data.get('user_id')
            if not user_id:
                return jsonify({'success': False, 'error': 'User ID is required'}), 400
                
            user = User.query.get_or_404(user_id)
            if user in policy.users:
                return jsonify({'success': False, 'error': 'User is already assigned to this policy'}), 400
                
            # Create assignment
            assignment = UserPolicyAssignment(
                user_id=user_id,
                policy_id=policy_id,
                assigned_by_id=current_user.id
            )
            db.session.add(assignment)
            
            # Log activity
            activity = SystemActivity(
                user_id=current_user.id,
                action='assign_policy_to_user',
                details=f'Assigned policy {policy.name} to user {user.username}'
            )
            db.session.add(activity)
            
        elif data.get('assign_type') == 'group':
            group_id = data.get('group_id')
            if not group_id:
                return jsonify({'success': False, 'error': 'Group ID is required'}), 400
                
            group = UserGroup.query.get_or_404(group_id)
            if group in policy.groups:
                return jsonify({'success': False, 'error': 'Group is already assigned to this policy'}), 400
                
            # Create assignment
            assignment = PolicyGroupAssignment(
                group_id=group_id,
                policy_id=policy_id,
                assigned_by_id=current_user.id
            )
            db.session.add(assignment)
            
            # Log activity
            activity = SystemActivity(
                user_id=current_user.id,
                action='assign_policy_to_group',
                details=f'Assigned policy {policy.name} to group {group.name}'
            )
            db.session.add(activity)
            
        else:
            return jsonify({'success': False, 'error': 'Invalid assignment type'}), 400
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'Policy assigned successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error assigning policy: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/policies/<int:policy_id>/unassign', methods=['POST'])
@login_required
@admin_required
def unassign_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        data = request.get_json()
        
        if 'user_id' in data:
            user_id = data['user_id']
            assignment = UserPolicyAssignment.query.filter_by(
                user_id=user_id,
                policy_id=policy_id
            ).first_or_404()
            
            # Log activity
            activity = SystemActivity(
                user_id=current_user.id,
                action='unassign_policy_from_user',
                details=f'Unassigned policy {policy.name} from user {assignment.user.username}'
            )
            db.session.add(activity)
            
            db.session.delete(assignment)
            
        elif 'group_id' in data:
            group_id = data['group_id']
            assignment = PolicyGroupAssignment.query.filter_by(
                group_id=group_id,
                policy_id=policy_id
            ).first_or_404()
            
            # Log activity
            activity = SystemActivity(
                user_id=current_user.id,
                action='unassign_policy_from_group',
                details=f'Unassigned policy {policy.name} from group {assignment.group.name}'
            )
            db.session.add(activity)
            
            db.session.delete(assignment)
            
        else:
            return jsonify({'success': False, 'error': 'No user_id or group_id provided'}), 400
            
        db.session.commit()
        return jsonify({'success': True, 'message': 'Policy unassigned successfully'})
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unassigning policy: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/user-groups')
@login_required
@admin_required
def admin_user_groups():
    # Check if we should show archived groups
    show_archived = request.args.get('show_archived', 'false').lower() == 'true'
    
    # Get groups based on the show_archived parameter
    if show_archived:
        groups = UserGroup.query.all()
    else:
        groups = UserGroup.query.filter_by(archived=False).all()
    
    return render_template('admin/user_groups.html', groups=groups, show_archived=show_archived)

@app.route('/admin/user-groups', methods=['POST'])
@login_required
@admin_required
def create_user_group():
    try:
        app.logger.debug("Received request to create user group")
        data = request.get_json()
        app.logger.debug(f"Request data: {data}")
        
        # Validate required fields
        if not data.get('name'):
            app.logger.warning("Group name is missing")
            return jsonify({'success': False, 'error': 'Group name is required'}), 400
            
        # Check if group name already exists
        if UserGroup.query.filter_by(name=data['name']).first():
            app.logger.warning(f"Group name already exists: {data['name']}")
            return jsonify({'success': False, 'error': 'A group with this name already exists'}), 400
            
        app.logger.debug(f"Creating new group with name: {data['name']}")
        # Create new group
        group = UserGroup(
            name=data['name'],
            description=data.get('description')
        )
        db.session.add(group)
        
        app.logger.debug("Creating system activity log")
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='create_group',
            details=f'Created new group: {group.name}'
        )
        db.session.add(activity)
        
        app.logger.debug("Committing changes to database")
        # Commit changes
        db.session.commit()
        
        app.logger.debug("Group created successfully")
        return jsonify({'success': True, 'message': 'Group created successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error creating group: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/admin/user-groups/<int:group_id>', methods=['DELETE'])
@login_required
@admin_required
def delete_user_group(group_id):
    try:
        group = UserGroup.query.get_or_404(group_id)
        group_name = group.name
        db.session.delete(group)
        db.session.commit()
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='delete_group',
            details=f'Deleted group: {group_name}'
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/user-groups/<int:group_id>', methods=['GET'])
@admin_required
def get_group(group_id):
    try:
        group = UserGroup.query.get_or_404(group_id)
        return jsonify({
            'success': True,
            'group': {
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'users': [{'id': user.id, 'username': user.username} for user in group.users]
            }
        })
    except Exception as e:
        app.logger.error(f"Error fetching group: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/user-groups/<int:group_id>/assign', methods=['POST'])
@login_required
@admin_required
def assign_user_to_group(group_id):
    try:
        app.logger.debug(f"Assigning user to group {group_id}")
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            }), 400
            
        # Get the group and user
        group = UserGroup.query.get_or_404(group_id)
        user = User.query.get_or_404(user_id)
        
        app.logger.debug(f"Found group: {group.name}, user: {user.username}")
        
        # Check if user is already in the group
        if user in group.users:
            return jsonify({
                'success': False,
                'error': 'User is already in this group'
            }), 400
            
        # Add user to group
        group.users.append(user)
        db.session.commit()
        
        app.logger.debug(f"Successfully added user {user.username} to group {group.name}")
        
        return jsonify({
            'success': True,
            'message': f'User {user.username} added to group {group.name}'
        })
    except Exception as e:
        app.logger.error(f"Error assigning user to group: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/user-groups/<int:group_id>/unassign', methods=['POST'])
@login_required
@admin_required
def unassign_user_from_group_by_id(group_id):
    try:
        app.logger.debug(f"Unassigning user from group {group_id}")
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            }), 400
            
        # Get the group and user
        group = UserGroup.query.get_or_404(group_id)
        user = User.query.get_or_404(user_id)
        
        app.logger.debug(f"Found group: {group.name}, user: {user.username}")
        
        # Check if user is in the group
        if user not in group.users:
            return jsonify({
                'success': False,
                'error': 'User is not in this group'
            }), 400
            
        # Remove user from group
        group.users.remove(user)
        db.session.commit()
        
        app.logger.debug(f"Successfully removed user {user.username} from group {group.name}")
        
        return jsonify({
            'success': True,
            'message': f'User {user.username} removed from group {group.name}'
        })
    except Exception as e:
        app.logger.error(f"Error unassigning user from group: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/reports/<int:report_id>/run', methods=['POST'])
@login_required
@admin_required
def run_report(report_id):
    try:
        report = Report.query.get_or_404(report_id)
        
        # Generate report based on type and parameters
        if report.type == 'violation':
            data = generate_violation_report(report.parameters)
        elif report.type == 'compliance':
            data = generate_compliance_report(report.parameters)
        elif report.type == 'audit':
            data = generate_audit_report(report.parameters)
        else:
            return jsonify({'success': False, 'error': 'Invalid report type'}), 400
            
        # Add report name to the data
        data['name'] = report.name
            
        # Update last run time
        report.last_run = datetime.utcnow()
        db.session.commit()
        
        return jsonify({
            'success': True,
            'data': data
        })
    except Exception as e:
        app.logger.error(f"Error running report: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def generate_violation_report(parameters):
    try:
        query = PolicyViolation.query.join(Policy).join(User)
        
        # Apply filters from parameters
        if parameters:
            if 'start_date' in parameters:
                query = query.filter(PolicyViolation.timestamp >= datetime.strptime(parameters['start_date'], '%Y-%m-%d'))
            if 'end_date' in parameters:
                query = query.filter(PolicyViolation.timestamp <= datetime.strptime(parameters['end_date'], '%Y-%m-%d'))
            if 'status' in parameters:
                # Convert status string to boolean for is_resolved
                if parameters['status'] == 'resolved':
                    query = query.filter(PolicyViolation.is_resolved == True)
                elif parameters['status'] == 'open':
                    query = query.filter(PolicyViolation.is_resolved == False)
            if 'policy_id' in parameters:
                query = query.filter(PolicyViolation.policy_id == parameters['policy_id'])
        
        violations = query.order_by(PolicyViolation.timestamp.desc()).all()
        
        return {
            'type': 'violation',
            'total_violations': len(violations),
            'violations': [{
                'id': v.id,
                'policy_id': v.policy_id,
                'policy_name': v.policy.name if v.policy else 'N/A',
                'user_id': v.user_id,
                'username': v.user.username if v.user else 'N/A',
                'timestamp': v.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'is_resolved': v.is_resolved,
                'status': 'Resolved' if v.is_resolved else 'Open',  # Added for backwards compatibility
                'details': v.details
            } for v in violations]
        }
    except Exception as e:
        app.logger.error(f"Error generating violation report: {str(e)}")
        raise

def generate_compliance_report(parameters):
    try:
        query = Policy.query
        
        # Apply filters from parameters
        if parameters:
            if 'policy_type' in parameters:
                query = query.filter(Policy.type == parameters['policy_type'])
            if 'is_active' in parameters:
                query = query.filter(Policy.is_active == parameters['is_active'])
        
        policies = query.all()
        
        return {
            'type': 'compliance',
            'total_policies': len(policies),
            'policies': [{
                'id': p.id,
                'name': p.name,
                'type': p.type,
                'is_active': p.is_active,
                'total_assignments': len(p.user_assignments) + len(p.groups)
            } for p in policies]
        }
    except Exception as e:
        app.logger.error(f"Error generating compliance report: {str(e)}")
        raise

def generate_audit_report(parameters):
    try:
        query = SystemActivity.query.join(User)
        
        # Apply filters from parameters
        if parameters:
            if 'start_date' in parameters:
                query = query.filter(SystemActivity.timestamp >= datetime.strptime(parameters['start_date'], '%Y-%m-%d'))
            if 'end_date' in parameters:
                query = query.filter(SystemActivity.timestamp <= datetime.strptime(parameters['end_date'], '%Y-%m-%d'))
            if 'action' in parameters:
                query = query.filter(SystemActivity.action == parameters['action'])
            if 'user_id' in parameters:
                query = query.filter(SystemActivity.user_id == parameters['user_id'])
        
        activities = query.order_by(SystemActivity.timestamp.desc()).all()
        
        return {
            'type': 'audit',
            'total_activities': len(activities),
            'activities': [{
                'id': a.id,
                'user_id': a.user_id,
                'username': a.user.username if a.user else 'N/A',
                'action': a.action,
                'timestamp': a.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                'details': a.details
            } for a in activities]
        }
    except Exception as e:
        app.logger.error(f"Error generating audit report: {str(e)}")
        raise

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    try:
        # Basic statistics
        total_users = User.query.count()
        active_users = User.query.filter_by(is_active=True).count()
        total_policies = Policy.query.count()
        assigned_policies = UserPolicyAssignment.query.count() + PolicyGroupAssignment.query.count()
        total_violations = PolicyViolation.query.count()
        pending_violations = PolicyViolation.query.filter_by(is_resolved=False).count()
        total_groups = UserGroup.query.count()
        total_group_members = db.session.query(func.count()).select_from(UserGroupMembership).scalar() or 0

        # Fetch recent activities (admin perspective)
        recent_activities = SystemActivity.query.order_by(SystemActivity.timestamp.desc()).limit(10).all()

        # Fetch recent violations (admin perspective)
        recent_violations = PolicyViolation.query.order_by(PolicyViolation.timestamp.desc()).limit(10).all()
        
        # Fetch high priority policies
        high_priority_policies = Policy.query.filter_by(is_active=True).order_by(Policy.priority.desc()).limit(5).all()

        # Get last backup time (placeholder)
        last_backup = "N/A" # Replace with actual backup tracking logic
        
        return render_template('admin/dashboard.html',
                             total_users=total_users,
                             active_users=active_users,
                             total_policies=total_policies,
                             assigned_policies=assigned_policies,
                             total_violations=total_violations,
                             pending_violations=pending_violations,
                             total_groups=total_groups,
                             total_group_members=total_group_members,
                             last_backup=last_backup,
                             recent_activities=recent_activities,
                             recent_violations=recent_violations, # Added
                             high_priority_policies=high_priority_policies # Added
                            )
    except Exception as e:
        app.logger.error(f"Error loading admin dashboard: {str(e)}")
        flash('Error loading dashboard data', 'error')
        # Redirect to admin dashboard or a safe page on error
        return redirect(url_for('index'))

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    try:
        user = User.query.get_or_404(user_id)
        
        # Generate a random password
        new_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=12))
        
        # Hash the new password
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.password_hash = hashed_password
        
        # Send email with new password
        msg = Message('Password Reset',
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[user.email])
        msg.body = f'Your password has been reset. Your new password is: {new_password}\nPlease change this password after logging in.'
        mail.send(msg)
        
        db.session.commit()
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='reset_password',
            details=f'Reset password for user: {user.username}'
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting password: {str(e)}")  # Add debug logging
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/user-groups/<int:group_id>/members', methods=['GET'])
@login_required
@admin_required
def get_group_members(group_id):
    try:
        group = UserGroup.query.get_or_404(group_id)
        return jsonify({
            'success': True,
            'members': [{
                'id': user.id,
                'username': user.username,
                'email': user.email
            } for user in group.users]
        })
    except Exception as e:
        app.logger.error(f"Error fetching group members: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/policies/<int:policy_id>/assignments')
@login_required
@admin_required
def policy_assignments(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    
    # Get available users (users not already assigned to this policy)
    assigned_user_ids = [user.id for user in policy.users]
    available_users = User.query.filter(
        User.id.notin_(assigned_user_ids),
        User.is_active == True,
        User.is_archived == False
    ).all()
    
    # Get available groups (groups not already assigned to this policy)
    assigned_group_ids = [group.id for group in policy.groups]
    available_groups = UserGroup.query.filter(
        UserGroup.id.notin_(assigned_group_ids),
        UserGroup.archived == False
    ).all()
    
    return render_template('admin/policy_assignments.html',
                         policy=policy,
                         available_users=available_users,
                         available_groups=available_groups)

@app.route('/admin/analytics')
@login_required
@admin_required
def admin_analytics():
    """Display analytics and insights based on system data."""
    try:
        # Define timeframes
        now = datetime.utcnow()
        past_30_days_start = now - timedelta(days=30)
        past_7_days_start = now - timedelta(days=7)
        today_date = now.date()

        # 1. Top 5 Violated Policies (Last 30 Days)
        top_policies_query = db.session.query(
                Policy.name,
                func.count(PolicyViolation.id).label('violation_count')
            ).join(PolicyViolation, PolicyViolation.policy_id == Policy.id)\
            .filter(PolicyViolation.timestamp >= past_30_days_start)\
            .group_by(Policy.id, Policy.name)\
            .order_by(func.count(PolicyViolation.id).desc())\
            .limit(5)\
            .all()
        top_violated_policies = [(name, count) for name, count in top_policies_query]

        # 2. Top 5 Violating Users (Last 30 Days)
        top_users_query = db.session.query(
                User.username,
                func.count(PolicyViolation.id).label('violation_count')
            ).join(PolicyViolation, PolicyViolation.user_id == User.id)\
            .filter(PolicyViolation.timestamp >= past_30_days_start)\
            .group_by(User.id, User.username)\
            .order_by(func.count(PolicyViolation.id).desc())\
            .limit(5)\
            .all()
        top_violating_users = [(name, count) for name, count in top_users_query]

        # 3. Violation Counts per Day (Last 7 Days)
        violations_per_day_dict = {}
        for i in range(7):
            target_date = today_date - timedelta(days=i)
            start_dt = datetime.combine(target_date, datetime.min.time())
            # Use < date + 1 day for simpler range query if timestamps are exact
            end_dt = datetime.combine(target_date + timedelta(days=1), datetime.min.time())
            count = PolicyViolation.query.filter(
                PolicyViolation.timestamp >= start_dt,
                PolicyViolation.timestamp < end_dt
            ).count()
            violations_per_day_dict[target_date.strftime('%Y-%m-%d')] = count
        
        # Prepare data for Chart.js (chronological order)
        daily_labels = sorted(violations_per_day_dict.keys())
        daily_counts = [violations_per_day_dict[label] for label in daily_labels]
        
        # Convert data to JSON strings for embedding in the template script
        chart_labels_json = json.dumps(daily_labels)
        chart_counts_json = json.dumps(daily_counts)

        return render_template('admin/analytics.html',
                               top_violated_policies=top_violated_policies,
                               top_violating_users=top_violating_users,
                               chart_labels=chart_labels_json, # Pass JSON string
                               chart_counts=chart_counts_json  # Pass JSON string
                              )

    except Exception as e:
        app.logger.error(f"Error loading analytics page: {str(e)}")
        flash('Error loading analytics data. Please try again later.', 'error')
        # Redirect to admin dashboard or a safe page on error
        return redirect(url_for('admin_dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            terms_agreement = request.form.get('terms_agreement')

            # Comprehensive validation
            errors = []
            if not username or not email or not password or not confirm_password:
                flash('All fields are required', 'error')
                return redirect(url_for('register'))

            # Email validation
            if not validate_email(email):
                flash('Please enter a valid email address', 'error')
                return redirect(url_for('register'))

                
            # Check if email already exists
            if User.query.filter_by(email=email).first():
                flash('Email address already registered', 'error')
                return redirect(url_for('register'))
                
            # Password validation
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))
                
            # Check password strength
            password_errors = check_password_strength(password)
            if password_errors:
                for error in password_errors:
                    flash(error, 'error')
                return redirect(url_for('register'))

            # Validate terms agreement
            if not terms_agreement:
                flash('You must agree to the terms and conditions to register', 'danger')
                return redirect(url_for('register'))

            # Validate password match
            if password != confirm_password:
                flash('Passwords do not match', 'danger')
                return redirect(url_for('register'))

            # Check if username or email already exists in users or registration requests
            if User.query.filter_by(username=username).first() or RegistrationRequest.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return redirect(url_for('register'))
            if User.query.filter_by(email=email).first() or RegistrationRequest.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('register'))

            # Create registration request
            reg_request = RegistrationRequest(
                username=username,
                email=email,
                status='pending',
                terms_accepted=True  # Record that terms were accepted
            )
            reg_request.set_password(password)
            
            db.session.add(reg_request)
            db.session.commit()
            flash('Registration request submitted! Please wait for admin approval.', 'success')
            return redirect(url_for('login'))

        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('Error during registration. Please try again.', 'danger')
            return redirect(url_for('register'))

    # GET request - show registration form
    return render_template('register.html')

@app.route('/admin/registration-requests')
@login_required
@admin_required
def admin_registration_requests():
    pending_requests = RegistrationRequest.query.filter_by(status='pending').all()
    approved_requests = RegistrationRequest.query.filter_by(status='approved').order_by(RegistrationRequest.processed_at.desc()).limit(10).all()
    rejected_requests = RegistrationRequest.query.filter_by(status='rejected').order_by(RegistrationRequest.processed_at.desc()).limit(10).all()
    
    return render_template('admin/registration_requests.html',
                         pending_requests=pending_requests,
                         approved_requests=approved_requests,
                         rejected_requests=rejected_requests)

@app.route('/admin/registration-requests/<int:request_id>/approve', methods=['POST'])
@login_required
@admin_required
def approve_registration_request(request_id):
    try:
        logger.info(f"Attempting to approve registration request {request_id}")
        registration_request = RegistrationRequest.query.get_or_404(request_id)
        
        if registration_request.status != 'pending':
            logger.warning(f"Request {request_id} is not pending, current status: {registration_request.status}")
            return jsonify({'success': False, 'error': 'Request is not pending'}), 400
            
        try:
            # Create new user
            new_user = User(
                username=registration_request.username,
                email=registration_request.email,
                password_hash=registration_request.password_hash,
                role='user'
            )
            db.session.add(new_user)
            
            # Update request status
            registration_request.status = 'approved'
            registration_request.processed_at = datetime.utcnow()
            registration_request.processed_by_id = current_user.id
            
            db.session.commit()
            logger.info(f"Successfully approved registration request {request_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing approval for request {request_id}: {str(e)}")
            return jsonify({'success': False, 'error': f'Error processing approval: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"Error in approve_registration_request: {str(e)}")
        return jsonify({'success': False, 'error': f'Error approving request: {str(e)}'}), 500

@app.route('/admin/registration-requests/<int:request_id>/reject', methods=['POST'])
@login_required
@admin_required
def reject_registration_request(request_id):
    try:
        logger.info(f"Attempting to reject registration request {request_id}")
        registration_request = RegistrationRequest.query.get_or_404(request_id)
        
        if registration_request.status != 'pending':
            logger.warning(f"Request {request_id} is not pending, current status: {registration_request.status}")
            return jsonify({'success': False, 'error': 'Request is not pending'}), 400
            
        try:
            data = request.get_json()
            if not data or 'reason' not in data:
                logger.warning(f"Missing reason in rejection request {request_id}")
                return jsonify({'success': False, 'error': 'Reason is required'}), 400
                
            # Update request status
            registration_request.status = 'rejected'
            registration_request.processed_at = datetime.utcnow()
            registration_request.processed_by_id = current_user.id
            registration_request.reason = data['reason']
            
            db.session.commit()
            logger.info(f"Successfully rejected registration request {request_id}")
            return jsonify({'success': True})
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error processing rejection for request {request_id}: {str(e)}")
            return jsonify({'success': False, 'error': f'Error processing rejection: {str(e)}'}), 500
            
    except Exception as e:
        logger.error(f"Error in reject_registration_request: {str(e)}")
        return jsonify({'success': False, 'error': f'Error rejecting request: {str(e)}'}), 500

@app.route('/admin/it-dashboard')
@login_required
@admin_required
def it_dashboard():
    # Get counts for dashboard cards
    active_policies_count = Policy.query.filter_by(is_active=True).count()
    open_violations_count = PolicyViolation.query.filter_by(is_resolved=False).count()
    active_users_count = User.query.filter_by(is_active=True, is_archived=False).count()
    active_sessions_count = User.query.filter(User.active_sessions > 0).count()

    # Get recent policies
    recent_policies = Policy.query.order_by(Policy.created_at.desc()).limit(5).all()

    # Get recent violations
    recent_violations = PolicyViolation.query.order_by(PolicyViolation.timestamp.desc()).limit(5).all()

    # Get users with active sessions
    users_with_sessions = User.query.filter(User.active_sessions > 0).all()

    return render_template('admin/it_admin_dashboard.html',
                         active_policies_count=active_policies_count,
                         open_violations_count=open_violations_count,
                         active_users_count=active_users_count,
                         active_sessions_count=active_sessions_count,
                         recent_policies=recent_policies,
                         recent_violations=recent_violations,
                         users_with_sessions=users_with_sessions)

@app.route('/admin/users/<int:user_id>/force-logout', methods=['POST'])
@login_required
@admin_required
def force_logout_user(user_id):
    user = User.query.get_or_404(user_id)
    user.active_sessions = 0
    user.last_activity = None
    db.session.commit()

    # Log the action
    activity = SystemActivity(
        user_id=current_user.id,
        action='force_logout',
        details=f'Forced logout for user {user.username}'
    )
    db.session.add(activity)
    db.session.commit()

    return jsonify({'success': True, 'message': 'User logged out successfully'})

@app.route('/admin/it-policies')
@login_required
@admin_required
def it_policies():
    show_archived = request.args.get('show_archived', 'false').lower() == 'true'
    if show_archived:
        policies = Policy.query.filter_by(is_archived=True).order_by(Policy.created_at.desc()).all()
    else:
        policies = Policy.query.filter_by(is_archived=False).order_by(Policy.created_at.desc()).all()
    return render_template('admin/it_policies.html', policies=policies, show_archived=show_archived)

@app.route('/admin/it-violations')
@login_required
@admin_required
def it_violations():
    violations = PolicyViolation.query.order_by(PolicyViolation.timestamp.desc()).all()
    return render_template('admin/it_violations.html', violations=violations)

@app.route('/admin/policies/<int:policy_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def update_policy_form(policy_id):
    policy = Policy.query.get_or_404(policy_id)
    
    if request.method == 'POST':
        try:
            # Update basic policy information
            policy.name = request.form.get('name')
            policy.description = request.form.get('description')
            policy.is_active = 'is_active' in request.form
            
            # Update policy type specific settings
            if policy.type == Policy.TYPE_PASSWORD:
                policy.settings = {
                    'require_uppercase': 'require_uppercase' in request.form,
                    'require_lowercase': 'require_lowercase' in request.form,
                    'require_numbers': 'require_numbers' in request.form,
                    'require_special': 'require_special' in request.form,
                    'min_length': int(request.form.get('min_length', 8))
                }
            elif policy.type == Policy.TYPE_LOGIN:
                policy.settings = {
                    'max_attempts': int(request.form.get('max_attempts', 3)),
                    'lockout_time': int(request.form.get('lockout_time', 30))
                }
            elif policy.type == Policy.TYPE_IP:
                policy.settings = {
                    'allowed_ips': request.form.get('allowed_ips', '').split(',')
                }
            elif policy.type == Policy.TYPE_SESSION:
                policy.settings = {
                    'max_concurrent_sessions': int(request.form.get('max_concurrent_sessions', 1)),
                    'session_timeout': int(request.form.get('session_timeout', 30)),
                    'force_logout': 'force_logout' in request.form,
                    'track_activity': 'track_activity' in request.form
                }
            
            db.session.commit()
            flash('Policy updated successfully!', 'success')
            return redirect(url_for('it_policies'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating policy: {str(e)}', 'danger')
            return redirect(url_for('update_policy_form', policy_id=policy_id))
    
    return render_template('admin/edit_policy.html', policy=policy)

@app.route('/admin/user-groups/<int:group_id>/archive', methods=['POST'])
@login_required
@admin_required
def archive_user_group(group_id):
    try:
        # Get the group
        group = UserGroup.query.get_or_404(group_id)
        
        # Set the group as archived
        group.archived = True
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='archive_group',
            details=f'Archived group: {group.name}'
        )
        db.session.add(activity)
        
        # Commit changes
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group archived successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error archiving group {group_id}: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/user-groups/<int:group_id>/unarchive', methods=['POST'])
@login_required
@admin_required
def unarchive_user_group(group_id):
    try:
        # Get the group
        group = UserGroup.query.get_or_404(group_id)
        
        # Set the group as not archived
        group.archived = False
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='unarchive_group',
            details=f'Unarchived group: {group.name}'
        )
        db.session.add(activity)
        
        # Commit changes
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group unarchived successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unarchiving group {group_id}: {str(e)}")
        app.logger.error(f"Error type: {type(e)}")
        app.logger.error(f"Error args: {e.args}")
        return jsonify({
            'success': False,
            'error': str(e),
            'error_type': str(type(e).__name__),
            'error_details': str(e.args)
        }), 500

@app.route('/admin/policies/<int:policy_id>/archive', methods=['POST'])
@login_required
@admin_required
def archive_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        policy.is_archived = True
        policy.is_active = False  # Also deactivate the policy when archiving
        db.session.commit()
        flash('Policy archived successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error archiving policy: {str(e)}', 'error')
    return redirect(url_for('it_policies'))

@app.route('/admin/policies/<int:policy_id>/unarchive', methods=['POST'])
@login_required
@admin_required
def unarchive_policy(policy_id):
    try:
        policy = Policy.query.get_or_404(policy_id)
        policy.is_archived = False
        policy.is_active = True  # Reactivate the policy when unarchiving
        
        # Log the activity
        activity = SystemActivity(
            user_id=current_user.id,
            action='unarchive_policy',
            details=f'Unarchived policy: {policy.name}'
        )
        db.session.add(activity)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Policy unarchived successfully'})
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error unarchiving policy {policy_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/reports/<int:report_id>/archive', methods=['POST'])
@login_required
@admin_required
def archive_report(report_id):
    report = Report.query.get_or_404(report_id)
    try:
        report.is_archived = True
        db.session.commit()
        return jsonify({'success': True, 'message': 'Report archived successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/reports/<int:report_id>/unarchive', methods=['POST'])
@login_required
@admin_required
def unarchive_report(report_id):
    report = Report.query.get_or_404(report_id)
    try:
        report.is_archived = False
        db.session.commit()
        return jsonify({'success': True, 'message': 'Report unarchived successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 