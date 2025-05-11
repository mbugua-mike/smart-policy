from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import pyotp
import bcrypt

db = SQLAlchemy()

class UserGroup(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    archived = db.Column(db.Boolean, default=False)
    
    # Relationships
    users = db.relationship('User', 
                          secondary='user_group_membership',
                          back_populates='user_groups')
    
    policies = db.relationship('Policy',
                             secondary='policy_group_assignment',
                             back_populates='groups')
    
    def __repr__(self):
        return f'<UserGroup {self.name}>'

class UserGroupMembership(db.Model):
    __tablename__ = 'user_group_membership'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('user_group.id', ondelete='CASCADE'), primary_key=True)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    # Role Constants
    ROLE_USER = 'user'
    ROLE_ADMIN = 'admin'
    ROLE_IT_ADMIN = 'it_admin'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default=ROLE_USER)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    is_archived = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    last_login = db.Column(db.DateTime)
    otp_secret = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Session Management Fields
    max_concurrent_sessions = db.Column(db.Integer, default=1)
    session_timeout_minutes = db.Column(db.Integer, default=30)
    last_activity = db.Column(db.DateTime)
    active_sessions = db.Column(db.Integer, default=0)
    
    # Relationships
    user_groups = db.relationship('UserGroup',
                                secondary='user_group_membership',
                                back_populates='users')
    
    # Alias for user_groups to maintain backward compatibility
    groups = db.relationship('UserGroup',
                           secondary='user_group_membership',
                           back_populates='users',
                           overlaps="user_groups")
    
    # Policy relationships
    policies = db.relationship('Policy',
                             secondary='user_policy_assignment',
                             primaryjoin='User.id == UserPolicyAssignment.user_id',
                             secondaryjoin='UserPolicyAssignment.policy_id == Policy.id',
                             back_populates='users',
                             overlaps="user_policy_assignments,assigned_policies")
    
    user_policy_assignments = db.relationship('UserPolicyAssignment',
                                            foreign_keys='[UserPolicyAssignment.user_id]',
                                            back_populates='user',
                                            overlaps="policies,assigned_policies")
    
    assigned_policies = db.relationship('UserPolicyAssignment',
                                      foreign_keys='[UserPolicyAssignment.assigned_by_id]',
                                      back_populates='assigned_by',
                                      overlaps="policies,user_policy_assignments")

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
    
    def get_otp(self):
        totp = pyotp.TOTP(self.otp_secret)
        return totp.now()
    
    def verify_otp(self, otp):
        totp = pyotp.TOTP(self.otp_secret)
        # Allow for a 4-interval window (2 minutes)
        return totp.verify(otp, valid_window=4)

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

    def generate_otp(self):
        if not self.otp_secret:
            self.otp_secret = pyotp.random_base32()
            db.session.commit()
        return pyotp.TOTP(self.otp_secret).now()

    def verify_otp(self, otp):
        if not self.otp_secret:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(otp, valid_window=4)  # Allow 2 minutes (4 intervals of 30 seconds)

    def is_it_admin(self):
        return self.role == self.ROLE_IT_ADMIN

    def is_admin(self):
        return self.role == self.ROLE_ADMIN

    def promote_to_it_admin(self):
        self.role = self.ROLE_IT_ADMIN
        db.session.commit()

    def demote_from_it_admin(self):
        self.role = self.ROLE_USER
        db.session.commit()

class Policy(db.Model):
    __tablename__ = 'policies'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    is_archived = db.Column(db.Boolean, default=False)
    settings = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    priority = db.Column(db.Integer, default=0)
    
    # Relationships
    users = db.relationship('User',
                          secondary='user_policy_assignment',
                          primaryjoin='Policy.id == UserPolicyAssignment.policy_id',
                          secondaryjoin='UserPolicyAssignment.user_id == User.id',
                          back_populates='policies',
                          overlaps="user_assignments,user_policy_assignments")
    
    groups = db.relationship('UserGroup',
                           secondary='policy_group_assignment',
                           back_populates='policies')
    
    violations = db.relationship('PolicyViolation', back_populates='policy')
    versions = db.relationship('PolicyVersion', back_populates='policy')
    schedules = db.relationship('PolicySchedule', back_populates='policy')
    user_assignments = db.relationship('UserPolicyAssignment',
                                     back_populates='policy',
                                     overlaps="users,policies")
    
    # Policy Types
    TYPE_PASSWORD = 'password'
    TYPE_LOGIN = 'login'
    TYPE_IP = 'ip'
    TYPE_SESSION = 'session'

class PolicyVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False)
    version_number = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    settings = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    policy = db.relationship('Policy', back_populates='versions')
    created_by = db.relationship('User', backref='policy_versions')

class PolicySchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    policy = db.relationship('Policy', back_populates='schedules')
    created_by = db.relationship('User', backref='policy_schedules')

class PolicyGroupAssignment(db.Model):
    __tablename__ = 'policy_group_assignment'
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), primary_key=True)
    group_id = db.Column(db.Integer, db.ForeignKey('user_group.id'), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_by = db.relationship('User', backref='policy_assignments')

class UserPolicyAssignment(db.Model):
    __tablename__ = 'user_policy_assignment'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), primary_key=True)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Relationships
    user = db.relationship('User',
                         foreign_keys=[user_id],
                         back_populates='user_policy_assignments',
                         overlaps="policies,users")
    
    policy = db.relationship('Policy',
                           back_populates='user_assignments',
                           overlaps="policies,users")
    
    assigned_by = db.relationship('User',
                                foreign_keys=[assigned_by_id],
                                back_populates='assigned_policies',
                                overlaps="policies,user_policy_assignments")

class PolicyViolation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policies.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    violation_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=True)
    severity = db.Column(db.String(20), nullable=False, default='medium')  # low, medium, high
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, nullable=False, default=False)
    resolved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    policy = db.relationship('Policy', back_populates='violations')
    user = db.relationship('User', foreign_keys=[user_id], backref=db.backref('violations', lazy=True))
    resolved_by = db.relationship('User', foreign_keys=[resolved_by_id], backref=db.backref('resolved_violations', lazy=True))

class IPRestriction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), nullable=False)
    description = db.Column(db.String(200))
    is_allowed = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45))
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=False)
    
    user = db.relationship('User', backref='login_attempts')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)  # 'violation', 'policy_update', 'schedule', etc.
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read_at = db.Column(db.DateTime)
    related_id = db.Column(db.Integer)  # ID of related entity (policy, violation, etc.)
    related_type = db.Column(db.String(50))  # Type of related entity

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    type = db.Column(db.String(50), nullable=False)  # 'violation', 'compliance', 'audit'
    parameters = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by = db.relationship('User', backref='reports')
    last_run = db.Column(db.DateTime)
    schedule = db.Column(db.String(100))  # Cron expression for scheduled reports
    is_active = db.Column(db.Boolean, default=True)
    is_archived = db.Column(db.Boolean, default=False)

class SystemActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='activities')

class RegistrationRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    processed_at = db.Column(db.DateTime)
    processed_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    processed_by = db.relationship('User', backref='processed_requests')
    reason = db.Column(db.String(500))  # Reason for rejection if applicable
    terms_accepted = db.Column(db.Boolean, default=False)  # Whether user accepted terms and conditions

    def set_password(self, password):
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    
    # Relationships
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='questions')
    answers = db.relationship('Answer', back_populates='question', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Question {self.title}>'

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    
    # Relationships
    question_id = db.Column(db.Integer, db.ForeignKey('question.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    question = db.relationship('Question', back_populates='answers')
    user = db.relationship('User', backref='answers')
    
    def __repr__(self):
        return f'<Answer to Question {self.question_id}>'
