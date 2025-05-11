from datetime import datetime
from models import db

class ITPolicy(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)  # e.g., 'security', 'software', 'hardware', 'network'
    department = db.Column(db.String(50), nullable=False, default='IT')
    is_active = db.Column(db.Boolean, default=True)
    is_archived = db.Column(db.Boolean, default=False)
    requires_consent = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_by = db.relationship('User', backref='created_it_policies')
    
    # Policy details stored as JSON
    details = db.Column(db.JSON)
    
    # Relationships
    assignments = db.relationship('ITPolicyAssignment', back_populates='policy')
    feedback = db.relationship('ITPolicyFeedback', back_populates='policy')

class ITPolicyAssignment(db.Model):
    __tablename__ = 'it_policy_assignment'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('it_policy.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assigned_at = db.Column(db.DateTime, default=datetime.utcnow)
    assigned_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected
    
    # Relationships
    policy = db.relationship('ITPolicy', back_populates='assignments')
    user = db.relationship('User', foreign_keys=[user_id], backref='it_policy_assignments')
    assigned_by = db.relationship('User', foreign_keys=[assigned_by_id], backref='assigned_it_policies')

class ITPolicyFeedback(db.Model):
    __tablename__ = 'it_policy_feedback'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('it_policy.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    feedback_type = db.Column(db.String(20), nullable=False)  # consent, comment, concern
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    policy = db.relationship('ITPolicy', back_populates='feedback')
    user = db.relationship('User', backref='it_policy_feedback') 