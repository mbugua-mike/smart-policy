from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from functools import wraps
from models import User
from it_models import ITPolicy, ITPolicyAssignment, ITPolicyFeedback
from app import db
from datetime import datetime

it_admin = Blueprint('it_admin', __name__)

def it_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'it_admin':
            flash('Access denied. IT Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@it_admin.route('/it-admin/dashboard')
@login_required
@it_admin_required
def it_dashboard():
    # Get statistics
    total_policies = ITPolicy.query.count()
    active_policies = ITPolicy.query.filter_by(is_active=True).count()
    pending_consents = ITPolicyAssignment.query.filter_by(status='pending').count()
    
    # Get recent policies
    recent_policies = ITPolicy.query.order_by(ITPolicy.created_at.desc()).limit(5).all()
    
    return render_template('it_admin/dashboard.html',
                         total_policies=total_policies,
                         active_policies=active_policies,
                         pending_consents=pending_consents,
                         recent_policies=recent_policies)

@it_admin.route('/it-admin/policies')
@login_required
@it_admin_required
def it_policies():
    show_archived = request.args.get('show_archived', 'false').lower() == 'true'
    if show_archived:
        policies = ITPolicy.query.filter_by(is_archived=True).order_by(ITPolicy.created_at.desc()).all()
    else:
        policies = ITPolicy.query.filter_by(is_archived=False).order_by(ITPolicy.created_at.desc()).all()
    return render_template('it_admin/policies.html', policies=policies, show_archived=show_archived)

@it_admin.route('/it-admin/policies/create', methods=['GET', 'POST'])
@login_required
@it_admin_required
def create_it_policy():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category = request.form.get('category')
        requires_consent = request.form.get('requires_consent') == 'on'
        
        # Create policy
        policy = ITPolicy(
            name=name,
            description=description,
            category=category,
            requires_consent=requires_consent,
            created_by_id=current_user.id,
            details=request.form.get('details', {})
        )
        
        db.session.add(policy)
        db.session.commit()
        
        flash('IT Policy created successfully!', 'success')
        return redirect(url_for('it_admin.it_policies'))
    
    return render_template('it_admin/create_policy.html')

@it_admin.route('/it-admin/policies/<int:policy_id>/assign', methods=['GET', 'POST'])
@login_required
@it_admin_required
def assign_it_policy(policy_id):
    policy = ITPolicy.query.get_or_404(policy_id)
    
    if request.method == 'POST':
        user_ids = request.form.getlist('user_ids')
        
        for user_id in user_ids:
            # Check if assignment already exists
            existing = ITPolicyAssignment.query.filter_by(
                policy_id=policy_id,
                user_id=user_id
            ).first()
            
            if not existing:
                assignment = ITPolicyAssignment(
                    policy_id=policy_id,
                    user_id=user_id,
                    assigned_by_id=current_user.id
                )
                db.session.add(assignment)
        
        db.session.commit()
        flash('Policy assigned successfully!', 'success')
        return redirect(url_for('it_admin.it_policies'))
    
    users = User.query.all()
    return render_template('it_admin/assign_policy.html', policy=policy, users=users)

@it_admin.route('/it-admin/policies/<int:policy_id>/feedback')
@login_required
@it_admin_required
def view_policy_feedback(policy_id):
    policy = ITPolicy.query.get_or_404(policy_id)
    feedback = ITPolicyFeedback.query.filter_by(policy_id=policy_id).all()
    return render_template('it_admin/policy_feedback.html', policy=policy, feedback=feedback)

@it_admin.route('/it-admin/consents')
@login_required
@it_admin_required
def pending_consents():
    assignments = ITPolicyAssignment.query.filter_by(status='pending').all()
    return render_template('it_admin/pending_consents.html', assignments=assignments)

@it_admin.route('/it-admin/policies/<int:policy_id>/archive', methods=['POST'])
@login_required
@it_admin_required
def archive_it_policy(policy_id):
    try:
        policy = ITPolicy.query.get_or_404(policy_id)
        policy.is_archived = True
        policy.is_active = False  # Also deactivate the policy when archiving
        db.session.commit()
        flash('Policy archived successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error archiving policy: {str(e)}', 'error')
    return redirect(url_for('it_admin.it_policies')) 