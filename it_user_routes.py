from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from it_models import ITPolicy, ITPolicyAssignment, ITPolicyFeedback
from app import db

it_user = Blueprint('it_user', __name__)

@it_user.route('/my-it-policies')
@login_required
def my_it_policies():
    # Get all policies assigned to the user
    assignments = ITPolicyAssignment.query.filter_by(user_id=current_user.id).all()
    return render_template('it_user/my_policies.html', assignments=assignments)

@it_user.route('/it-policies/<int:policy_id>')
@login_required
def view_it_policy(policy_id):
    policy = ITPolicy.query.get_or_404(policy_id)
    assignment = ITPolicyAssignment.query.filter_by(
        policy_id=policy_id,
        user_id=current_user.id
    ).first()
    
    if not assignment:
        flash('You do not have access to this policy.', 'error')
        return redirect(url_for('it_user.my_it_policies'))
    
    return render_template('it_user/view_policy.html', policy=policy, assignment=assignment)

@it_user.route('/it-policies/<int:policy_id>/respond', methods=['POST'])
@login_required
def respond_to_policy(policy_id):
    policy = ITPolicy.query.get_or_404(policy_id)
    assignment = ITPolicyAssignment.query.filter_by(
        policy_id=policy_id,
        user_id=current_user.id
    ).first()
    
    if not assignment:
        flash('You do not have access to this policy.', 'error')
        return redirect(url_for('it_user.my_it_policies'))
    
    action = request.form.get('action')
    feedback = request.form.get('feedback', '')
    
    if action == 'accept':
        assignment.status = 'accepted'
    elif action == 'reject':
        assignment.status = 'rejected'
    
    # Create feedback if provided
    if feedback:
        policy_feedback = ITPolicyFeedback(
            policy_id=policy_id,
            user_id=current_user.id,
            feedback_type='comment',
            content=feedback
        )
        db.session.add(policy_feedback)
    
    db.session.commit()
    
    flash(f'Policy {action}ed successfully!', 'success')
    return redirect(url_for('it_user.my_it_policies'))

@it_user.route('/it-policies/<int:policy_id>/feedback', methods=['POST'])
@login_required
def add_policy_feedback(policy_id):
    policy = ITPolicy.query.get_or_404(policy_id)
    assignment = ITPolicyAssignment.query.filter_by(
        policy_id=policy_id,
        user_id=current_user.id
    ).first()
    
    if not assignment:
        flash('You do not have access to this policy.', 'error')
        return redirect(url_for('it_user.my_it_policies'))
    
    feedback_type = request.form.get('feedback_type')
    content = request.form.get('content')
    
    if not content:
        flash('Feedback content cannot be empty.', 'error')
        return redirect(url_for('it_user.view_it_policy', policy_id=policy_id))
    
    policy_feedback = ITPolicyFeedback(
        policy_id=policy_id,
        user_id=current_user.id,
        feedback_type=feedback_type,
        content=content
    )
    
    db.session.add(policy_feedback)
    db.session.commit()
    
    flash('Feedback submitted successfully!', 'success')
    return redirect(url_for('it_user.view_it_policy', policy_id=policy_id)) 