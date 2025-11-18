from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from .models import db, Patient, Doctor, Admin, Department, Appointment, Treatment # Added '.'
from functools import wraps
from datetime import datetime

auth_bp = Blueprint('auth', __name__)
admin_bp = Blueprint('admin', __name__)
doctor_bp = Blueprint('doctor', __name__)
patient_bp = Blueprint('patient', __name__)

# --- Helper: Role-Based Login Required ---
def login_required(role="any"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please log in.", "danger")
                return redirect(url_for('auth.login'))
            if role != "any" and session.get('role') != role:
                flash("Access denied.", "danger")
                return redirect(url_for('auth.login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@auth_bp.route('/', methods=['GET', 'POST'])
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """
    Universal login route for Admin, Doctor, and Patient.
    """
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        print(f"--- DEBUG: Attempting Login for '{username}' ---") # DEBUG PRINT
        
        # 1. Check if Admin
        admin = Admin.query.filter_by(username=username).first()
        if admin:
            print(f"DEBUG: Found Admin user: {admin.username}")
            if admin.check_password(password):
                session['user_id'] = admin.id
                session['role'] = 'admin'
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin.dashboard'))
            else:
                print("DEBUG: Admin password check failed.")
            
        # 2. Check if Doctor
        doctor = Doctor.query.filter_by(username=username).first()
        if doctor:
            print(f"DEBUG: Found Doctor user: {doctor.username}")
            if doctor.check_password(password):
                session['user_id'] = doctor.id
                session['role'] = 'doctor'
                flash(f'Welcome, Dr. {doctor.full_name}!', 'success')
                return redirect(url_for('doctor.dashboard'))
            else:
                print("DEBUG: Doctor password check failed.")

        # 3. Check if Patient
        patient = Patient.query.filter_by(username=username).first()
        if patient:
            print(f"DEBUG: Found Patient user: {patient.username}")
            if patient.check_password(password):
                session['user_id'] = patient.id
                session['role'] = 'patient'
                flash(f'Welcome, {patient.username}!', 'success')
                return redirect(url_for('patient.dashboard'))
            else:
                print("DEBUG: Patient password check failed.")
        else:
            print("DEBUG: No Patient found with that username.")
            
        # 4. If no user found or password wrong
        flash('Invalid credentials.', 'danger')
        return redirect(url_for('auth.login'))

    return render_template('login.html')
@auth_bp.route('/logout')
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.clear() # Wipes the user ID and Role from memory
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """
    Patient registration route with DEBUG PRINTS.
    """
    if request.method == 'POST':
        print("\n--- DEBUG: Registration Attempt Started ---")
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"DEBUG: Form Data Received -> Username: {username}, Password: {'***' if password else 'MISSING'}")

        # 1. Check if fields are empty
        if not username or not password:
            print("DEBUG: ERROR - Missing username or password")
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('auth.register'))

        # 2. Check if username exists in ANY table
        print("DEBUG: Checking if user already exists...")
        if Patient.query.filter_by(username=username).first():
            print(f"DEBUG: Username '{username}' already exists in PATIENT table.")
            flash('Username taken.', 'danger')
            return redirect(url_for('auth.register'))
            
        if Doctor.query.filter_by(username=username).first():
            print(f"DEBUG: Username '{username}' already exists in DOCTOR table.")
            flash('Username taken.', 'danger')
            return redirect(url_for('auth.register'))

        # 3. Create and Save New Patient
        try:
            print("DEBUG: Creating new Patient object...")
            new_patient = Patient(username=username)
            new_patient.set_password(password)
            
            print("DEBUG: Adding to database session...")
            db.session.add(new_patient)
            
            print("DEBUG: Committing to database file...")
            db.session.commit()
            print("DEBUG: SUCCESS! Patient saved to database.")
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            print(f"DEBUG: CRITICAL DATABASE ERROR: {e}")
            db.session.rollback() # Undo any changes if error occurs
            flash('Error creating account. Please try again.', 'danger')
            return redirect(url_for('auth.register'))
    
    # GET request
    return render_template('register.html')
# --- Admin Routes ---
@admin_bp.route('/dashboard')
@login_required(role="admin")
def dashboard():
    # 1. Fetch all data from the database
    doctors = Doctor.query.all()
    patients = Patient.query.all()
    appointments = Appointment.query.all()
    
    # 2. Pass the data to the HTML template
    return render_template('admin_dashboard.html', 
                           doctor_count=len(doctors), 
                           patient_count=len(patients), 
                           appointment_count=len(appointments),
                           doctors=doctors,    # This fills the "Registered Doctors" list
                           patients=patients,  # This fills the "Registered Patients" list
                           appointments=appointments)
@admin_bp.route('/create_doctor', methods=['GET', 'POST'])
@login_required(role="admin")
def create_doctor():
    if request.method == 'POST':
        print("\n--- DEBUG: Creating Doctor ---")
        fullname = request.form.get('fullname')
        specialization = request.form.get('specialization')
        experience = request.form.get('experience')

        print(f"DEBUG: Data -> Name: {fullname}, Spec: {specialization}, Exp: {experience}")

        # 1. Generate a unique username (fullname + random digits if needed could be added later)
        # Simple logic: "John Doe" -> "john.doe"
        username = fullname.lower().replace(" ", ".")
        
        # 2. Check if username exists
        if Doctor.query.filter_by(username=username).first():
            print(f"DEBUG: Username '{username}' already exists!")
            flash(f'Error: Doctor with username "{username}" already exists.', 'danger')
            return redirect(url_for('admin.create_doctor'))

        try:
            # 3. Check/Create Department
            dept = Department.query.filter_by(name=specialization).first()
            if not dept:
                print(f"DEBUG: Creating new Department '{specialization}'")
                dept = Department(name=specialization)
                db.session.add(dept)
                db.session.commit() # Commit to get ID

            # 4. Create Doctor
            print(f"DEBUG: Creating Doctor '{username}'...")
            new_doctor = Doctor(
                username=username,
                full_name=fullname,
                department_id=dept.id,
                experience_years=experience
            )
            # Set default password 'doctor123' for testing
            new_doctor.set_password('doctor123') 
            
            db.session.add(new_doctor)
            db.session.commit()
            print("DEBUG: Doctor saved successfully.")
            
            flash(f'Doctor {fullname} added! (Login: {username} / doctor123)', 'success')
            return redirect(url_for('admin.dashboard'))

        except Exception as e:
            print(f"DEBUG: Database Error: {e}")
            db.session.rollback()
            flash('Database error. Could not add doctor.', 'danger')
            return redirect(url_for('admin.create_doctor'))

    return render_template('a_create.html')
# --- DELETE DOCTOR (Corrected) ---
@admin_bp.route('/delete_doctor/<int:id>', methods=['POST'])
@login_required(role="admin")
def delete_doctor(id):
    doctor = Doctor.query.get_or_404(id)
    
    # In your model, the Doctor IS the user, so we just delete the doctor.
    db.session.delete(doctor)
    db.session.commit()
    
    flash('Doctor removed successfully.', 'success')
    return redirect(url_for('admin.dashboard'))

# --- DELETE PATIENT (Corrected) ---
@admin_bp.route('/delete_patient/<int:id>', methods=['POST'])
@login_required(role="admin")
def delete_patient(id):
    patient = Patient.query.get_or_404(id)
    
    # In your model, the Patient IS the user, so we just delete the patient.
    db.session.delete(patient)
    db.session.commit()
    
    flash('Patient removed successfully.', 'success')
    return redirect(url_for('admin.dashboard'))
# --- EDIT DOCTOR ---
@admin_bp.route('/edit_doctor/<int:id>', methods=['GET', 'POST'])
@login_required(role="admin")
def edit_doctor(id):
    doctor = Doctor.query.get_or_404(id)
    
    if request.method == 'POST':
        doctor.full_name = request.form.get('fullname')
        doctor.experience_years = request.form.get('experience')
        
        # Update Specialization (Department)
        spec_name = request.form.get('specialization')
        department = Department.query.filter_by(name=spec_name).first()
        if not department:
            department = Department(name=spec_name)
            db.session.add(department)
            db.session.commit()
        doctor.department_id = department.id
        
        db.session.commit()
        flash('Doctor details updated!', 'success')
        return redirect(url_for('admin.dashboard'))
        
    return render_template('a_edit.html', doctor=doctor)
# --- Doctor Routes ---
# ... (Keep Auth and Admin sections as they are) ...

# --- Doctor Routes ---
@doctor_bp.route('/dashboard')
@login_required('doctor')
def dashboard():
    # Fetch the Doctor's profile
    doctor = Doctor.query.get(session['user_id'])
    
    # Fetch upcoming appointments
    appointments = Appointment.query.filter_by(doctor_id=doctor.id).all()
    
    return render_template('doctor_dashboard.html', doctor=doctor, appointments=appointments)

@doctor_bp.route('/appointment_action/<int:id>/<string:action>', methods=['POST'])
@login_required('doctor')
def appointment_action(id, action):
    appointment = Appointment.query.get_or_404(id)
    
    if action == 'complete':
        appointment.status = 'Completed'
        flash('Appointment marked as completed.', 'success')
    elif action == 'cancel':
        appointment.status = 'Cancelled'
        flash('Appointment cancelled.', 'warning')
        
    db.session.commit()
    return redirect(url_for('doctor.dashboard'))

@doctor_bp.route('/update_history/<int:appointment_id>', methods=['GET', 'POST'])
@login_required('doctor')
def update_history(appointment_id):
    appointment = Appointment.query.get_or_404(appointment_id)
    
    # Check if treatment already exists
    treatment = Treatment.query.filter_by(appointment_id=appointment.id).first()
    
    if request.method == 'POST':
        diagnosis = request.form.get('diagnosis')
        prescription = request.form.get('prescription')
        medicines = request.form.get('medicines')
        
        if not treatment:
            treatment = Treatment(appointment_id=appointment.id)
            db.session.add(treatment)
        
        treatment.diagnosis = diagnosis
        treatment.prescription = prescription
        treatment.medicines = medicines
        
        # Mark appointment as completed when history is updated
        appointment.status = 'Completed'
        
        db.session.commit()
        flash('Patient history updated successfully!', 'success')
        return redirect(url_for('doctor.dashboard'))
        
    return render_template('doc_update.html', appointment=appointment, treatment=treatment)

@doctor_bp.route('/availability', methods=['GET', 'POST'])
@login_required('doctor')
def availability():
    # For this milestone, we will just render the page. 
    # Full 7-day grid logic requires complex JavaScript.
    if request.method == 'POST':
        flash('Availability saved (Demo Mode).', 'success')
        return redirect(url_for('doctor.dashboard'))
    return render_template('doc_provide_availability.html')


# --- Patient Routes ---
@patient_bp.route('/dashboard')
@login_required(role="patient")
def dashboard():
    current_patient = Patient.query.get(session['user_id'])
    departments = Department.query.all()
    appointments = Appointment.query.filter_by(patient_id=session.get('user_id')).all()
    
    return render_template('patient_dashboard.html', 
                           departments=departments, 
                           appointments=appointments, 
                           user=current_patient)

@patient_bp.route('/book_appointment/<int:doctor_id>', methods=['GET', 'POST'])
@login_required(role="patient")
def book_appointment(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    
    if request.method == 'POST':
        date_str = request.form.get('date')
        time_slot = request.form.get('time_slot')
        
        try:
            appt_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            
            # Check for double booking
            existing = Appointment.query.filter_by(doctor_id=doctor.id, appointment_date=appt_date, time_slot=time_slot).first()
            if existing:
                flash('Doctor is already booked at this time. Please choose another slot.', 'danger')
                return redirect(url_for('patient.book_appointment', doctor_id=doctor.id))
            
            new_appointment = Appointment(
                patient_id=session['user_id'],
                doctor_id=doctor.id,
                appointment_date=appt_date,
                time_slot=time_slot,
                status="Booked"
            )
            db.session.add(new_appointment)
            db.session.commit()
            flash('Appointment booked successfully!', 'success')
            return redirect(url_for('patient.dashboard'))
            
        except ValueError:
            flash('Invalid date format.', 'danger')

    return render_template('p_availability.html', doctor=doctor)

@patient_bp.route('/history')
@login_required(role="patient")
def history():
    treatments = Treatment.query.join(Appointment).filter(Appointment.patient_id == session['user_id']).all()
    return render_template('p_history.html', treatments=treatments)

@patient_bp.route('/department/<int:dept_id>')
@login_required('patient')
def department(dept_id):
    department = Department.query.get_or_404(dept_id)
    return render_template('view_department.html', department=department)

@patient_bp.route('/doctor_profile/<int:doctor_id>')
@login_required('patient')
def doctor_profile(doctor_id):
    doctor = Doctor.query.get_or_404(doctor_id)
    return render_template('view_doctor.html', doctor=doctor)