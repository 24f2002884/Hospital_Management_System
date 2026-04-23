# 🏥 Hospital Management System

## 📌 Overview

This project is a **Flask-based Hospital Management System** designed to streamline interactions between **Admins, Doctors, and Patients**. It provides role-based access control, enabling efficient management of hospital operations such as appointments, treatments, and user records.

---

## 🚀 Features

### 🔐 Authentication & Authorization

* Secure login/logout system
* Role-based access control (Admin, Doctor, Patient)

### 👨‍⚕️ Admin Functionalities

* Dashboard with search capabilities
* Create, update, and delete:

  * Doctors
  * Patients
* View complete patient history

### 🩺 Doctor Functionalities

* View assigned appointments
* Update treatment records
* Manage availability schedule

### 🧑‍🤝‍🧑 Patient Functionalities

* User registration
* Book appointments
* View appointment and treatment history

### 🗄️ Database Operations

* Full CRUD operations
* Managed relationships using SQLAlchemy ORM:

  * Users
  * Appointments
  * Treatments
  * Doctor availability

---

## 🏗️ Project Architecture

### Core Components

* **`app.py`**

  * Entry point of the application
  * Initializes Flask app using `create_app()`
  * Sets up database using `setup_database()`
  * Runs the server

* **`models.py`**

  * Defines database schema:

    * Admin
    * Department
    * Doctor
    * Patient
    * Appointment
    * Treatment
    * DoctorAvailability
  * Handles relationships and password logic

* **`controllers.py`**

  * Contains Flask Blueprints:

    * `auth_bp` → Authentication
    * `admin_bp` → Admin operations
    * `doctor_bp` → Doctor operations
    * `patient_bp` → Patient operations
  * Implements routing, logic, and role-based access

* **`database.py`**

  * Configures SQLAlchemy ORM (`db = SQLAlchemy()`)

* **Templates (`templates/`)**

  * HTML files for:

    * Login & Registration
    * Dashboards
    * CRUD operations

* **App Factory & DB Setup**

  * `create_app()` → App configuration
  * `setup_database()` → Database initialization

---

## 📂 Project Structure

```
app.py
hospital_management/
│
├── application/
│   ├── models.py
│   ├── controllers.py
│   ├── database.py
│   ├── templates/
│   └── hospital.db
│
requirements.txt
```

---

## ⚙️ Installation & Setup

### Prerequisites

* Python 3.x
* pip
* virtualenv (recommended)

### Steps

```bash
# Create virtual environment
python -m venv venv

# Activate environment
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

# Install dependencies
pip install -r requirements.txt
```

---

## 🛠️ Database Initialization

```python
from hospital_management.application import create_app, setup_database

app = create_app()
setup_database(app)
```

---

## ▶️ Running the Application

```bash
python app.py
```

Visit:

```
http://localhost:5000
```

---

## 🔑 Role-Based Access

| Role    | Permissions                               |
| ------- | ----------------------------------------- |
| Admin   | Manage doctors, patients, view reports    |
| Doctor  | Manage appointments, update treatments    |
| Patient | Register, book appointments, view history |

---

## 🤝 Contributing

Contributions are welcome. You can:

* Fork the repository
* Create a feature branch
* Submit a pull request

---

## 📄 License

This project is open-source. Add a license if required.

---

## 📌 Summary

This system provides a structured and scalable solution for hospital operations using:

* Flask for backend
* SQLAlchemy for ORM
* Role-based architecture for security

It is designed to be **modular, extensible, and easy to maintain**, making it suitable for both learning and real-world adaptation.
