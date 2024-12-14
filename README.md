# User Authentication System

## Overview
This is a Python-based User Authentication System built using Tkinter, providing secure user registration, login, and password management functionality.

## Features
- User Registration with Strong Password Requirements
- Secure Login Mechanism
- Password Hashing (using bcrypt)
- Forgot Password Functionality
- Simple Dashboard after Authentication

## Security Features
- Passwords are hashed before storage
- Password complexity requirements:
  - Minimum 8 characters
  - Must contain:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
- Username validation (alphanumeric, minimum 5 characters)
- Random password generation for password reset

## Prerequisites
- Python 3.x
- bcrypt
- tkinter (usually comes pre-installed with Python)

## Installation

1. Clone the repository:
   ```
   git clone [https://github.com/your-username/user-authentication-system.git](https://github.com/YourNuthishere/User-Authentication-Python-Project.git)
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Running the Application
```
python behind.py
```

## Project Structure
- `behind.py`: Main application file containing all classes and logic
- `users.json`: Stores user credentials (hashed passwords)
- `users_data.txt`: Stores unencrypted user data for recovery purposes
- `requirements.txt`: Lists project dependencies

## Classes
- `UserManagement`: Handles user data storage and password hashing
- `Dashboard`: Displays after successful login
- `Registration`: Manages user registration process
- `Login`: Handles user authentication and password reset
- `UserAuthApp`: Main application container

## Security Notes
⚠️ IMPORTANT: 
- The `users_data.txt` file stores unencrypted credentials and should be kept secure
- Always use this application in a controlled, secure environment



