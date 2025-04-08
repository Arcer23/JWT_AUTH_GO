🔐 Authentication Backend with Go and Gin 

    User Registration & Login

        Secure signup and login with validation

        Email uniqueness checks

    Password Hashing

        Uses bcrypt to hash passwords before storing them in the database

    JWT Authentication

        Generates and verifies JSON Web Tokens (JWTs) for stateless authentication

        Tokens include claims like user ID and expiration time

    Refresh Token Mechanism

        Issues long-lived refresh tokens for extended sessions

        Access tokens can be renewed securely

    Middleware for Protected Routes

        Auth middleware to restrict access to authenticated users

        Parses and validates JWT from headers

    Role-Based Access Control

        Supports user roles (e.g., Admin, User) for fine-grained permission management

    Clean Code Structure

        Modular and scalable folder structure for easy maintenance and extension
