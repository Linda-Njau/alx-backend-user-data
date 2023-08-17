#!/usr/bin/env python3
"""integration tests for app.py"""

import requests

BASE_URL = "http://0.0.0.0:5000"


def register_user(email: str, password: str) -> None:
    """Register a user"""
    response = requests.post(
        f"{BASE_URL}/users", data={
            "email": email,
            "password": password
        })
    assert response.status_code == 200


def log_in_wrong_password(email: str, password: str) -> None:
    """Log in a user with the wrong password"""
    response = requests.post(
        f"{BASE_URL}/sessions", data={
            "email": email,
            "password": password
            })
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Log in a user with password"""
    response = requests.post(
        f"{BASE_URL}/sessions", data={
            "email": email,
            "password": password
            })
    assert response.status_code == 200


def profile_unlogged() -> None:
    """trys to access the profile unlogged"""
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """profile access"""
    response = requests.get(
        f"{BASE_URL}/profile", cookies={
            "session_id": session_id})
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """Log out a session"""
    response = requests.delete(
        f"{BASE_URL}/sessions", cookies={
            "session_id": session_id})
    assert response.status_code == 302


def reset_password_token(email: str) -> str:
    """Reset password"""
    response = requests.post(
        f"{BASE_URL}/reset_password", data={
            "email": email})
    assert response.status_code == 200


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """updates the password"""
    response = requests.put(
        f"{BASE_URL}/reset_password",
        data={"email": email,
              "reset_token": reset_token,
              "new_password": new_password
              })
    assert response.status_code == 200


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
