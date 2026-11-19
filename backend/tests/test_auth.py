import pytest
from fastapi import HTTPException
from backend.app.schemas import UserRegister, UserLogin
from backend.app.routers.auth import register, login, get_me
from backend.app.auth import verify_password, get_password_hash, create_access_token, get_current_user

def test_auth_registration_and_login(db_session):
    # 1. Register new user
    user_in = UserRegister(
        email="student@university.edu",
        password="SecurePassword2026!",
        full_name="Alex River"
    )
    res = register(user_in, db_session)
    assert "access_token" in res
    assert res["user"].email == "student@university.edu"
    assert res["user"].full_name == "Alex River"
    assert verify_password("SecurePassword2026!", res["user"].password_hash)

    # 2. Duplicate registration must fail with 400
    with pytest.raises(HTTPException) as exc_info:
        register(user_in, db_session)
    assert exc_info.value.status_code == 400

    # 3. Login with correct password
    login_in = UserLogin(
        email="student@university.edu",
        password="SecurePassword2026!"
    )
    login_res = login(login_in, db_session)
    token = login_res["access_token"]
    assert token is not None
    assert login_res["user"].email == "student@university.edu"

    # 4. Login with incorrect password must fail with 401
    bad_login = UserLogin(
        email="student@university.edu",
        password="WrongPassword!"
    )
    with pytest.raises(HTTPException) as bad_exc:
        login(bad_login, db_session)
    assert bad_exc.value.status_code == 401

    # 5. Token validation & get_current_user
    current_user = get_current_user(token, db_session)
    assert current_user.id == res["user"].id
    assert current_user.email == "student@university.edu"

    # 6. Invalid token fails
    with pytest.raises(HTTPException) as token_exc:
        get_current_user("invalid.jwt.token", db_session)
    assert token_exc.value.status_code == 401
