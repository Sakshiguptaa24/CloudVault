from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from backend.app.database import get_db
from backend.app.models import User, MFARecoveryCode, AuditLog
from backend.app.schemas import UserRegister, UserLogin, UserResponse, TokenResponse
from backend.app.auth import verify_password, get_password_hash, create_access_token, get_current_user
from backend.app.services.crypto_service import (
    generate_totp_secret, get_totp_uri, verify_totp_code,
    generate_recovery_codes, hash_recovery_code
)
from backend.app.ai.security import record_audit_log

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication & MFA"])

class MFAEnableRequest(BaseModel):
    secret: str
    code: str

class MFAVerifyRequest(BaseModel):
    user_id: str
    code: str

class MFADisableRequest(BaseModel):
    password: str
    code: str

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email.lower()).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists"
        )

    user = User(
        email=user_in.email.lower(),
        password_hash=get_password_hash(user_in.password),
        full_name=user_in.full_name
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_audit_log(
        user_id=user.id,
        event_type="AUTH_REGISTER",
        action=f"User {user.email} registered",
        details={"email": user.email},
        db=db
    )

    token = create_access_token({"sub": user.id, "email": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_required": False,
        "user": user
    }

@router.post("/login", response_model=TokenResponse)
def login(user_in: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_in.email.lower()).first()
    if not user or not verify_password(user_in.password, user.password_hash):
        if user:
            record_audit_log(
                user_id=user.id,
                event_type="AUTH_LOGIN_FAILED",
                action="Failed password attempt",
                details={"email": user_in.email},
                db=db,
                severity="WARNING"
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is deactivated")

    # Multi-Factor Authentication Check
    if user.mfa_enabled:
        if not user_in.mfa_code:
            # Signal that MFA token is required
            return {
                "access_token": None,
                "token_type": "bearer",
                "mfa_required": True,
                "user": user
            }

        # Validate MFA code (either 6-digit TOTP or 8-char recovery code)
        is_mfa_valid = False
        mfa_input = user_in.mfa_code.strip()

        # Check TOTP
        if len(mfa_input) == 6 and mfa_input.isdigit():
            is_mfa_valid = verify_totp_code(user.mfa_secret, mfa_input)

        # Check Recovery Code
        if not is_mfa_valid:
            code_h = hash_recovery_code(mfa_input)
            rec_code = db.query(MFARecoveryCode).filter(
                MFARecoveryCode.user_id == user.id,
                MFARecoveryCode.code_hash == code_h,
                MFARecoveryCode.is_used == False
            ).first()
            if rec_code:
                rec_code.is_used = True
                rec_code.used_at = datetime.utcnow()
                db.commit()
                is_mfa_valid = True
                record_audit_log(
                    user_id=user.id,
                    event_type="AUTH_RECOVERY_CODE_CONSUMED",
                    action="Used one-time recovery code for login",
                    details={"code_id": rec_code.id},
                    db=db,
                    severity="WARNING"
                )

        if not is_mfa_valid:
            record_audit_log(
                user_id=user.id,
                event_type="AUTH_MFA_FAILED",
                action="Invalid TOTP or recovery code",
                details={"email": user.email},
                db=db,
                severity="WARNING"
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid MFA verification code.")

    record_audit_log(
        user_id=user.id,
        event_type="AUTH_LOGIN_SUCCESS",
        action="Successful authentication",
        details={"email": user.email, "mfa_used": user.mfa_enabled},
        db=db
    )

    token = create_access_token({"sub": user.id, "email": user.email})
    return {
        "access_token": token,
        "token_type": "bearer",
        "mfa_required": False,
        "user": user
    }

@router.post("/token")
def login_for_docs(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username.lower()).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    token = create_access_token({"sub": user.id, "email": user.email})
    return {"access_token": token, "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

# =====================================================================
# MFA ENDPOINTS
# =====================================================================

@router.post("/mfa/setup")
def setup_mfa(current_user: User = Depends(get_current_user)):
    """Generate a new TOTP secret and QR pairing URI for user."""
    secret = generate_totp_secret()
    otpauth_url = get_totp_uri(current_user.email, secret)
    return {
        "secret": secret,
        "otpauth_url": otpauth_url,
        "instructions": "Scan QR code or enter this secret into Google Authenticator or Authy."
    }

@router.post("/mfa/enable")
def enable_mfa(
    req: MFAEnableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verify first TOTP token and activate MFA on account. Generates 8 one-time backup codes."""
    if not verify_totp_code(req.secret, req.code):
        raise HTTPException(status_code=400, detail="Invalid verification code. Please check your authenticator clock.")

    current_user.mfa_secret = req.secret
    current_user.mfa_enabled = True

    # Generate 8 recovery codes
    raw_codes = generate_recovery_codes(8)
    for code in raw_codes:
        rec_entry = MFARecoveryCode(
            user_id=current_user.id,
            code_hash=hash_recovery_code(code),
            is_used=False
        )
        db.add(rec_entry)

    db.commit()

    record_audit_log(
        user_id=current_user.id,
        event_type="AUTH_MFA_ENABLED",
        action="TOTP Multi-Factor Authentication activated",
        details={"codes_count": len(raw_codes)},
        db=db,
        severity="WARNING"
    )

    return {
        "status": "SUCCESS",
        "message": "Multi-Factor Authentication enabled successfully!",
        "recovery_codes": raw_codes,
        "warning": "Save these one-time recovery codes securely. They will not be displayed again."
    }

@router.post("/mfa/disable")
def disable_mfa(
    req: MFADisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Disable MFA on user account. Requires current password and TOTP code."""
    if not verify_password(req.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect password.")

    if not verify_totp_code(current_user.mfa_secret, req.code):
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    current_user.mfa_enabled = False
    current_user.mfa_secret = None

    # Invalidate all recovery codes
    db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == current_user.id).delete()
    db.commit()

    record_audit_log(
        user_id=current_user.id,
        event_type="AUTH_MFA_DISABLED",
        action="TOTP Multi-Factor Authentication disabled",
        details={},
        db=db,
        severity="CRITICAL"
    )

    return {"status": "SUCCESS", "message": "Multi-Factor Authentication disabled."}
