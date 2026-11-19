from fastapi import APIRouter, Depends, Query
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import User
from backend.app.auth import get_current_user
from backend.app.services.analytics_service import (
    get_analytics_overview,
    get_storage_forecast,
    get_top_large_files,
    calculate_backup_health_score,
    get_backup_failure_trends,
    get_storage_optimization_suggestions
)
from backend.app.ai.tools import tool_get_backup_recommendations

router = APIRouter(prefix="/api/v1/analytics", tags=["Predictive Analytics"])

@router.get("/overview")
def analytics_overview(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve comprehensive storage utilization, deduplication savings, multi-cloud cost models, and file breakdown."""
    return get_analytics_overview(current_user.id, db)

@router.get("/storage-forecast")
def storage_forecast(
    days: int = Query(30, ge=7, le=365),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Forecast storage growth and predict days until quota is exhausted based on historical rates and linear regression."""
    return get_storage_forecast(current_user.id, db, forecast_days=days)

@router.get("/recommendations")
def backup_recommendations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve intelligent schedule and retention policy recommendations."""
    return tool_get_backup_recommendations(current_user.id, db)

@router.get("/health-score")
@router.get("/backup-health-score")
def backup_health_score(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Calculate multi-dimensional Backup Health Score (0 - 100)."""
    return calculate_backup_health_score(current_user.id, db)

@router.get("/large-files")
def list_large_files(
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Identify the largest files stored across all protected snapshots."""
    return {"large_files": get_top_large_files(current_user.id, db, limit=limit)}

@router.get("/failure-trends")
def backup_failure_trends(
    lookback_days: int = Query(30, ge=1, le=90),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Analyze historical backup failures, group root causes, and provide actionable remediation advice."""
    return get_backup_failure_trends(current_user.id, db, lookback_days=lookback_days)

@router.get("/optimizations")
def storage_optimizations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve data lifecycle, cold file tiering, and deduplication optimization suggestions."""
    return get_storage_optimization_suggestions(current_user.id, db)
