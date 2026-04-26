from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone, date
from backend.app.database import get_db
from backend.app.models.db_models import ScanResult
from sqlalchemy import func

router = APIRouter()

# Global Intelligence — Source: Cloudflare/APWG Phishing Reports 2025
GLOBAL_TOP_BRANDS = [
    {"brand": "Microsoft", "category": "Enterprise SaaS", "share": "28%"},
    {"brand": "Google", "category": "Consumer Services", "share": "16%"},
    {"brand": "Amazon", "category": "E-Commerce", "share": "11%"},
    {"brand": "Apple", "category": "Consumer Tech", "share": "9%"},
    {"brand": "Netflix", "category": "Streaming", "share": "7%"},
    {"brand": "Facebook", "category": "Social Media", "share": "6%"},
    {"brand": "PayPal", "category": "Financial Services", "share": "5%"},
    {"brand": "DHL", "category": "Logistics", "share": "4%"},
    {"brand": "LinkedIn", "category": "Professional Network", "share": "3%"},
    {"brand": "Wells Fargo", "category": "Banking", "share": "2%"},
]

@router.get("/")
def get_analytics(
    db: Session = Depends(get_db),
    days: int = Query(default=7, ge=0, description="Filter window in days. 0 = all time.")
):
    """
    Returns historical scan data for the dashboard with time-filtering.
    """
    now = datetime.now(timezone.utc)
    
    # Define time cutoff
    if days > 0:
        cutoff = now - timedelta(days=days)
    else:
        cutoff = None

    # 1. Total Scans
    total_q = db.query(ScanResult)
    if cutoff:
        total_q = total_q.filter(ScanResult.timestamp >= cutoff)
    total_scans = total_q.count()
    
    # 2. Scans by Risk Level
    risk_q = db.query(ScanResult.risk_level, func.count(ScanResult.id))
    if cutoff:
        risk_q = risk_q.filter(ScanResult.timestamp >= cutoff)
    risk_distribution = risk_q.group_by(ScanResult.risk_level).all()
    
    # 3. Daily Volume (for trend chart, backfilled)
    if days > 0:
        chart_days = days
    else:
        oldest = db.query(func.min(ScanResult.timestamp)).scalar()
        if oldest:
            diff_days = (now.date() - oldest.date()).days + 1
            chart_days = max(7, min(diff_days, 90)) # At least 7 days, cap at 90 days
        else:
            chart_days = 30
            
    chart_cutoff = now - timedelta(days=chart_days)
    daily_raw = db.query(
        func.date(ScanResult.timestamp),
        func.count(ScanResult.id)
    ).filter(ScanResult.timestamp >= chart_cutoff)\
     .group_by(func.date(ScanResult.timestamp))\
     .order_by(func.date(ScanResult.timestamp)).all()
    
    # Backfill missing days
    volume_map = {str(row[0]): row[1] for row in daily_raw}
    daily_volume = []
    for i in range(chart_days):
        d = (now - timedelta(days=chart_days - 1 - i)).date()
        daily_volume.append({"date": str(d), "count": volume_map.get(str(d), 0)})

    # 4. Top Brands Detected from user's scans (Case-insensitive grouping)
    brand_q = db.query(
        func.lower(ScanResult.brand_name).label("brand_lower"),
        func.count(ScanResult.id)
    ).filter(ScanResult.brand_name != None)
    if cutoff:
        brand_q = brand_q.filter(ScanResult.timestamp >= cutoff)
    
    top_brands_raw = brand_q.group_by(func.lower(ScanResult.brand_name))\
     .order_by(func.count(ScanResult.id).desc())\
     .limit(5).all()
    
    top_brands = [{"brand": b[0].title(), "count": b[1]} for b in top_brands_raw]

    return {
        "total_scans": total_scans,
        "risk_distribution": {r[0]: r[1] for r in risk_distribution},
        "daily_volume": daily_volume,
        "top_brands": top_brands,
        "top_impersonated_brands": GLOBAL_TOP_BRANDS,
        "last_updated": now.isoformat(),
        "filter_days": days
    }

@router.get("/scans")
def get_scan_list(
    db: Session = Depends(get_db),
    filter: str = Query(default="all", description="Filter: 'all', 'malicious', or 'safe'"),
    days: int = Query(default=7, ge=0, description="Time window. 0 = all time."),
    limit: int = Query(default=50, ge=1, le=100)
):
    """Returns a filtered list of scans for the stat card drill-down."""
    now = datetime.now(timezone.utc)
    
    q = db.query(ScanResult)
    
    # Time filter
    if days > 0:
        q = q.filter(ScanResult.timestamp >= now - timedelta(days=days))
    
    # Risk filter
    if filter == "malicious":
        q = q.filter(ScanResult.risk_level.in_(["High", "Medium", "Malicious", "Unknown"]))
    elif filter == "safe":
        q = q.filter(ScanResult.risk_level.in_(["Low", "Safe"]))
    # "all" -> no additional filter
    
    scans = q.order_by(ScanResult.timestamp.desc()).limit(limit).all()
    
    return [{
        "url": s.url,
        "risk_level": s.risk_level,
        "risk_score": s.risk_score,
        "brand_name": s.brand_name,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None
    } for s in scans]
