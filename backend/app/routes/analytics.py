from fastapi import APIRouter, Depends, Query, Header, HTTPException
from typing import Optional
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone, date
from backend.app.database import get_db
from backend.app.models.db_models import ScanResult, EmailScanResult
from backend.app.utils.auth import get_current_user, has_access_to_client, AuthUser, validate_client_id_pattern
from sqlalchemy import func, case
import json
import logging
from collections import Counter

logger = logging.getLogger(__name__)

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
    days: int = Query(default=7, ge=0, description="Filter window in days. 0 = all time."),
    x_client_id: Optional[str] = Header(None),
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Returns historical scan data for the dashboard with time-filtering.

    Args:
        db (Session): Database session.
        days (int): Time window filter in days.
        x_client_id (Optional[str]): The client identifier passed via X-Client-Id header. Scopes data to this client.
        current_user (AuthUser): Authenticated user principal.
    """
    # Enforce authorization: verify user can access this client_id
    has_access_to_client(current_user, x_client_id)
    
    now = datetime.now(timezone.utc)
    
    # Define time cutoff
    if days > 0:
        cutoff = now - timedelta(days=days)
    else:
        cutoff = None

    # Define chart window and cutoff
    if days > 0:
        chart_days = days
    else:
        # Filter by client_id if present for chart range
        oldest_url_q = db.query(func.min(ScanResult.timestamp))
        if x_client_id:
            oldest_url_q = oldest_url_q.filter(ScanResult.client_id == x_client_id)
        oldest_url = oldest_url_q.scalar()

        if oldest_url:
            try:
                # Handle possible string vs date object from SQLite/Postgres
                o_date = oldest_url.date() if hasattr(oldest_url, 'date') else datetime.fromisoformat(str(oldest_url)).date()
            except (ValueError, TypeError, AttributeError):
                o_date = now.date()
            
            diff_days = (now.date() - o_date).days + 1
            chart_days = max(7, min(diff_days, 90))
        else:
            chart_days = 30
    
    chart_cutoff = now - timedelta(days=chart_days)

    # --- 1. URL INTELLIGENCE DATA ---
    # Fetch only the LATEST scan for each unique URL within the time window
    url_latest_sub = db.query(func.max(ScanResult.id).label("latest_id")).group_by(ScanResult.url)
    if cutoff:
        url_latest_sub = url_latest_sub.filter(ScanResult.timestamp >= cutoff)
    if x_client_id:
        url_latest_sub = url_latest_sub.filter(ScanResult.client_id == x_client_id)
        
    url_latest_ids = url_latest_sub.subquery()

    # Total Unique URL Scans
    url_total_scans = db.query(ScanResult).filter(ScanResult.id.in_(url_latest_ids)).count()
    
    # URL Risk Distribution (on unique urls)
    url_risk_raw = db.query(ScanResult.risk_level, func.count(ScanResult.id)) \
        .filter(ScanResult.id.in_(url_latest_ids)) \
        .group_by(ScanResult.risk_level).all()
    # Normalize keys to lowercase for frontend consistency
    url_risk_dist = {}
    for r in url_risk_raw:
        k = str(r[0] or "unknown").lower()
        url_risk_dist[k] = url_risk_dist.get(k, 0) + r[1]
    
    # URL Daily Volume (unique scans per day)
    url_daily_q = db.query(
        func.date(ScanResult.timestamp),
        func.count(ScanResult.id)
    ).filter(ScanResult.timestamp >= chart_cutoff)
    if x_client_id:
        url_daily_q = url_daily_q.filter(ScanResult.client_id == x_client_id)
        
    url_daily_raw = url_daily_q.group_by(func.date(ScanResult.timestamp))\
     .order_by(func.date(ScanResult.timestamp)).all()
    
    url_vol_map = {}
    for row in url_daily_raw:
        d_val = row[0]
        # Robust date key normalization
        if hasattr(d_val, 'strftime'):
            d_key = d_val.strftime('%Y-%m-%d')
        else:
            d_key = str(d_val).split(' ')[0]
        url_vol_map[d_key] = row[1]
    
    
    url_daily_volume = []
    for i in range(chart_days):
        d = (now - timedelta(days=chart_days - 1 - i)).date()
        url_daily_volume.append({"date": str(d), "count": url_vol_map.get(str(d), 0)})

    # URL Top Brands (on unique urls)
    top_brands_raw = db.query(
        func.lower(ScanResult.brand_name).label("brand_lower"),
        func.count(ScanResult.id)
    ).filter(ScanResult.id.in_(url_latest_ids), ScanResult.brand_name != None) \
     .group_by(func.lower(ScanResult.brand_name))\
     .order_by(func.count(ScanResult.id).desc())\
     .limit(5).all()
    top_brands = [{"brand": b[0].title(), "count": b[1]} for b in top_brands_raw]

    # Optimized TLD Aggregation (Phase 5B)
    tld_counts_raw = db.query(
        ScanResult.tld,
        func.count(ScanResult.id).label("total"),
        func.sum(
            case(
                (func.lower(ScanResult.risk_level).in_(["high", "malicious"]), 1),
                else_=0
            )
        ).label("malicious_count")
    ).filter(
        ScanResult.id.in_(url_latest_ids),
        ScanResult.tld != None
    ).group_by(ScanResult.tld).all()

    top_malicious_tlds = sorted(
        [{"tld": f".{t}", "count": int(m or 0), "malicious_pct": round((int(m or 0) / total * 100), 1) if total > 0 else 0}
         for t, total, m in tld_counts_raw if m and m > 0],
        key=lambda x: x["count"], reverse=True
    )[:5]

    # --- 2. EMAIL INTELLIGENCE DATA ---
    # Total Email Scans
    email_total_q = db.query(EmailScanResult)
    if cutoff:
        email_total_q = email_total_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        email_total_q = email_total_q.filter(EmailScanResult.client_id == x_client_id)
    email_total_scans = email_total_q.count()
    
    # Email Risk Distribution
    email_risk_q = db.query(EmailScanResult.verdict_label, func.count(EmailScanResult.id))
    if cutoff:
        email_risk_q = email_risk_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        email_risk_q = email_risk_q.filter(EmailScanResult.client_id == x_client_id)
        
    email_risk_raw = email_risk_q.group_by(EmailScanResult.verdict_label).all()
    # Normalize keys to lowercase
    email_risk_dist = {}
    for r in email_risk_raw:
        k = str(r[0] or "unknown").lower()
        email_risk_dist[k] = email_risk_dist.get(k, 0) + r[1]
    
    # Email Daily Volume
    email_daily_q = db.query(
        func.date(EmailScanResult.timestamp),
        func.count(EmailScanResult.id)
    ).filter(EmailScanResult.timestamp >= chart_cutoff)
    if x_client_id:
        email_daily_q = email_daily_q.filter(EmailScanResult.client_id == x_client_id)
        
    email_daily_raw = email_daily_q.group_by(func.date(EmailScanResult.timestamp))\
     .order_by(func.date(EmailScanResult.timestamp)).all()
    
    email_vol_map = {}
    for row in email_daily_raw:
        d_val = row[0]
        if hasattr(d_val, 'strftime'):
            d_key = d_val.strftime('%Y-%m-%d')
        else:
            d_key = str(d_val).split(' ')[0]
        email_vol_map[d_key] = row[1]
    email_daily_volume = []
    for i in range(chart_days):
        d = (now - timedelta(days=chart_days - 1 - i)).date()
        email_daily_volume.append({"date": str(d), "count": email_vol_map.get(str(d), 0)})

    # Attack Vectors
    av_q = db.query(EmailScanResult.se_categories)
    if cutoff:
        av_q = av_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        av_q = av_q.filter(EmailScanResult.client_id == x_client_id)
    
    av_results = av_q.all()
    av_counter = Counter()
    for res in av_results:
        if res[0]:
            try:
                cats = json.loads(res[0])
                av_counter.update(cats)
            except (json.JSONDecodeError, TypeError) as e:
                logger.debug(f"Skipping malformed se_categories: {e}")
                continue
            
    total_av = sum(av_counter.values())
    attack_vectors = [
        {"category": cat, "count": count, "percentage": round((count / total_av * 100), 1) if total_av > 0 else 0}
        for cat, count in av_counter.most_common(5)
    ]

    # Auth Posture
    auth_q = db.query(EmailScanResult.spf_result, EmailScanResult.dkim_result, EmailScanResult.dmarc_result)
    if cutoff:
        auth_q = auth_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        auth_q = auth_q.filter(EmailScanResult.client_id == x_client_id)
    
    auth_results = auth_q.all()
    auth_posture = {
        "spf": {"pass": 0, "fail": 0, "none": 0},
        "dkim": {"pass": 0, "fail": 0, "none": 0},
        "dmarc": {"pass": 0, "fail": 0, "none": 0}
    }
    
    for spf, dkim, dmarc in auth_results:
        spf_norm = (spf or "none").lower().strip()
        dkim_norm = (dkim or "none").lower().strip()
        dmarc_norm = (dmarc or "none").lower().strip()
        
        if spf_norm in auth_posture["spf"]: auth_posture["spf"][spf_norm] += 1
        else: auth_posture["spf"]["none"] += 1
        
        if dkim_norm in auth_posture["dkim"]: auth_posture["dkim"][dkim_norm] += 1
        else: auth_posture["dkim"]["none"] += 1
        
        if dmarc_norm in auth_posture["dmarc"]: auth_posture["dmarc"][dmarc_norm] += 1
        else: auth_posture["dmarc"]["none"] += 1

    # Obfuscation Heatmap
    ob_q = db.query(EmailScanResult.obfuscation_techniques)
    if cutoff:
        ob_q = ob_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        ob_q = ob_q.filter(EmailScanResult.client_id == x_client_id)
        
    ob_results = ob_q.all()
    ob_counter = Counter()
    for res in ob_results:
        if res[0]:
            try:
                techs = json.loads(res[0])
                ob_counter.update(techs)
            except (json.JSONDecodeError, TypeError) as e:
                logger.debug(f"Skipping malformed obfuscation_techniques: {e}")
                continue
    obfuscation_heatmap = [
        {"technique": tech, "count": count}
        for tech, count in ob_counter.most_common(10)
    ]

    # Confidence Trend
    trend_q = db.query(
        func.date(EmailScanResult.timestamp),
        EmailScanResult.analysis_quality,
        func.count(EmailScanResult.id)
    )
    if cutoff:
        trend_q = trend_q.filter(EmailScanResult.timestamp >= cutoff)
    if x_client_id:
        trend_q = trend_q.filter(EmailScanResult.client_id == x_client_id)
        
    trend_raw = trend_q.group_by(func.date(EmailScanResult.timestamp), EmailScanResult.analysis_quality).all()
    
    trend_map = {}
    for dt, qual, count in trend_raw:
        dt_str = str(dt)
        if dt_str not in trend_map:
            trend_map[dt_str] = {"date": dt_str, "high": 0, "medium": 0, "low": 0, "total": 0, "weighted_sum": 0}
        trend_map[dt_str][qual] = count
        trend_map[dt_str]["total"] += count
        weight = 1.0 if qual == "high" else 0.6 if qual == "medium" else 0.3
        trend_map[dt_str]["weighted_sum"] += (count * weight)

    confidence_trend = []
    for i in range(chart_days):
        d = (now - timedelta(days=chart_days - 1 - i)).date()
        d_str = str(d)
        if d_str in trend_map:
            day_data = trend_map[d_str]
            confidence_trend.append({
                "date": d_str,
                "avg_quality": round((day_data["weighted_sum"] / day_data["total"]) * 100, 1) if day_data["total"] > 0 else 0,
                "high": day_data["high"],
                "medium": day_data["medium"],
                "low": day_data["low"]
            })
        else:
            confidence_trend.append({"date": d_str, "avg_quality": 0, "high": 0, "medium": 0, "low": 0})

    return {
        "url": {
            "total_scans": url_total_scans,
            "risk_distribution": url_risk_dist,
            "daily_volume": url_daily_volume,
            "top_brands": top_brands,
            "top_malicious_tlds": top_malicious_tlds,
        },
        "email": {
            "total_scans": email_total_scans,
            "risk_distribution": email_risk_dist,
            "daily_volume": email_daily_volume,
            "attack_vectors": attack_vectors,
            "auth_posture": auth_posture,
            "obfuscation_heatmap": obfuscation_heatmap,
            "confidence_trend": confidence_trend,
        },
        "combined": {
            "total_scans": url_total_scans + email_total_scans,
            "last_updated": now.isoformat(),
            "filter_days": days
        },
        "top_impersonated_brands": GLOBAL_TOP_BRANDS,
        "last_updated": now.isoformat(),
        "filter_days": days
    }

@router.get("/scans")
def get_scan_list(
    db: Session = Depends(get_db),
    filter: str = Query(default="all", description="Filter: 'all', 'malicious', or 'safe'"),
    days: int = Query(default=7, ge=0, description="Time window. 0 = all time."),
    limit: int = Query(default=50, ge=1, le=100),
    x_client_id: Optional[str] = Header(None),
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Returns a filtered list of scans for the stat card drill-down.

    Args:
        db (Session): Database session.
        filter (str): Filter criteria ('all', 'malicious', 'suspicious', 'safe', 'offline').
        days (int): Time window in days.
        limit (int): Max results to return.
        x_client_id (Optional[str]): The client identifier passed via X-Client-Id header. Filters results by client.
        current_user (AuthUser): Authenticated user principal.
    """
    # Enforce authorization: verify user can access this client_id
    has_access_to_client(current_user, x_client_id)
    
    now = datetime.now(timezone.utc)
    
    # Time cutoff
    cutoff = now - timedelta(days=days) if days > 0 else None

    # Latest unique scan IDs
    sub_q = db.query(func.max(ScanResult.id)).group_by(ScanResult.url)
    if cutoff:
        sub_q = sub_q.filter(ScanResult.timestamp >= cutoff)
    if x_client_id:
        sub_q = sub_q.filter(ScanResult.client_id == x_client_id)
    latest_ids = sub_q.subquery()

    q = db.query(ScanResult).filter(ScanResult.id.in_(latest_ids))
    
    # Risk filter (Case-insensitive support for legacy and new labels)
    if filter == "malicious":
        q = q.filter(func.lower(ScanResult.risk_level).in_(["high", "malicious"]))
    elif filter == "suspicious":
        q = q.filter(func.lower(ScanResult.risk_level).in_(["medium", "suspicious"]))
    elif filter == "safe":
        q = q.filter(func.lower(ScanResult.risk_level).in_(["low", "safe"]))
    elif filter == "offline":
        q = q.filter(func.lower(ScanResult.risk_level) == "unknown")
    
    scans = q.order_by(ScanResult.timestamp.desc()).limit(limit).all()
    
    return [{
        "url": s.url,
        "risk_level": s.risk_level,
        "risk_score": s.risk_score,
        "brand_name": s.brand_name,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None
    } for s in scans]

@router.get("/email-scans")
def get_email_scan_list(
    db: Session = Depends(get_db),
    filter: str = Query(default="all", description="Filter: 'all', 'malicious', 'suspicious', or 'safe'"),
    days: int = Query(default=7, ge=0, description="Time window. 0 = all time."),
    limit: int = Query(default=50, ge=1, le=100),
    x_client_id: Optional[str] = Header(None),
    current_user: AuthUser = Depends(get_current_user)
):
    """
    Returns a filtered list of email scans for the stat card drill-down.

    Args:
        db (Session): Database session.
        filter (str): Filter criteria ('all', 'malicious', 'suspicious', 'safe').
        days (int): Time window in days.
        limit (int): Max results to return.
        x_client_id (Optional[str]): The client identifier passed via X-Client-Id header. Filters results by client.
        current_user (AuthUser): Authenticated user principal.
    """
    # Enforce authorization: verify user can access this client_id
    has_access_to_client(current_user, x_client_id)
    
    now = datetime.now(timezone.utc)
    
    q = db.query(EmailScanResult)
    
    # Time filter
    if days > 0:
        q = q.filter(EmailScanResult.timestamp >= now - timedelta(days=days))
    
    # Client filter
    if x_client_id:
        q = q.filter(EmailScanResult.client_id == x_client_id)
        
    # Risk filter
    if filter == "malicious":
        q = q.filter(EmailScanResult.verdict_label == "malicious")
    elif filter == "suspicious":
        q = q.filter(EmailScanResult.verdict_label == "suspicious")
    elif filter == "safe":
        q = q.filter(EmailScanResult.verdict_label == "safe")
    
    scans = q.order_by(EmailScanResult.timestamp.desc()).limit(limit).all()
    
    return [{
        "scan_id": s.scan_id,
        "verdict_label": s.verdict_label,
        "final_risk_score": s.final_risk_score,
        "sender_domain": s.sender_domain,
        "timestamp": s.timestamp.isoformat() if s.timestamp else None
    } for s in scans]
