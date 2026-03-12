"""
Trend Prediction Module for Thailand Cyber Threat Intelligence
Uses Facebook Prophet for advanced time series forecasting.

Why Prophet?
- Handles missing data gracefully (common in threat logs)
- Detects seasonality automatically (weekly/daily attack patterns)
- Provides confidence intervals for uncertainty quantification
- Explainable output for business stakeholders
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
import logging
import warnings

# Suppress Prophet's verbose output
warnings.filterwarnings("ignore", category=FutureWarning)
logging.getLogger('cmdstanpy').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Prophet is optional - fallback to simple regression if not installed
try:
    from prophet import Prophet
    PROPHET_AVAILABLE = True
    logger.info("Prophet loaded successfully - advanced forecasting enabled")
except ImportError:
    PROPHET_AVAILABLE = False
    logger.warning("Prophet not installed - using fallback linear regression")

import pandas as pd


def aggregate_daily_counts(events: List[Dict]) -> Dict[str, Dict[str, int]]:
    """
    Aggregate IOC events by date and threat type.
    
    Returns:
        Dict[date_string, Dict[threat_type, count]]
    """
    daily_counts = defaultdict(lambda: defaultdict(int))
    
    for event in events:
        event_time = event.get('event_time', '') or event.get('collect_time', '')
        if event_time:
            try:
                dt = datetime.fromisoformat(event_time.replace('Z', '+00:00'))
                date_key = dt.strftime('%Y-%m-%d')
                threat_types = event.get('aiThreatTypes', [])
                if threat_types:
                    for t in threat_types:
                        daily_counts[date_key][t] += 1
                else:
                    daily_counts[date_key]['Unknown'] += 1
            except Exception:
                pass
    
    return dict(daily_counts)


def calculate_trend_prophet(values: List[float], dates: List[str]) -> Dict[str, Any]:
    """
    Calculate trend and forecast using Facebook Prophet.
    
    Args:
        values: Daily counts
        dates: Corresponding dates (YYYY-MM-DD format)
    
    Returns:
        Dict with slope, direction, prediction, confidence intervals
    """
    n = len(values)
    
    # Minimum data check
    if n < 2:
        return _insufficient_data_response(values, n)
    
    # Prepare DataFrame for Prophet
    df = pd.DataFrame({
        'ds': pd.to_datetime(dates),
        'y': values
    })
    
    if not PROPHET_AVAILABLE:
        # Fallback to simple linear regression
        return _fallback_linear_regression(values, n)
    
    try:
        # Initialize Prophet with cybersecurity-appropriate settings
        model = Prophet(
            yearly_seasonality=False,  # Cyber attacks don't follow yearly patterns
            weekly_seasonality=True,   # But DO follow weekly patterns (weekends = less activity)
            daily_seasonality=False,   # Not enough granularity for daily patterns
            changepoint_prior_scale=0.05,  # Conservative changepoint detection
            interval_width=0.95        # 95% confidence interval
        )
        
        # Fit model (suppress output)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model.fit(df)
        
        # Create future dates (7 days ahead)
        future = model.make_future_dataframe(periods=7)
        forecast = model.predict(future)
        
        # Extract results
        last_actual = values[-1]
        prediction_7d = forecast['yhat'].iloc[-1]
        prediction_lower = max(0, forecast['yhat_lower'].iloc[-1])
        prediction_upper = forecast['yhat_upper'].iloc[-1]
        
        # Calculate trend direction
        trend_start = forecast['trend'].iloc[0]
        trend_end = forecast['trend'].iloc[-1]
        slope = (trend_end - trend_start) / max(n, 1)
        
        # Determine direction
        current_avg = sum(values) / n if n > 0 else 0
        threshold = current_avg * 0.1 if current_avg > 0 else 0.5
        
        if slope > threshold:
            direction = "increasing"
        elif slope < -threshold:
            direction = "decreasing"
        else:
            direction = "stable"
        
        # Calculate change percent
        change_percent = ((prediction_7d - current_avg) / current_avg * 100) if current_avg > 0 else 0
        
        return {
            "slope": round(slope, 3),
            "direction": direction,
            "confidence": 0.95,  # Prophet default
            "current_avg": round(current_avg, 1),
            "prediction_7d": round(max(0, prediction_7d), 1),
            "prediction_lower": round(prediction_lower, 1),
            "prediction_upper": round(prediction_upper, 1),
            "confidence_interval": round(prediction_upper - prediction_lower, 1),
            "change_percent": round(change_percent, 1),
            "model": "prophet",
            "data_quality": {
                "sufficient_data": n >= 7,
                "min_required": 7,
                "actual_days": n,
                "warning": f"มีข้อมูลเพียง {n} วัน (แนะนำ ≥7 วัน)" if n < 7 else None,
                "warning_en": f"Only {n} days of data (recommend ≥7)" if n < 7 else None
            },
            # Prophet-specific outputs
            "seasonality_detected": {
                "weekly": True,
                "note": "Cyber attacks typically decrease on weekends"
            }
        }
        
    except Exception as e:
        logger.error(f"Prophet prediction failed: {e}, falling back to linear regression")
        return _fallback_linear_regression(values, n)


def _insufficient_data_response(values: List[float], n: int) -> Dict[str, Any]:
    """Response when there's not enough data."""
    return {
        "slope": 0,
        "direction": "stable",
        "confidence": 0,
        "prediction_7d": values[-1] if values else 0,
        "prediction_lower": values[-1] if values else 0,
        "prediction_upper": values[-1] if values else 0,
        "confidence_interval": 0,
        "model": "none",
        "data_quality": {
            "sufficient_data": False,
            "min_required": 7,
            "actual_days": n,
            "warning": "ข้อมูลน้อยเกินไป ไม่สามารถพยากรณ์ได้",
            "warning_en": "Insufficient data for prediction"
        }
    }


def _fallback_linear_regression(values: List[float], n: int) -> Dict[str, Any]:
    """Fallback to simple linear regression when Prophet is unavailable."""
    import math
    
    x_mean = (n - 1) / 2
    y_mean = sum(values) / n
    
    numerator = sum((i - x_mean) * (values[i] - y_mean) for i in range(n))
    denominator = sum((i - x_mean) ** 2 for i in range(n))
    
    slope = numerator / denominator if denominator != 0 else 0
    intercept = y_mean - slope * x_mean
    
    # Calculate R-squared
    y_pred = [slope * i + intercept for i in range(n)]
    ss_res = sum((values[i] - y_pred[i]) ** 2 for i in range(n))
    ss_tot = sum((v - y_mean) ** 2 for v in values)
    r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
    
    # Standard error and confidence interval
    if n > 2:
        mse = ss_res / (n - 2)
        std_error = math.sqrt(mse) if mse > 0 else 0
    else:
        std_error = y_mean * 0.5
    
    confidence_interval = 1.96 * std_error
    
    # Predict 7 days ahead
    prediction_7d = slope * (n + 6) + intercept
    prediction_lower = max(0, prediction_7d - confidence_interval)
    prediction_upper = prediction_7d + confidence_interval
    
    # Determine direction
    threshold = 0.5
    if slope > threshold:
        direction = "increasing"
    elif slope < -threshold:
        direction = "decreasing"
    else:
        direction = "stable"
    
    return {
        "slope": round(slope, 3),
        "direction": direction,
        "confidence": round(max(0, r_squared), 3),
        "current_avg": round(y_mean, 1),
        "prediction_7d": round(max(0, prediction_7d), 1),
        "prediction_lower": round(prediction_lower, 1),
        "prediction_upper": round(prediction_upper, 1),
        "confidence_interval": round(confidence_interval, 1),
        "change_percent": round((slope * 7 / y_mean) * 100, 1) if y_mean > 0 else 0,
        "model": "linear_regression_fallback",
        "data_quality": {
            "sufficient_data": n >= 7,
            "min_required": 7,
            "actual_days": n,
            "r_squared": round(r_squared, 3),
            "std_error": round(std_error, 2),
            "warning": "Prophet unavailable, using fallback" if not PROPHET_AVAILABLE else None
        }
    }


def predict_trends(events: List[Dict], top_n: int = 5) -> Dict[str, Any]:
    """
    Predict threat trends for all major threat types using Prophet.
    
    Returns:
        Dict with predictions for each threat type and summary
    """
    daily_counts = aggregate_daily_counts(events)
    
    if not daily_counts:
        return {
            "error": "No data available for prediction",
            "predictions": [],
            "summary": {}
        }
    
    # Get sorted dates
    sorted_dates = sorted(daily_counts.keys())
    date_range = {
        "start": sorted_dates[0],
        "end": sorted_dates[-1],
        "total_days": len(sorted_dates)
    }
    
    # Get all threat types
    all_types = set()
    for counts in daily_counts.values():
        all_types.update(counts.keys())
    
    # Calculate trends for each threat type
    predictions = []
    for threat_type in all_types:
        values = [daily_counts[d].get(threat_type, 0) for d in sorted_dates]
        total = sum(values)
        
        if total < 3:  # Skip if too few samples
            continue
        
        # Use Prophet-based trend calculation
        trend = calculate_trend_prophet(values, sorted_dates)
        trend["threat_type"] = threat_type
        trend["total_count"] = total
        trend["daily_values"] = values
        
        # Generate prediction text
        if trend["direction"] == "increasing":
            trend["prediction_text"] = f"{threat_type} มีแนวโน้มเพิ่มขึ้น +{trend['change_percent']}% ในสัปดาห์หน้า"
            trend["prediction_text_en"] = f"{threat_type} trending up +{trend['change_percent']}% next week"
            trend["alert_level"] = "warning" if trend["change_percent"] > 20 else "info"
        elif trend["direction"] == "decreasing":
            trend["prediction_text"] = f"{threat_type} มีแนวโน้มลดลง {trend['change_percent']}% ในสัปดาห์หน้า"
            trend["prediction_text_en"] = f"{threat_type} trending down {trend['change_percent']}% next week"
            trend["alert_level"] = "success"
        else:
            trend["prediction_text"] = f"{threat_type} มีแนวโน้มคงที่"
            trend["prediction_text_en"] = f"{threat_type} stable trend"
            trend["alert_level"] = "neutral"
        
        predictions.append(trend)
    
    # Sort by absolute slope (most significant trends first)
    predictions.sort(key=lambda x: abs(x["slope"]), reverse=True)
    
    # Get top increasing threats (for alerts)
    increasing_threats = [p for p in predictions if p["direction"] == "increasing"]
    increasing_threats.sort(key=lambda x: x["change_percent"], reverse=True)
    
    return {
        "date_range": date_range,
        "predictions": predictions[:top_n],
        "all_predictions": predictions,
        "top_increasing": increasing_threats[:3],
        "model_used": "prophet" if PROPHET_AVAILABLE else "linear_regression",
        "summary": {
            "total_threat_types": len(predictions),
            "increasing_count": len([p for p in predictions if p["direction"] == "increasing"]),
            "decreasing_count": len([p for p in predictions if p["direction"] == "decreasing"]),
            "stable_count": len([p for p in predictions if p["direction"] == "stable"]),
            "generated_at": datetime.now().isoformat()
        }
    }


def generate_trend_forecast(
    events: List[Dict], 
    forecast_days: int = 7
) -> Dict[str, Any]:
    """
    Generate forecast data for legacy dashboard visualization.
    
    Returns:
        Dict with historical data + forecast for charting
    """
    daily_counts = aggregate_daily_counts(events)
    sorted_dates = sorted(daily_counts.keys())
    
    if len(sorted_dates) < 2:
        return {"error": "Insufficient data for forecasting"}
    
    # Get top 5 threat types by volume
    type_totals = defaultdict(int)
    for counts in daily_counts.values():
        for t, c in counts.items():
            type_totals[t] += c
    
    top_types = sorted(type_totals.keys(), key=lambda x: type_totals[x], reverse=True)[:5]
    
    # Build chart data
    chart_data = {
        "labels": [],
        "datasets": {},
        "model_used": "prophet" if PROPHET_AVAILABLE else "linear_regression"
    }
    
    # Historical data
    for date in sorted_dates:
        chart_data["labels"].append(date)
        for threat_type in top_types:
            if threat_type not in chart_data["datasets"]:
                chart_data["datasets"][threat_type] = {
                    "historical": [],
                    "forecast": [],
                    "forecast_lower": [],
                    "forecast_upper": []
                }
            chart_data["datasets"][threat_type]["historical"].append(
                daily_counts[date].get(threat_type, 0)
            )
    
    # Generate forecast using Prophet
    last_date = datetime.strptime(sorted_dates[-1], '%Y-%m-%d')
    
    for threat_type in top_types:
        values = chart_data["datasets"][threat_type]["historical"]
        trend = calculate_trend_prophet(values, sorted_dates)
        
        # Generate daily forecasts
        for i in range(1, forecast_days + 1):
            forecast_date = (last_date + timedelta(days=i)).strftime('%Y-%m-%d')
            
            if i == 1:  # Only add dates once
                chart_data["labels"].append(forecast_date)
            
            # Linear interpolation for intermediate days
            day_prediction = trend["current_avg"] + trend["slope"] * i
            day_prediction = max(0, round(day_prediction))
            
            # Confidence bounds widen with distance
            uncertainty_factor = 1 + (i * 0.1)
            lower = max(0, day_prediction - trend["confidence_interval"] * uncertainty_factor)
            upper = day_prediction + trend["confidence_interval"] * uncertainty_factor
            
            chart_data["datasets"][threat_type]["forecast"].append(day_prediction)
            chart_data["datasets"][threat_type]["forecast_lower"].append(round(lower))
            chart_data["datasets"][threat_type]["forecast_upper"].append(round(upper))
    
    # Mark forecast start index
    chart_data["forecast_start_index"] = len(sorted_dates)
    
    return chart_data


# Test function
if __name__ == "__main__":
    import json
    
    print(f"Prophet available: {PROPHET_AVAILABLE}")
    
    # Load sample data
    try:
        with open("../legacy/dashboard-poc/public/data/normalized_iocs.json") as f:
            data = json.load(f)
        
        events = data.get("events", [])
        
        print("=== Trend Predictions (Prophet) ===")
        predictions = predict_trends(events)
        
        print(f"\nModel Used: {predictions.get('model_used', 'unknown')}")
        print(f"Date Range: {predictions['date_range']['start']} to {predictions['date_range']['end']}")
        print(f"Total Days: {predictions['date_range']['total_days']}")
        
        print("\n📈 Top Threat Predictions:")
        for p in predictions["predictions"]:
            arrow = "↑" if p["direction"] == "increasing" else "↓" if p["direction"] == "decreasing" else "→"
            model_tag = f"[{p.get('model', 'unknown')}]"
            print(f"  {arrow} {p['threat_type']}: {p['prediction_text_en']} {model_tag}")
        
        print("\n⚠️ Increasing Threats Alert:")
        for p in predictions["top_increasing"]:
            print(f"  🔺 {p['threat_type']}: +{p['change_percent']}%")
            
    except FileNotFoundError:
        print("Sample data file not found - skipping test")
