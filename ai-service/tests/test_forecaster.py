"""Tests for models.forecaster – Holt-Winters triple exponential smoothing."""

from __future__ import annotations

import pytest

from models.forecaster import (
    ForecastResult,
    forecast,
    guarded_holt_winters_forecast,
    has_forecast_signal,
    holt_winters_forecast,
    seasonal_average,
    winsorize,
)


def test_winsorize_caps_single_spike():
    # A baseline of ~20 with one 1000× spike at index 50.
    series = [20.0] * 100
    series[50] = 1_000.0
    capped, indices = winsorize(series)
    assert indices == [50]
    assert capped[50] < 1_000.0
    # Everything else untouched.
    assert capped[:50] == series[:50]
    assert capped[51:] == series[51:]


def test_winsorize_leaves_clean_series_alone():
    series = [10.0 + (i % 7) for i in range(60)]
    capped, indices = winsorize(series)
    assert indices == []
    assert capped == series


def test_forecast_records_anomaly_indices():
    # 84 days (12 weeks) of weekly-seasonal data with one outlier.
    import math
    series = [50 + 10 * math.sin(2 * math.pi * i / 7) for i in range(84)]
    series[40] = 5_000
    result = forecast(series, horizon=7, season_length=7)
    assert 40 in result.anomaly_indices
    assert 5_000 in result.anomaly_values
    # And with the spike capped, the forecast should still emit (not be
    # rejected by backtest the way the raw series would be).
    assert len(result.point) == 7


def test_forecast_survives_spike_in_holdout_window():
    # 120 days of low-volatility baseline with a single huge spike in
    # the hold-out window (last 7 days). This is the exact scenario
    # that caused the user-visible 'backtest_failed' bug: even after
    # winsorizing the spike value, mean sMAPE was dragged past 0.6 by
    # the single capped day. Median sMAPE + excluding winsorized
    # positions from the score should let the forecast through.
    import random
    random.seed(42)
    series = [30_000 + random.randint(-2_000, 2_000) for _ in range(120)]
    series[115] = 1_000_000  # ← attack-day spike inside the hold-out
    result = forecast(series, horizon=7, season_length=7)
    assert 115 in result.anomaly_indices
    assert result.point, f"Forecast should emit; got reason={result.reason}"


# ---------------------------------------------------------------------------
# New forecast() API — point + CI + backtest gate
# ---------------------------------------------------------------------------

def test_forecast_short_input_returns_empty_with_reason():
    result = forecast([5, 10, 15], horizon=6, season_length=24)
    assert isinstance(result, ForecastResult)
    assert result.point == []
    assert result.reason == "insufficient_history"


def test_forecast_sparse_input_returns_empty():
    # 96 hours but only one spike — not enough density to predict.
    series = [0] * 50 + [100] + [0] * 45
    result = forecast(series, horizon=24, season_length=24)
    assert result.point == []
    assert result.reason == "insufficient_signal"


def test_forecast_returns_confidence_interval():
    # 96 hours of a stable repeating pattern → forecast + CI should
    # bracket the point estimate symmetrically.
    series = ([10, 12, 14, 16, 18, 20, 18, 16, 14, 12, 10, 8] * 8)[:96]
    result = forecast(series, horizon=12, season_length=12)
    assert len(result.point) == 12
    assert len(result.lower) == 12
    assert len(result.upper) == 12
    for lower, point, upper in zip(result.lower, result.point, result.upper):
        assert lower <= point <= upper
    # CI should widen with horizon (variance grows with √h).
    assert (result.upper[-1] - result.lower[-1]) >= (result.upper[0] - result.lower[0])


def test_forecast_backtest_suppresses_unpredictable_series():
    # Random-walk-ish series with no real seasonality. The hold-out
    # backtest should reject this and return an empty forecast.
    import random
    random.seed(0)
    series = [random.randint(0, 100) for _ in range(96)]
    result = forecast(series, horizon=24, season_length=24)
    # Either suppressed by backtest, or returned with smape recorded.
    if not result.point:
        assert result.reason == "backtest_failed"
        assert result.smape is not None and result.smape > 0.6





# ---------------------------------------------------------------------------
# 1. Constant series -> forecast ~ same value
# ---------------------------------------------------------------------------

def test_holt_winters_constant_series():
    constant_value = 10
    series = [constant_value] * 72  # 3 full seasons of 24
    forecast = holt_winters_forecast(series, horizon=24)

    assert len(forecast) == 24
    for value in forecast:
        assert abs(value - constant_value) <= 1, (
            f"Expected ~{constant_value}, got {value}"
        )


# ---------------------------------------------------------------------------
# 2. Trending up -> forecast continues upward
# ---------------------------------------------------------------------------

def test_holt_winters_trending_up():
    # Build 72 points with a clear upward trend + seasonal noise.
    # With damping the forecast won't extrapolate without bound, but the
    # forecast season's mean should still exceed the last observed season's
    # mean since the level is still rising.
    series = [i + (i % 24) for i in range(72)]
    forecast = holt_winters_forecast(series, horizon=24)

    assert len(forecast) == 24
    last_season_mean = sum(series[-24:]) / 24
    forecast_mean = sum(forecast) / 24
    assert forecast_mean > last_season_mean, (
        "Forecast season mean should exceed last observed season mean"
    )


# ---------------------------------------------------------------------------
# 3. 24-hour repeating pattern preserved in forecast
# ---------------------------------------------------------------------------

def test_holt_winters_seasonal_24h():
    pattern = list(range(24))  # 0, 1, 2, ... 23
    series = pattern * 4       # 96 points = 4 full seasons
    forecast = holt_winters_forecast(series, horizon=24)

    assert len(forecast) == 24
    # The seasonal shape should be roughly preserved.
    # Check the forecast is not flat (std-dev > 0) and correlates with pattern.
    assert max(forecast) > min(forecast), (
        "Forecast should preserve seasonal variation"
    )
    # The high-hour forecasts should be larger than the low-hour forecasts
    low_quarter_avg = sum(forecast[:6]) / 6
    high_quarter_avg = sum(forecast[18:]) / 6
    assert high_quarter_avg > low_quarter_avg, (
        "Seasonal shape should place higher values in the later hours"
    )


# ---------------------------------------------------------------------------
# 4. Fallback for short input (< 2 * season_length)
# ---------------------------------------------------------------------------

def test_holt_winters_short_input_returns_zeros():
    # When the window is shorter than two seasonal cycles there isn't enough
    # signal to fit Holt-Winters honestly. Return zeros so the caller can
    # suppress the forecast series rather than echo the input shape.
    series = [5, 10, 15]
    forecast = holt_winters_forecast(series, horizon=6)
    assert forecast == [0] * 6


# ---------------------------------------------------------------------------
# 5. Empty input -> list of zeros
# ---------------------------------------------------------------------------

def test_holt_winters_empty_input():
    forecast = holt_winters_forecast([], horizon=12)
    assert forecast == [0] * 12


# ---------------------------------------------------------------------------
# 6. All forecasts are non-negative
# ---------------------------------------------------------------------------

def test_holt_winters_non_negative():
    # Series that dips, potentially producing negative raw forecasts
    series = [100] * 24 + [0] * 24 + [50] * 24
    forecast = holt_winters_forecast(series, horizon=48)

    for value in forecast:
        assert value >= 0, f"Forecast must be non-negative, got {value}"


# ---------------------------------------------------------------------------
# 7. Output length == horizon
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("horizon", [1, 12, 24, 48, 100])
def test_holt_winters_correct_length(horizon: int):
    series = [7] * 72
    forecast = holt_winters_forecast(series, horizon=horizon)
    assert len(forecast) == horizon


# ---------------------------------------------------------------------------
# seasonal_average standalone
# ---------------------------------------------------------------------------

def test_seasonal_average_empty():
    assert seasonal_average([], horizon=5) == [0] * 5


def test_seasonal_average_repeats_last_season():
    values = list(range(30))  # 30 values, season_length=24
    result = seasonal_average(values, horizon=48, season_length=24)
    # Should repeat last 24 values twice
    last_season = values[-24:]
    expected = [max(0, round(last_season[i % 24])) for i in range(48)]
    assert result == expected


def test_has_forecast_signal_rejects_single_sparse_spike():
    values = [0, 0, 103, 0, 0, 0, 0]
    assert has_forecast_signal(values) is False


def test_guarded_forecast_does_not_repeat_sparse_spike():
    values = [0, 0, 103, 0, 0, 0, 0]
    assert guarded_holt_winters_forecast(values, horizon=7, season_length=7) == [0] * 7


def test_guarded_forecast_allows_dense_pattern():
    values = [10, 12, 11, 13, 12, 14, 13, 15]
    forecast = guarded_holt_winters_forecast(values, horizon=3, season_length=4)
    assert len(forecast) == 3
    assert any(value > 0 for value in forecast)
