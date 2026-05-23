"""
Holt-Winters Triple Exponential Smoothing (Additive)

Forecasts cybersecurity event volume with daily seasonality (24-hour cycle).
Used by the dashboard for attack volume trend prediction.

Design reference: 04Trend-Prediction specification.
"""

from __future__ import annotations


def seasonal_average(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
) -> list[int]:
    """Fallback: repeat last season's pattern."""
    if not values:
        return [0 for _ in range(horizon)]
    season = values[-season_length:] if len(values) >= season_length else values
    return [max(0, round(season[index % len(season)])) for index in range(horizon)]


def holt_linear_forecast(
    values: list[int | float],
    horizon: int,
    alpha: float = 0.5,
    beta: float = 0.2,
    damping: float = 0.9,
) -> list[int]:
    """
    Holt's double exponential smoothing (level + damped trend, no seasonality).

    Used when the historical window is too short to fit a full seasonal model
    (n < 2 * season_length). Damping (phi) keeps the trend from extrapolating
    a single spike into an unbounded ramp.
    """
    if not values:
        return [0 for _ in range(horizon)]
    if len(values) == 1:
        return [max(0, round(values[0])) for _ in range(horizon)]

    level = float(values[0])
    trend = float(values[1]) - float(values[0])
    for i in range(1, len(values)):
        value = float(values[i])
        level_new = alpha * value + (1 - alpha) * (level + damping * trend)
        trend_new = beta * (level_new - level) + (1 - beta) * damping * trend
        level = level_new
        trend = trend_new

    result: list[int] = []
    damped_sum = 0.0
    factor = 1.0
    for _ in range(horizon):
        factor *= damping
        damped_sum += factor
        result.append(max(0, round(level + damped_sum * trend)))
    return result


def holt_winters_forecast(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
    alpha: float = 0.3,
    beta: float = 0.1,
    gamma: float = 0.3,
) -> list[int]:
    """
    Additive Holt-Winters triple exponential smoothing.

    Parameters
    ----------
    values : list of numeric
        Observed time-series values (e.g. hourly event counts).
    horizon : int
        Number of future periods to forecast.
    season_length : int
        Length of one seasonal cycle (default 24 for hourly data).
    alpha : float
        Level smoothing factor (0 < alpha < 1).
    beta : float
        Trend smoothing factor (0 < beta < 1).
    gamma : float
        Seasonal smoothing factor (0 < gamma < 1).

    Returns
    -------
    list[int]
        Non-negative integer forecasts of length *horizon*.
    """
    if not values:
        return [0 for _ in range(horizon)]

    n = len(values)

    # Full Holt-Winters needs at least two complete seasonal cycles to fit
    # level + trend + seasonal components. With less data, drop seasonality
    # and fall back to Holt's damped linear trend instead of repeating the
    # last season verbatim (which produced an exact copy of the historical
    # shape as the "forecast").
    if n < 2 * season_length:
        return holt_linear_forecast(values, horizon)

    # --- Initialisation ---
    first_season = values[:season_length]
    second_season = values[season_length: 2 * season_length]

    level = sum(first_season) / season_length
    trend = (sum(second_season) / season_length - level) / season_length
    seasonal = [value - level for value in first_season]

    # --- Smoothing pass (from second season onward) ---
    for i in range(season_length, n):
        season_index = i % season_length
        value = values[i]

        level_new = (
            alpha * (value - seasonal[season_index])
            + (1 - alpha) * (level + trend)
        )
        trend_new = beta * (level_new - level) + (1 - beta) * trend
        seasonal[season_index] = (
            gamma * (value - level_new)
            + (1 - gamma) * seasonal[season_index]
        )

        level = level_new
        trend = trend_new

    # --- Forecasting ---
    result: list[int] = []
    for h in range(1, horizon + 1):
        forecast_value = level + h * trend + seasonal[(n + h) % season_length]
        result.append(max(0, round(forecast_value)))

    return result


def has_forecast_signal(
    values: list[int | float],
    *,
    min_non_zero_points: int = 3,
    min_non_zero_ratio: float = 0.25,
) -> bool:
    """
    Return whether a series has enough signal to forecast without repeating
    isolated import spikes as if they were a real trend.
    """
    if not values:
        return False

    non_zero_points = sum(1 for value in values if value > 0)
    if non_zero_points < min_non_zero_points:
        return False

    return (non_zero_points / len(values)) >= min_non_zero_ratio


def guarded_holt_winters_forecast(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
    *,
    min_non_zero_points: int = 3,
    min_non_zero_ratio: float = 0.25,
) -> list[int]:
    """
    Forecast only when historical data is dense enough to support a trend.

    Sparse cybersecurity feeds often contain one-off backfill spikes. Plain
    seasonal fallback repeats those spikes and creates misleading future peaks,
    so sparse input is treated as a zero forecast.
    """
    if not has_forecast_signal(
        values,
        min_non_zero_points=min_non_zero_points,
        min_non_zero_ratio=min_non_zero_ratio,
    ):
        return [0 for _ in range(horizon)]

    return holt_winters_forecast(values, horizon, season_length=season_length)
