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

    if n < 2 * season_length:
        return seasonal_average(values, horizon, season_length)

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
