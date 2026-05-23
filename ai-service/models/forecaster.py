"""
Holt-Winters Triple Exponential Smoothing (Additive, Damped Trend).

Used by the dashboard's Attack Volume Trend chart. Implements the full
spec from 04Trend-Prediction with the following correctness additions
beyond a textbook implementation:

  1. Damped trend (Gardner-McKenzie) — prevents the linear trend from
     extrapolating without bound at long forecast horizons.
  2. Auto-tuning of (alpha, beta, gamma, phi) via grid search that
     minimises in-sample SSE — removes the arbitrary hand-picked
     smoothing constants the previous version used.
  3. Hold-out backtest gate — refits on the first n - season_length
     observations, predicts the held-out season, and computes sMAPE.
     If the model can't predict the recent past, we don't claim it can
     predict the future: the forecast is suppressed instead of shown.
  4. Residual-based 80% prediction interval — gives the chart an
     uncertainty band instead of a single misleading line.

Dependency-free (pure Python + math). statsmodels would replace this
file in 30 lines but adds ~50 MB to the deploy image and pulls pandas.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


@dataclass
class ForecastResult:
    """Output of a Holt-Winters fit + forecast."""

    point: list[int] = field(default_factory=list)
    lower: list[int] = field(default_factory=list)   # 80% CI lower bound
    upper: list[int] = field(default_factory=list)   # 80% CI upper bound
    smape: float | None = None                        # backtest error, if run
    params: tuple[float, float, float, float] | None = None  # α, β, γ, φ
    reason: str | None = None                         # why empty, if empty
    anomaly_indices: list[int] = field(default_factory=list)  # winsorized positions
    anomaly_values: list[float] = field(default_factory=list)  # original values at those positions


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _fit(
    values: list[float],
    season_length: int,
    alpha: float,
    beta: float,
    gamma: float,
    phi: float,
) -> tuple[float, float, list[float], list[float]]:
    """
    Fit damped-trend additive Holt-Winters.

    Returns (level, trend, seasonal_array, in_sample_residuals).
    Residuals are 1-step-ahead in-sample forecast errors collected after
    the initialisation window.
    """
    n = len(values)
    first = values[:season_length]
    second = values[season_length: 2 * season_length]

    level = sum(first) / season_length
    trend = (sum(second) / season_length - level) / season_length
    seasonal = [value - level for value in first]
    residuals: list[float] = []

    for i in range(season_length, n):
        season_index = i % season_length
        value = values[i]
        # 1-step-ahead prediction using last state (before this obs).
        prediction = level + phi * trend + seasonal[season_index]
        residuals.append(value - prediction)

        level_new = alpha * (value - seasonal[season_index]) + (1 - alpha) * (level + phi * trend)
        trend_new = beta * (level_new - level) + (1 - beta) * phi * trend
        seasonal[season_index] = (
            gamma * (value - level_new) + (1 - gamma) * seasonal[season_index]
        )
        level = level_new
        trend = trend_new

    return level, trend, seasonal, residuals


def _project(
    level: float,
    trend: float,
    seasonal: list[float],
    n_observed: int,
    horizon: int,
    season_length: int,
    phi: float,
) -> list[float]:
    """
    Generate `horizon` future point forecasts from a fitted state.

    Damped trend sum: ŷ_{t+h} = level + (φ + φ² + … + φʰ)·trend + seasonal.
    With φ=1 this reduces to plain linear extrapolation; with φ<1 the
    trend contribution converges, capping unbounded growth.
    """
    forecasts: list[float] = []
    damped_sum = 0.0
    factor = 1.0
    for h in range(1, horizon + 1):
        factor *= phi
        damped_sum += factor
        season_index = (n_observed + h - 1) % season_length
        forecasts.append(level + damped_sum * trend + seasonal[season_index])
    return forecasts


# Small but sufficient grid. Combinations: 4 × 4 × 4 × 4 = 256 fits.
_SMOOTHING_GRID = (0.1, 0.3, 0.5, 0.8)
_DAMPING_GRID = (0.85, 0.92, 0.98, 1.0)


def _tune(values: list[float], season_length: int) -> tuple[float, float, float, float]:
    """
    Grid-search the four smoothing parameters minimising in-sample SSE.

    Cheaper than statsmodels' MLE optimiser and good enough for chart
    forecasts. Returns (alpha, beta, gamma, phi).
    """
    best_sse = float("inf")
    best = (0.3, 0.1, 0.3, 0.95)
    for alpha in _SMOOTHING_GRID:
        for beta in _SMOOTHING_GRID:
            for gamma in _SMOOTHING_GRID:
                for phi in _DAMPING_GRID:
                    _, _, _, residuals = _fit(values, season_length, alpha, beta, gamma, phi)
                    sse = sum(residual * residual for residual in residuals)
                    if sse < best_sse:
                        best_sse = sse
                        best = (alpha, beta, gamma, phi)
    return best


def _median(values: list[float]) -> float:
    sorted_values = sorted(values)
    n = len(sorted_values)
    mid = n // 2
    if n % 2:
        return sorted_values[mid]
    return (sorted_values[mid - 1] + sorted_values[mid]) / 2.0


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    rank = (pct / 100.0) * (len(sorted_values) - 1)
    low = int(rank)
    high = min(low + 1, len(sorted_values) - 1)
    weight = rank - low
    return sorted_values[low] * (1 - weight) + sorted_values[high] * weight


def winsorize(
    values: list[float],
    *,
    multiplier: float = 4.0,
) -> tuple[list[float], list[int]]:
    """
    Cap outlier spikes using a percentile-based upper bound.

    We use percentiles instead of mean ± std (not robust to outliers)
    and instead of pure MAD (degenerates to zero when most values are
    identical, which happens for sparse cybersecurity feeds). The
    bound is `p95 + multiplier × (p95 − p50)`: this scales with the
    natural spread of the data and reliably catches the single
    50× attack-day spike that would otherwise wreck Holt-Winters.

    Only the upper side is capped — low values (a quiet hour) are
    normal. The series length and ordering are preserved.

    Returns (capped_series, indices_of_capped_values).
    """
    if len(values) < 4:
        return list(values), []

    sorted_values = sorted(values)
    p50 = _percentile(sorted_values, 50)
    p95 = _percentile(sorted_values, 95)
    spread = p95 - p50
    if spread <= 0:
        # Flat or nearly-flat data; fall back to a multiple of p95 to
        # still flag a lone spike in an otherwise constant series.
        upper_bound = p95 * (1 + multiplier) if p95 > 0 else 0.0
        if upper_bound <= 0:
            return list(values), []
    else:
        upper_bound = p95 + multiplier * spread

    capped: list[float] = []
    anomaly_indices: list[int] = []
    for index, value in enumerate(values):
        if value > upper_bound:
            capped.append(upper_bound)
            anomaly_indices.append(index)
        else:
            capped.append(value)
    return capped, anomaly_indices


def _smape(
    actual: list[float],
    predicted: list[float],
    *,
    exclude_indices: set[int] | None = None,
) -> float:
    """
    Symmetric median absolute percentage error.

    Uses median instead of mean so a single outlier day in the hold-out
    window (e.g. a capped attack-volume spike) can't single-handedly
    drag the score past the gate. Also supports excluding specified
    indices — the caller passes positions that were winsorized in the
    full series so the model isn't penalised for failing to predict
    values it was explicitly told to ignore.
    """
    errors: list[float] = []
    exclude = exclude_indices or set()
    for index, (a, p) in enumerate(zip(actual, predicted)):
        if index in exclude:
            continue
        if (abs(a) + abs(p)) == 0:
            continue
        errors.append(abs(p - a) / ((abs(a) + abs(p)) / 2.0))
    if not errors:
        return 0.0
    return _median(errors)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# z-score for an 80% prediction interval (two-sided).
_Z_80 = 1.2816

# Minimum density of non-zero observations to attempt a forecast.
_MIN_NONZERO_POINTS = 3
_MIN_NONZERO_RATIO = 0.25

# sMAPE above this on the hold-out → the model is not predictive enough,
# suppress the forecast rather than render a wrong dashed line.
_SMAPE_SUPPRESSION_THRESHOLD = 0.6


def has_forecast_signal(
    values: list[int | float],
    *,
    min_non_zero_points: int = _MIN_NONZERO_POINTS,
    min_non_zero_ratio: float = _MIN_NONZERO_RATIO,
) -> bool:
    """Whether a series is dense enough to bother forecasting."""
    if not values:
        return False
    non_zero = sum(1 for value in values if value > 0)
    if non_zero < min_non_zero_points:
        return False
    return (non_zero / len(values)) >= min_non_zero_ratio


def forecast(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
    *,
    smape_threshold: float = _SMAPE_SUPPRESSION_THRESHOLD,
) -> ForecastResult:
    """
    Produce a damped Holt-Winters forecast with an 80% prediction interval.

    Returns an empty ForecastResult (with a reason populated) when the
    input is too short, too sparse, or the backtest indicates the model
    can't actually predict this series. The caller should treat an empty
    result as "do not render a forecast series".
    """
    if not values:
        return ForecastResult(reason="empty_input")
    if not has_forecast_signal(values):
        return ForecastResult(reason="insufficient_signal")
    if len(values) < 2 * season_length:
        return ForecastResult(reason="insufficient_history")

    raw = [float(value) for value in values]
    n = len(raw)

    # Winsorize before fitting. Outlier spikes (a single attack day with
    # 50× normal traffic) destroy Holt-Winters' level and trend updates
    # and blow up the backtest. We cap them for the *model* only — the
    # historical chart still shows the raw values; the anomaly indices
    # are returned so the UI can label what was excluded.
    series, anomaly_indices = winsorize(raw)
    anomaly_values = [raw[i] for i in anomaly_indices]

    # --- Backtest gate ------------------------------------------------------
    # Backtest uses the winsorized series. We additionally exclude any
    # day in the hold-out that WAS winsorized: the model was told to
    # ignore that spike, so penalising it for missing the capped value
    # would just re-introduce the bug winsorize is supposed to prevent.
    smape: float | None = None
    if n >= 3 * season_length:
        train = series[: n - season_length]
        test = series[n - season_length:]
        # Convert global anomaly positions into test-relative positions.
        test_offset = n - season_length
        excluded = {
            index - test_offset
            for index in anomaly_indices
            if index >= test_offset
        }
        tuned = _tune(train, season_length)
        level, trend, seasonal, _ = _fit(train, season_length, *tuned)
        backtest_pred = _project(
            level, trend, seasonal, len(train), season_length, season_length, tuned[3]
        )
        smape = _smape(test, backtest_pred, exclude_indices=excluded)
        if smape > smape_threshold:
            return ForecastResult(
                smape=smape,
                reason="backtest_failed",
                anomaly_indices=anomaly_indices,
                anomaly_values=anomaly_values,
            )

    # --- Fit on full (winsorized) history ----------------------------------
    alpha, beta, gamma, phi = _tune(series, season_length)
    level, trend, seasonal, residuals = _fit(series, season_length, alpha, beta, gamma, phi)
    point = _project(level, trend, seasonal, n, horizon, season_length, phi)

    # --- 80% prediction interval -------------------------------------------
    # σ̂ from in-sample residuals; multi-step variance grows ~√h for a
    # damped linear-trend model. Not the analytic HW PI (which requires
    # the state-space form), but a defensible approximation.
    if residuals:
        sigma = math.sqrt(sum(r * r for r in residuals) / len(residuals))
    else:
        sigma = 0.0

    point_int = [max(0, int(round(value))) for value in point]
    lower = [
        max(0, int(round(value - _Z_80 * sigma * math.sqrt(h))))
        for h, value in enumerate(point, start=1)
    ]
    upper = [
        max(0, int(round(value + _Z_80 * sigma * math.sqrt(h))))
        for h, value in enumerate(point, start=1)
    ]

    return ForecastResult(
        point=point_int,
        lower=lower,
        upper=upper,
        smape=smape,
        params=(alpha, beta, gamma, phi),
        anomaly_indices=anomaly_indices,
        anomaly_values=anomaly_values,
    )


# ---------------------------------------------------------------------------
# Back-compat shims
# ---------------------------------------------------------------------------
# Old callers expect plain lists. Keep these so the dashboard router can
# migrate piecewise. New code should call forecast() directly to get the
# confidence interval too.


def holt_winters_forecast(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
) -> list[int]:
    """Back-compat: point forecast only. Returns zeros on suppression."""
    result = forecast(values, horizon, season_length)
    if not result.point:
        return [0 for _ in range(horizon)]
    return result.point


def guarded_holt_winters_forecast(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
    **_unused_kwargs,
) -> list[int]:
    """
    Back-compat: the new forecast() already includes signal + backtest
    guards, so this is just an alias for the point-only path.
    """
    return holt_winters_forecast(values, horizon, season_length)


def seasonal_average(
    values: list[int | float],
    horizon: int,
    season_length: int = 24,
) -> list[int]:
    """
    Back-compat for tests. Repeats the last observed season — not used by
    the live forecast pipeline (it produced the duplicate-shape bug); kept
    only so historical seasonal_average tests still pass.
    """
    if not values:
        return [0 for _ in range(horizon)]
    season = values[-season_length:] if len(values) >= season_length else values
    return [max(0, round(season[index % len(season)])) for index in range(horizon)]
