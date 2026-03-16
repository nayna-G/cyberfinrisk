import numpy as np
import scipy.stats as stats
from typing import Dict, Optional

def pert(min_val: float, likely_val: float, max_val: float, confidence: float = 4, size: int = 1) -> np.ndarray:
    """
    Sample from a Beta-PERT distribution.
    
    Args:
        min_val: Minimum value
        likely_val: Most likely value
        max_val: Maximum value
        confidence: Confidence factor (default 4)
        size: Number of samples to draw
    """
    if min_val >= max_val:
        return np.full(size, min_val)
    
    if not (min_val <= likely_val <= max_val):
        # Fallback if likely is out of bounds
        likely_val = (min_val + max_val) / 2

    # Beta-PERT formula for mean and variance
    # alpha and beta parameters
    alpha = 1 + confidence * (likely_val - min_val) / (max_val - min_val)
    beta_val = 1 + confidence * (max_val - likely_val) / (max_val - min_val)
    
    # Sample from Beta distribution and scale to [min_val, max_val]
    # Handle edge case where alpha or beta is extremely small/large if ranges are tight
    try:
        beta_samples = stats.beta.rvs(alpha, beta_val, size=size)
    except Exception:
        # Fallback to uniform or point if stats fails on edge cases
        return np.full(size, likely_val)
        
    return min_val + beta_samples * (max_val - min_val)

def run_lec_simulation(
    probability: float, 
    impact_params: Dict[str, Dict[str, float]], 
    iterations: int = 10000
) -> Dict[str, float]:
    """
    Run Monte Carlo simulation for Loss Exceedance Curve.
    
    Args:
        probability: Probability of exploit (P)
        impact_params: Dictionary of cost categories and their min/likely/max ranges
                       e.g. { "data_breach": {"min": 100, "likely": 200, "max": 400}, ... }
        iterations: Number of simulation iterations
                       
    Returns:
        Dictionary with simulation statistics (mean, 10th, 50th, 90th percentiles)
    """
    # Sample costs for each category
    sampled_costs = {}
    for category, params in impact_params.items():
        min_val = params.get("min", params.get("likely", 0.0))
        likely_val = params.get("likely", 0.0)
        max_val = params.get("max", params.get("likely", 0.0))
        
        # Sample using Beta-PERT
        sampled_costs[category] = pert(min_val, likely_val, max_val, size=iterations)

    # Sum sampled costs across categories for each iteration
    total_impact_samples = np.zeros(iterations)
    for category, samples in sampled_costs.items():
         total_impact_samples += samples

    # Simulate event occurrence (Loss Event Frequency/Probability)
    # Roll a dice for each iteration based on probability
    happened = np.random.random(iterations) < probability
    
    # Calculate loss: impact if happened, else 0
    total_losses = np.where(happened, total_impact_samples, 0.0)

    # Calculate statistics
    mean_loss = np.mean(total_losses)
    p10_loss = np.percentile(total_losses, 10)
    p50_loss = np.percentile(total_losses, 50)
    p90_loss = np.percentile(total_losses, 90)
    p95_loss = np.percentile(total_losses, 95)

    return {
        "mean": round(float(mean_loss), 2),
        "p10": round(float(p10_loss), 2),
        "p50": round(float(p50_loss), 2),
        "p90": round(float(p90_loss), 2),
        "p95": round(float(p95_loss), 2)
    }
