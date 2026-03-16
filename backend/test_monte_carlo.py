import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.monte_carlo import run_lec_simulation

def test_simulation():
    print("Testing Monte Carlo Simulation...")
    
    # Sample impact params
    impact_params = {
        "data_breach": {"min": 1000, "likely": 5000, "max": 10000},
        "incident_response": {"min": 500, "likely": 1000, "max": 2000},
        "downtime": {"min": 200, "likely": 500, "max": 1000},
        "regulatory": {"min": 0, "likely": 0, "max": 0},
        "reputation": {"min": 1000, "likely": 3000, "max": 6000}
    }
    
    probability = 0.5 # 50% chance
    
    stats = run_lec_simulation(probability, impact_params, iterations=10000)
    
    print("\nSimulation Results:")
    for k, v in stats.items():
        print(f"  {k}: ${v:,.2f}")
        
    print("\nVerifying constraints:")
    # Mean should be roughly probability * sum(likely)
    approx_expected = probability * sum(p["likely"] for p in impact_params.values())
    print(f"  Expected (Deterministic approx): ${approx_expected:,.2f}")
    print(f"  Simulation Mean: ${stats['mean']:,.2f}")
    
    # Assertions for sanity check
    assert stats["mean"] > 0, "Mean should be positive"
    assert stats["p90"] >= stats["mean"], "p90 should be >= mean"
    assert stats["p10"] <= stats["mean"], "p10 should be <= mean"
    
    print("\n✅ Simulation logic verified successfully!")

if __name__ == "__main__":
    try:
        test_simulation()
    except Exception as e:
        print(f"\n❌ Test Failed: {e}")
        sys.exit(1)
