try:
    from pgmpy.models import BayesianNetwork
    from pgmpy.factors.discrete import TabularCPD
    from pgmpy.inference import VariableElimination
    print("pgmpy imported successfully!")
except ImportError:
    print("pgmpy not yet available. This will run once installation completes.")

def create_model():
    # Define structure
    model = BayesianNetwork([
        ('Exposure', 'CF'),
        ('AssetCriticality', 'PoA'),
        ('BugType', 'V'),
        ('CF', 'LEF'),
        ('PoA', 'LEF'),
        ('V', 'LEF')
    ])

    # 1. Exposure (States: Public, Internal, Private)
    cpd_exposure = TabularCPD(variable='Exposure', variable_card=3, 
                               values=[[0.33], [0.33], [0.34]],
                               state_names={'Exposure': ['Public', 'Internal', 'Private']})

    # 2. AssetCriticality (States: High, Med, Low)
    cpd_crit = TabularCPD(variable='AssetCriticality', variable_card=3, 
                           values=[[0.33], [0.33], [0.34]],
                           state_names={'AssetCriticality': ['High', 'Med', 'Low']})

    # 3. BugType (States: Critical_Bug, High_Bug, Med_Bug, Low_Bug)
    cpd_bug = TabularCPD(variable='BugType', variable_card=4, 
                         values=[[0.25], [0.25], [0.25], [0.25]],
                         state_names={'BugType': ['Critical_Bug', 'High_Bug', 'Med_Bug', 'Low_Bug']})

    # 4. ContactFrequency (CF) - Depends on Exposure
    # States: High_CF, Med_CF, Low_CF
    # Exposure: Public, Internal, Private
    cpd_cf = TabularCPD(variable='CF', variable_card=3,
                         values=[
                             # Public, Internal, Private
                             [0.8,    0.2,      0.05], # High_CF
                             [0.15,   0.6,      0.25], # Med_CF
                             [0.05,   0.2,      0.7]   # Low_CF
                         ],
                         evidence=['Exposure'], evidence_card=[3],
                         state_names={'CF': ['High_CF', 'Med_CF', 'Low_CF'],
                                      'Exposure': ['Public', 'Internal', 'Private']})

    # 5. ProbabilityOfAction (PoA) - Depends on AssetCriticality
    # States: High_PoA, Med_PoA, Low_PoA
    # AssetCriticality: High, Med, Low
    cpd_poa = TabularCPD(variable='PoA', variable_card=3,
                          values=[
                              # High, Med, Low
                              [0.7,   0.3,  0.1], # High_PoA
                              [0.2,   0.5,  0.3], # Med_PoA
                              [0.1,   0.2,  0.6]  # Low_PoA
                          ],
                          evidence=['AssetCriticality'], evidence_card=[3],
                          state_names={'PoA': ['High_PoA', 'Med_PoA', 'Low_PoA'],
                                       'AssetCriticality': ['High', 'Med', 'Low']})

    # 6. Susceptibility (V) - Depends on BugType
    # States: High_V, Med_V, Low_V
    # BugType: Critical_Bug, High_Bug, Med_Bug, Low_Bug
    cpd_v = TabularCPD(variable='V', variable_card=3,
                        values=[
                            # Crit, High, Med, Low
                            [0.9,   0.6,  0.2,  0.05], # High_V
                            [0.08,  0.3,  0.6,  0.25], # Med_V
                            [0.02,  0.1,  0.2,  0.7]   # Low_V
                        ],
                        evidence=['BugType'], evidence_card=[4],
                        state_names={'V': ['High_V', 'Med_V', 'Low_V'],
                                     'BugType': ['Critical_Bug', 'High_Bug', 'Med_Bug', 'Low_Bug']})

    # 7. LossEventFrequency (LEF) - Depends on CF, PoA, V
    # All are card 3: 3*3*3 = 27 evidence columns
    # We will generate a smart weight combination to populate values
    # To reduce manual entry matrix errors: Let weights = (High=2, Med=1, Low=0)
    # Sum scores, map to distribution vector.
    
    values_lef_high = []
    values_lef_med = []
    values_lef_low = []
    
    for cf in [2, 1, 0]: # High, Med, Low
        for poa in [2, 1, 0]:
            for v in [2, 1, 0]:
                score = cf + poa + v # range 0 to 6
                # Normalize distribution roughly
                if score >= 5:   dist = [0.8, 0.15, 0.05]
                elif score >= 4: dist = [0.5, 0.4, 0.1]
                elif score >= 3: dist = [0.2, 0.6, 0.2]
                elif score >= 2: dist = [0.05, 0.4, 0.55]
                else:            dist = [0.01, 0.19, 0.8]
                values_lef_high.append(dist[0])
                values_lef_med.append(dist[1])
                values_lef_low.append(dist[2])

    cpd_lef = TabularCPD(variable='LEF', variable_card=3,
                          values=[values_lef_high, values_lef_med, values_lef_low],
                          evidence=['CF', 'PoA', 'V'], evidence_card=[3, 3, 3],
                          state_names={'LEF': ['High_LEF', 'Med_LEF', 'Low_LEF'],
                                       'CF': ['High_CF', 'Med_CF', 'Low_CF'],
                                       'PoA': ['High_PoA', 'Med_PoA', 'Low_PoA'],
                                       'V': ['High_V', 'Med_V', 'Low_V']})

    # Add factors
    model.add_cpds(cpd_exposure, cpd_crit, cpd_bug, cpd_cf, cpd_poa, cpd_v, cpd_lef)
    model.check_model()
    return model

if __name__ == "__main__":
    try:
        model = create_model()
        print("✅ Model built and verified successfully!")
        
        # Test inference
        infer = VariableElimination(model)
        q = infer.query(variables=['LEF'], evidence={'Exposure': 'Public', 'BugType': 'Critical_Bug'})
        print("\nInference for Public Exposure + Critical Bug:")
        print(q)
    except Exception as e:
        print(f"❌ Verification failed: {e}")
