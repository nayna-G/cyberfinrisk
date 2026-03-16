import logging
from typing import Optional
from models.company import AssetContext

logger = logging.getLogger(__name__)

# Lazy import pgmpy to handle slow installations or initialization overhead
pgmpy_available = False
BayesianNetwork = None
TabularCPD = None
VariableElimination = None

def _import_pgmpy():
    global BayesianNetwork, TabularCPD, VariableElimination, pgmpy_available
    if pgmpy_available:
        return
    try:
        from pgmpy.models import BayesianNetwork as BN
        from pgmpy.factors.discrete import TabularCPD as CPD
        from pgmpy.inference import VariableElimination as VE
        BayesianNetwork = BN
        TabularCPD = CPD
        VariableElimination = VE
        pgmpy_available = True
    except (ImportError, Exception) as e:
        logger.warning(f"pgmpy not loaded statefully ({e}). falling back to baseline probability models.")

class FAIRBayesianNetwork:
    def __init__(self):
        _import_pgmpy()
        if not pgmpy_available:
            self.model = None
            return

        # Define structure
        # CF: Contact Frequency, PoA: Probability of Action, V: Susceptibility
        # C: Control Effectiveness
        # LEF: Loss Event Frequency
        self.model = BayesianNetwork([
            ('Exposure', 'CF'),
            ('AssetCriticality', 'PoA'),
            ('BugType', 'V'),
            ('CF', 'LEF'),
            ('PoA', 'LEF'),
            ('V', 'LEF'),
            ('ControlEffectiveness', 'LEF')
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

        # 4. ControlEffectiveness (States: High_Eff, Med_Eff, Low_Eff)
        cpd_control = TabularCPD(variable='ControlEffectiveness', variable_card=3,
                                  values=[[0.33], [0.34], [0.33]],
                                  state_names={'ControlEffectiveness': ['High_Eff', 'Med_Eff', 'Low_Eff']})

        # 5. ContactFrequency (CF) - Depends on Exposure
        cpd_cf = TabularCPD(variable='CF', variable_card=3,
                             values=[
                                 [0.8,    0.2,      0.05], # High_CF
                                 [0.15,   0.6,      0.25], # Med_CF
                                 [0.05,   0.2,      0.7]   # Low_CF
                             ],
                             evidence=['Exposure'], evidence_card=[3],
                             state_names={'CF': ['High_CF', 'Med_CF', 'Low_CF'],
                                          'Exposure': ['Public', 'Internal', 'Private']})

        # 6. ProbabilityOfAction (PoA) - Depends on AssetCriticality
        cpd_poa = TabularCPD(variable='PoA', variable_card=3,
                              values=[
                                  [0.7,   0.3,  0.1], # High_PoA
                                  [0.2,   0.5,  0.3], # Med_PoA
                                  [0.1,   0.2,  0.6]  # Low_PoA
                              ],
                              evidence=['AssetCriticality'], evidence_card=[3],
                              state_names={'PoA': ['High_PoA', 'Med_PoA', 'Low_PoA'],
                                           'AssetCriticality': ['High', 'Med', 'Low']})

        # 7. Susceptibility (V) - Depends on BugType
        cpd_v = TabularCPD(variable='V', variable_card=3,
                            values=[
                                [0.9,   0.6,  0.2,  0.05], # High_V
                                [0.08,  0.3,  0.6,  0.25], # Med_V
                                [0.02,  0.1,  0.2,  0.7]   # Low_V
                            ],
                            evidence=['BugType'], evidence_card=[4],
                            state_names={'V': ['High_V', 'Med_V', 'Low_V'],
                                         'BugType': ['Critical_Bug', 'High_Bug', 'Med_Bug', 'Low_Bug']})

        # 8. LossEventFrequency (LEF) - Depends on CF, PoA, V, ControlEffectiveness
        values_lef_high = []
        values_lef_med = []
        values_lef_low = []
        
        for cf in [2, 1, 0]: # High, Med, Low
            for poa in [2, 1, 0]:
                for v in [2, 1, 0]:
                     for c in [2, 1, 0]: # Control High=2, Med=1, Low=0
                          # Score calculation: High value for risks, minus control score
                          score = cf + poa + v - c # range -2 to 6
                          if score >= 5:   dist = [0.85, 0.1, 0.05]
                          elif score >= 4: dist = [0.7, 0.2, 0.1]
                          elif score >= 3: dist = [0.4, 0.4, 0.2]
                          elif score >= 2: dist = [0.15, 0.5, 0.35]
                          elif score >= 1: dist = [0.05, 0.3, 0.65]
                          else:            dist = [0.01, 0.09, 0.9]
                          values_lef_high.append(dist[0])
                          values_lef_med.append(dist[1])
                          values_lef_low.append(dist[2])

        cpd_lef = TabularCPD(variable='LEF', variable_card=3,
                              values=[values_lef_high, values_lef_med, values_lef_low],
                              evidence=['CF', 'PoA', 'V', 'ControlEffectiveness'], evidence_card=[3, 3, 3, 3],
                              state_names={'LEF': ['High_LEF', 'Med_LEF', 'Low_LEF'],
                                           'CF': ['High_CF', 'Med_CF', 'Low_CF'],
                                           'PoA': ['High_PoA', 'Med_PoA', 'Low_PoA'],
                                           'V': ['High_V', 'Med_V', 'Low_V'],
                                           'ControlEffectiveness': ['High_Eff', 'Med_Eff', 'Low_Eff']})

        self.model.add_cpds(cpd_exposure, cpd_crit, cpd_bug, cpd_control, cpd_cf, cpd_poa, cpd_v, cpd_lef)
        self.model.check_model()
        self.infer = VariableElimination(self.model)

    def infer_probability(self, exposure: str, bug_type: str, asset: Optional[AssetContext] = None, controls_efficacy: Optional[float] = None) -> float:
        """
        Infers the Loss Event Frequency (LEF) probability using evidence nodes.
        """
        if not self.model:
            return 0.05

        evidence = {}
        
        # 1. Map Exposure
        exposure_map = {
            "PUBLIC": "Public",
            "INTERNAL": "Internal",
            "PRIVATE": "Private"
        }
        evidence['Exposure'] = exposure_map.get(exposure.upper(), "Internal")

        # 2. Map AssetCriticality
        if asset:
             if asset.environment.lower() == "prod":
                  evidence['AssetCriticality'] = "High"
             elif asset.environment.lower() == "staging":
                  evidence['AssetCriticality'] = "Med"
             else:
                  evidence['AssetCriticality'] = "Low"
        else:
             evidence['AssetCriticality'] = "Med"

        # 3. Map BugType
        bug_type_upper = bug_type.upper()
        if bug_type_upper in ["RCE", "COMMAND_INJECTION", "AUTH_BYPASS"]:
             evidence['BugType'] = "Critical_Bug"
        elif bug_type_upper in ["SQL_INJECTION", "SSRF", "HARDCODED_CREDENTIALS"]:
             evidence['BugType'] = "High_Bug"
        elif bug_type_upper in ["XSS", "IDOR", "PATH_TRAVERSAL"]:
             evidence['BugType'] = "Med_Bug"
        else:
             evidence['BugType'] = "Low_Bug"

        # 4. Map ControlEffectiveness
        if controls_efficacy is not None:
             if controls_efficacy >= 0.8:
                  evidence['ControlEffectiveness'] = "High_Eff"
             elif controls_efficacy >= 0.4:
                  evidence['ControlEffectiveness'] = "Med_Eff"
             else:
                  evidence['ControlEffectiveness'] = "Low_Eff"

        try:
             q = self.infer.query(variables=['LEF'], evidence=evidence, show_progress=False)
             return float(q.values[0])
        except Exception as e:
             logger.error(f"BN Inference failed: {e}")
             return 0.05

_bn = None
def get_bn_probability(exposure: str, bug_type: str, asset: Optional[AssetContext] = None) -> float:
    global _bn
    if _bn is None:
        _bn = FAIRBayesianNetwork()
    return _bn.infer_probability(exposure, bug_type, asset)
