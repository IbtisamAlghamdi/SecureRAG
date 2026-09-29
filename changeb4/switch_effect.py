"""L0-L3 only: no retrieval, no language model. Measures what the two
run-time switches do to the internal attack and benign sets."""
import os, sys, importlib
sys.path.insert(0, "/home/user/SecureRAG")

SEEDS = [42, 137, 271, 413, 509]

def run(b64_mode, zwsp_mode):
    os.environ["SECURERAG_B64_RULE_MODE"] = b64_mode
    os.environ["SECURERAG_ZWSP_MODE"] = zwsp_mode
    for m in [k for k in list(sys.modules) if k.startswith("src.")]:
        del sys.modules[m]
    from src.config import settings
    settings.B64_RULE_MODE = b64_mode
    settings.ZWSP_MODE = zwsp_mode
    from src.defenses.sanitization.sanitize import sanitize_input, get_sanitization_report
    from src.defenses.rules.rule_filter import rule_based_detector_detailed, quick_high_risk_scan
    from src.defenses.anomaly.anomaly_detector import compute_anomaly_score
    from src.attacks.generator import RealisticAttackGenerator, BenignQueryGenerator
    import random

    thr = settings.ANOMALY_THRESHOLD
    tot = {"att": 0, "det": 0, "ben": 0, "fp": 0,
           "L1": 0, "L2": 0, "L3": 0}
    for seed in SEEDS:
        import random
        random.seed(seed)
        g = RealisticAttackGenerator()
        batch = g.generate_batch(1334, benign_ratio=0.25)
        atts = [q for q in batch if q.get("is_attack")]
        random.seed(seed)
        bg = BenignQueryGenerator()
        bens = bg.generate_batch(333)
        for text, is_attack in [(a["query"], True) for a in atts] + [(b, False) for b in bens]:
            high = quick_high_risk_scan(text)
            clean = sanitize_input(text)
            rep = get_sanitization_report(text, clean)
            layer = None
            if rep["had_template_inj"] or rep["had_injection"] or rep["had_base64"]:
                layer = "L1"
            else:
                hit, _, _ = rule_based_detector_detailed(clean)
                if hit:
                    layer = "L2"
                else:
                    score = compute_anomaly_score(clean)
                    bar = thr * (0.7 if high else 1.0) * 2.0
                    if score > bar:
                        layer = "L3"
            if is_attack:
                tot["att"] += 1
                if layer: tot["det"] += 1; tot[layer] += 1
            else:
                tot["ben"] += 1
                if layer: tot["fp"] += 1
    return tot

print("config                     attacks  detected    rate      L1     L2    L3   benign  FP     FPR")
rows = {}
for b64, zw in [("shape","delete"), ("decode","space"), ("decode","delete"), ("shape","space")]:
    t = run(b64, zw)
    rows[(b64,zw)] = t
    print("b64=%-6s zwsp=%-6s   %6d  %7d  %6.2f%%  %6d %6d %5d   %5d %3d  %5.2f%%" % (
        b64, zw, t["att"], t["det"], 100*t["det"]/t["att"], t["L1"], t["L2"], t["L3"],
        t["ben"], t["fp"], 100*t["fp"]/t["ben"]))
a = rows[("shape","delete")]; b = rows[("decode","space")]
print()
print("thesis config  -> detection %.2f%%  FPR %.2f%%" % (100*a["det"]/a["att"], 100*a["fp"]/a["ben"]))
print("BIPIA config   -> detection %.2f%%  FPR %.2f%%" % (100*b["det"]/b["att"], 100*b["fp"]/b["ben"]))
print("change         -> detection %+.2f points, FPR %+.2f points" % (
    100*b["det"]/b["att"] - 100*a["det"]/a["att"], 100*b["fp"]/b["ben"] - 100*a["fp"]/a["ben"]))
