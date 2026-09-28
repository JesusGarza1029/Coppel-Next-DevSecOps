from __future__ import annotations
import json, sys
from pathlib import Path
RISK_NAMES = {3:"High",2:"Medium",1:"Low",0:"Informational"}
def main(path: str) -> int:
    data=json.loads(Path(path).read_text(encoding="utf-8"))
    findings=[]
    for site in data.get("site",[]):
        for alert in site.get("alerts",[]):
            findings.append({"risk":int(alert.get("riskcode",0)),"name":alert.get("name","Unknown"),"count":alert.get("count",0)})
    counts={name:0 for name in RISK_NAMES.values()}
    for item in findings:
        name=RISK_NAMES.get(item["risk"],"Unknown")
        counts[name]=counts.get(name,0)+int(item.get("count") or 0)
    print("ZAP findings by risk:")
    for name in ["High","Medium","Low","Informational"]: print(f"- {name}: {counts.get(name,0)}")
    blockers=[item for item in findings if item["risk"]>=2]
    if blockers:
        print("\nBLOCKING findings:")
        for item in blockers: print(f"- {RISK_NAMES[item['risk']]}: {item['name']} (count={item['count']})")
        return 1
    print("\nZAP gate: PASS (sin hallazgos High/Medium)")
    return 0
if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit(2)
    raise SystemExit(main(sys.argv[1]))
