from __future__ import annotations
import json, sys
from pathlib import Path
LABELS={"bugs":"Bugs","vulnerabilities":"Vulnerabilidades","security_hotspots":"Security Hotspots","code_smells":"Code Smells","coverage":"Cobertura","duplicated_lines_density":"Duplicación de líneas","sqale_index":"Deuda técnica (índice SQALE)","ncloc":"Líneas de código","tests":"Pruebas","test_failures":"Fallos de pruebas","alert_status":"Quality Gate"}
def main(src:str,dst:str)->None:
    data=json.loads(Path(src).read_text(encoding="utf-8"))
    measures={m["metric"]:m.get("value","-") for m in data.get("component",{}).get("measures",[])}
    lines=["# Métricas SonarQube — Coppel Next","","| Métrica | Resultado |","|---|---:|"]
    for key,label in LABELS.items(): lines.append(f"| {label} | {measures.get(key,'-')} |")
    lines += ["","> Evidencia generada por SonarQube durante CI."]
    Path(dst).write_text("\n".join(lines)+"\n",encoding="utf-8")
if __name__=="__main__":
    if len(sys.argv)!=3: raise SystemExit(2)
    main(sys.argv[1],sys.argv[2])
