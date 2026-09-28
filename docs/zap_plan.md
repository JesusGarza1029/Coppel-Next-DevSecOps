# OWASP ZAP

El pipeline ejecuta ZAP Full Scan contra el servicio desplegado en Kubernetes staging.

El script `scripts/check_zap_report.py` bloquea el pipeline ante hallazgos High o Medium. Los reportes HTML, JSON, XML y Markdown se conservan como artifact.
