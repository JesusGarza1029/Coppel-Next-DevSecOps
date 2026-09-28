# SonarQube

El workflow crea una instancia efímera de SonarQube Community Build, genera un token temporal, analiza el código y detiene el pipeline si falla el Quality Gate.

Métricas exportadas: bugs, vulnerabilities, security hotspots, code smells, coverage, duplicated lines density, SQALE/deuda técnica, LOC, tests, test failures y alert_status.
