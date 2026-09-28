# Coppel Next - Implementación DevSecOps

Módulo académico de registro de donantes para demostrar autenticación JWT con roles, pruebas, CI/CD, Docker, Kubernetes, OWASP ZAP y SonarQube.

## Resultado local validado

- 29 pruebas aprobadas
- 96.77% cobertura
- SQLi/XSS/JWT/roles cubiertos por pruebas
- Dockerfile no-root
- Kubernetes con health checks, recursos, secretos y fsGroup

## Ejecutar localmente

```bash
pip install -r requirements.txt
pytest -q --cov=app --cov-report=term-missing --cov-fail-under=80
uvicorn app.main:app --reload
```

## CI/CD

El workflow `.github/workflows/ci-cd.yml` ejecuta: tests -> cobertura -> SonarQube Community Build efímero -> Quality Gate -> Docker -> Kubernetes kind -> smoke test -> ZAP Full Scan -> artifacts.

### Secretos de GitHub

Configura únicamente:

- `JWT_SECRET`: mínimo 32 caracteres.
- `ADMIN_PASSWORD`: mínimo 12 caracteres.

No se requieren secretos SonarQube porque el workflow crea una instancia efímera de Community Build y genera un token temporal para cada ejecución.

## Seguridad

La aplicación exige `JWT_SECRET` y `ADMIN_PASSWORD` en `ENVIRONMENT=production`, usa PBKDF2-HMAC-SHA256 para contraseñas, consultas SQL parametrizadas, validación de datos, escape HTML y encabezados de seguridad.

## Evidencia

Los documentos `docs/evidencia_rubrica.md`, `docs/resultado_zap.md`, `docs/resultado_sonar.md` y `docs/final_submission_checklist.md` están diseñados para documentar el cierre.

## Referencias técnicas

- OWASP ZAP Full Scan: https://www.zaproxy.org/docs/docker/full-scan/
- OWASP ZAP GitHub Action: https://github.com/zaproxy/action-full-scan
- SonarQube Scan Action: https://github.com/sonarsource/sonarqube-scan-action
- SonarQube Quality Gate Action: https://github.com/SonarSource/sonarqube-quality-gate-action
- SonarQube Community Build: https://docs.sonarsource.com/sonarqube-community-build/try-out-sonarqube
- GitHub setup-python: https://github.com/actions/setup-python
- GitHub checkout: https://github.com/actions/checkout
- kind-action: https://github.com/helm/kind-action
