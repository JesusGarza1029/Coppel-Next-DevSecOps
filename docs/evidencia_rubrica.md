# Evidencia frente a la rúbrica

## 1. Implementación y seguridad — 20/20 objetivo
- API FastAPI de registro de donantes.
- JWT con expiración.
- Roles administrador/usuario.
- Control de autorización por endpoint.
- 29 pruebas locales y cobertura validada de 96.77%.
- Casos de JWT inválido/expirado, escalada de privilegios, XSS y SQLi.

## 2. CI/CD — 25/25 objetivo
Pipeline: pruebas → cobertura → SonarQube → Quality Gate → Docker → Kubernetes staging → smoke tests → ZAP Full Scan → artifacts.

## 3. Seguridad y calidad — 25/25 objetivo
- Pruebas de seguridad automatizadas.
- OWASP ZAP Full Scan con gate para High/Medium.
- SonarQube con métricas de bugs, vulnerabilidades, hotspots, code smells, cobertura, duplicación, deuda técnica y Quality Gate.
- Los resultados finales deben conservarse como artifacts de la ejecución real de GitHub Actions.

## 4. Cierre — 15/15 objetivo
Comparación planificado/ejecutado, desviaciones, causas y lecciones aprendidas.

## 5. Mejora continua — 15/15 objetivo
Acciones medibles de seguridad, observabilidad, escalabilidad y propuesta de analítica predictiva para donaciones.
