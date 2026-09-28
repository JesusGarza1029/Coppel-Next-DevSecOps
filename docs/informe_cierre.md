# Informe de cierre

## Planificado vs ejecutado
- Módulo de donantes: ejecutado.
- JWT y roles: ejecutados.
- Pruebas unitarias: ejecutadas; cobertura local 96.77%.
- Docker: implementado.
- Kubernetes staging: automatizado en CI.
- SonarQube: automatizado en CI.
- OWASP ZAP Full Scan: automatizado en CI.

## Desviaciones
La ejecución local no pudo reproducir Docker, Kubernetes, ZAP y SonarQube por limitaciones del entorno; se trasladó su ejecución al runner de GitHub Actions, donde el workflow genera evidencia reproducible.

## Lecciones aprendidas
1. La seguridad debe incorporarse desde el desarrollo.
2. Las pruebas de autorización deben cubrir escalada de privilegios.
3. Los Quality Gates evitan que un cambio con problemas continúe hacia staging.
4. La infraestructura como código hace reproducible el entorno de prueba.
5. Los artifacts son esenciales para demostrar resultados de CI/CD.
