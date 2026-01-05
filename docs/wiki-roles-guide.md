# Guía de Clasificación por Roles de la Wiki

Esta guía define cómo se clasifican los artículos de la Wiki basándose en **roles profesionales** y **enfoques de aprendizaje**, NO en niveles subjetivos de dificultad.

## Definición de Roles

### 🎓 Estudiante
**Perfil**: Personas que están aprendiendo seguridad web, ya sea de forma autodidacta o en educación formal.

**Intereses principales:**
- Entender conceptos fundamentales
- Aprender cómo funcionan las vulnerabilidades
- Conocer la teoría antes de la práctica
- Prepararse para certificaciones (CEH, OSCP, etc.)

**Artículos relevantes:**
- Fundamentos completos
- Vulnerabilidades básicas (SQL Injection, XSS)
- Teoría de defensas

### 💻 Desarrollador
**Perfil**: Ingenieros de software que construyen aplicaciones web y APIs.

**Intereses principales:**
- Implementar código seguro
- Prevenir vulnerabilidades en el desarrollo
- Configurar headers y políticas de seguridad
- Code review y secure coding practices

**Artículos relevantes:**
- Fundamentos de arquitectura web
- Defensas (Input Validation, Output Encoding, CSP)
- Configuración segura (Security Headers, Sessions)
- Herramientas de testing (OWASP ZAP para DevSecOps)

### 🔴 Pentester
**Perfil**: Profesionales de seguridad ofensiva que realizan pruebas de penetración.

**Intereses principales:**
- Explotar vulnerabilidades
- Técnicas de bypass
- Herramientas de hacking ético
- Metodologías de testing (OWASP, PTES)

**Artículos relevantes:**
- Vulnerabilidades (especialmente técnicas avanzadas)
- Herramientas (Burp Suite, SQLMap, etc.)
- Técnicas de evasión
- Payloads y exploitation

### 🛡️ CISO (Chief Information Security Officer)
**Perfil**: Líderes y gestores de seguridad que toman decisiones estratégicas.

**Intereses principales:**
- Gestión de riesgo
- Políticas y compliance
- Decisiones de arquitectura
- Budget y priorización de defensas

**Artículos relevantes:**
- Fundamentos para entender el landscape
- Vulnerabilidades críticas (OWASP Top 10)
- Estrategias de defensa (CSP, Security Headers)
- Impacto de negocio (CVSS scores)

## Clasificación de Artículos

Cada artículo puede ser relevante para **múltiples roles**. La clasificación se basa en:

1. **¿Para quién es más útil este contenido?**
2. **¿Qué perspectiva toma el artículo?** (teórica, implementación, explotación, estratégica)
3. **¿Qué hace el lector con esta información?** (aprender, desarrollar, testear, decidir)

## Distribución Actual por Rol

**Fundamentos (6 artículos):**
- Todos los roles: HTTP Básico, Cookies y Sesiones
- Estudiante + Desarrollador + CISO: Autenticación/Autorización
- Estudiante + Desarrollador: Arquitectura Cliente-Servidor
- Desarrollador + Pentester: APIs REST, CORS

**Vulnerabilidades (8 artículos):**
- Todos los roles: SQL Injection, XSS
- Desarrollador + Pentester + CISO: CSRF
- Desarrollador + Pentester: IDOR, Command Injection, XXE
- Desarrollador + CISO: Broken Authentication
- Solo Pentester: SSTI

**Defensas (7 artículos):**
- Desarrollador: Input Validation, Output Encoding, Parameterized Queries
- Desarrollador + CISO: Password Hashing, CSP, Security Headers, Secure Sessions

**Herramientas (4 artículos):**
- Pentester + Desarrollador: Nikto, OWASP ZAP
- Solo Pentester: Burp Suite, SQLMap

## Beneficios del Sistema de Roles

✅ **Objetivo**: No depende de percepción subjetiva de dificultad  
✅ **Práctico**: Usuario selecciona su rol y ve contenido relevante  
✅ **Escalable**: Fácil agregar nuevos roles (DevSecOps, Auditor, etc.)  
✅ **Real**: Refleja roles del mercado laboral  
✅ **Flexible**: Un artículo puede servir a múltiples roles

## Posibles Roles Futuros

- **DevSecOps**: Integración de seguridad en CI/CD
- **Compliance Officer**: Regulaciones (GDPR, PCI-DSS)
- **Security Architect**: Diseño de sistemas seguros
- **SOC Analyst**: Detección y respuesta a incidentes
- **Bug Bounty Hunter**: Cazarrecompensas profesional

---

Última actualización: 5 de enero de 2026  
Sistema: **Basado en Roles**, NO en niveles subjetivos
