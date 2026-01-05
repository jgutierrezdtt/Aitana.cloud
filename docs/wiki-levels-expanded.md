# Sistema de Clasificación por Niveles y Roles - Wiki de Seguridad

## Filosofía

Este sistema clasifica artículos basándose en **niveles de experiencia profesional** y **roles especializados** en desarrollo seguro, NO en percepciones subjetivas de dificultad.

## 12 Niveles y Roles Profesionales

### 1. 🎓 Estudiante
**Perfil**: Aprendiendo conceptos básicos de desarrollo web y seguridad  
**Experiencia**: 0 años, formación académica  
**Intereses principales**:
- Conceptos fundamentales (HTTP, cookies, sesiones)
- Vulnerabilidades comunes (SQLi, XSS)
- Teoría antes que práctica
- Certificaciones base

---

### 2. 🌱 Junior Developer (0-2 años)
**Perfil**: Desarrollador junior comenzando carrera profesional  
**Experiencia**: 0-2 años en desarrollo  
**Intereses principales**:
- Implementación de código seguro básico
- Validación de entrada y output encoding
- Queries parametrizadas
- Prevención de vulnerabilidades comunes
- Best practices de seguridad

---

### 3. 💻 Mid-Level Developer (2-5 años)
**Perfil**: Desarrollador con experiencia intermedia  
**Experiencia**: 2-5 años en desarrollo  
**Intereses principales**:
- Autenticación y autorización robusta
- Manejo seguro de sesiones
- APIs REST seguras
- CORS y políticas de seguridad
- Headers de seguridad
- CSP (Content Security Policy)

---

### 4. 🚀 Senior Developer (5-10 años)
**Perfil**: Desarrollador senior con experiencia sólida  
**Experiencia**: 5-10 años en desarrollo  
**Intereses principales**:
- Arquitectura segura de aplicaciones
- Vulnerabilidades avanzadas (XXE, SSTI)
- Criptografía y hashing de passwords
- Code review con enfoque en seguridad
- Mentoring en buenas prácticas

---

### 5. 🏗️ Tech Lead / Architect (10+ años)
**Perfil**: Líder técnico o arquitecto de software  
**Experiencia**: 10+ años en desarrollo  
**Intereses principales**:
- Diseño de arquitecturas seguras
- Decisiones técnicas de seguridad
- Escalabilidad con seguridad
- Evaluación de riesgos técnicos
- Standards y frameworks de desarrollo seguro

---

### 6. ⚙️ DevSecOps Engineer
**Perfil**: Especialista en integración de seguridad en CI/CD  
**Experiencia**: Variable + especialización  
**Intereses principales**:
- Automatización de security testing
- Pipeline security (SAST, DAST, SCA)
- Container security
- Infrastructure as Code seguro
- Security gates en deployment
- Herramientas: OWASP ZAP, SQLMap en pipelines

---

### 7. 🛡️ Security Champion
**Perfil**: Desarrollador que lidera iniciativas de seguridad en su equipo  
**Experiencia**: Variable + liderazgo en seguridad  
**Intereses principales**:
- Evangelización de seguridad
- Training del equipo en secure coding
- Code review enfocado en seguridad
- Threat modeling
- Puente entre desarrollo y seguridad

---

### 8. 🔴 Pentester
**Perfil**: Profesional de testing de penetración ofensivo  
**Experiencia**: Variable + especialización en offensive security  
**Intereses principales**:
- Exploitation de vulnerabilidades
- Bypass de controles de seguridad
- Herramientas: Burp Suite, SQLMap, Nikto
- Técnicas avanzadas (SSTI, XXE, Command Injection)
- Bug bounty hunting
- Red teaming

---

### 9. 🎯 Security Expert
**Perfil**: Experto técnico dedicado 100% a ciberseguridad  
**Experiencia**: 5-10+ años en seguridad  
**Intereses principales**:
- Investigación de vulnerabilidades
- Security research
- CVE hunting y disclosure
- Desarrollo de exploits
- Advanced attack techniques
- Security architecture design

---

### 10. 💼 CISO (Chief Information Security Officer)
**Perfil**: Responsable de estrategia de seguridad organizacional  
**Experiencia**: 10-15+ años (técnico + management)  
**Intereses principales**:
- Decisiones estratégicas de seguridad
- Gestión de riesgos (risk management)
- Compliance y regulaciones
- Presupuesto de seguridad
- Visión ejecutiva de vulnerabilidades críticas
- Impacto de negocio

---

### 11. 📊 Security Manager / PMO
**Perfil**: Gestor de programas y proyectos de seguridad  
**Experiencia**: 7-12+ años (técnico + PM)  
**Intereses principales**:
- Gestión de programas de seguridad
- Governance y compliance
- Security roadmaps
- Coordinación de equipos de seguridad
- KPIs y métricas de seguridad
- Budget management

---

### 12. 💰 Bug Bounty Hunter
**Perfil**: Cazarrecompensas profesional de vulnerabilidades  
**Experiencia**: Variable + especialización en bug hunting  
**Intereses principales**:
- Hunting de vulnerabilidades en programas públicos
- Maximización de bounties
- Automatización de reconnaissance
- Técnicas de exploitation eficientes
- Chaining de vulnerabilidades
- 0-day discovery

---

## Distribución de Artículos por Nivel/Rol

### Fundamentos (6 artículos)
- **HTTP Básico**: Todos los niveles (base universal)
- **Cookies y Sesiones**: Todos excepto Security Manager
- **Autenticación/Autorización**: Mid-level en adelante + roles de seguridad
- **Arquitectura Cliente-Servidor**: Estudiante hasta Tech Lead
- **APIs REST**: Mid-level en adelante + roles de seguridad
- **CORS**: Mid-level en adelante + roles de seguridad

### Vulnerabilidades (8 artículos)
- **SQL Injection**: TODOS los niveles (crítico universal)
- **XSS**: TODOS los niveles (crítico universal)
- **CSRF**: Mid-level en adelante + roles de seguridad
- **IDOR**: Junior en adelante + roles de seguridad
- **Broken Authentication**: Mid-level en adelante + CISO/Manager
- **Command Injection**: Mid-level en adelante + pentesters
- **XXE**: Senior en adelante + roles especializados
- **SSTI**: Senior en adelante + roles especializados

### Defensas (7 artículos)
- **Input Validation**: Junior en adelante + pentesters
- **Output Encoding**: Junior en adelante (excepto managers)
- **Parameterized Queries**: Junior en adelante (excepto managers)
- **Password Hashing**: Mid-level en adelante + managers
- **CSP**: Mid-level en adelante + CISO
- **Security Headers**: Mid-level en adelante + managers
- **Secure Sessions**: Mid-level en adelante + CISO

### Herramientas (4 artículos)
- **Nikto**: Senior en adelante + roles especializados
- **OWASP ZAP**: Mid-level en adelante + roles especializados
- **Burp Suite**: Senior en adelante + roles especializados
- **SQLMap**: Roles especializados (DevSecOps, Champions, Pentesters, etc.)

---

## Beneficios del Sistema de 12 Niveles

✅ **Granularidad**: Cubre toda la progresión de carrera en desarrollo seguro  
✅ **Objetivo**: Basado en años de experiencia y especialización real  
✅ **Práctico**: Usuario identifica su nivel actual y siguiente objetivo  
✅ **Escalable**: Fácil agregar más roles especializados  
✅ **Real**: Refleja roles del mercado laboral actual  
✅ **Flexible**: Artículos pueden servir a múltiples niveles  
✅ **Progresivo**: Muestra path de crecimiento profesional claro

---

## Comparación: Sistema Anterior vs Nuevo

### ❌ Sistema Anterior (4 roles)
- Estudiante, Desarrollador, Pentester, CISO
- Muy genérico, "Desarrollador" cubre 0-15 años
- No diferencia entre junior y senior
- No incluye roles especializados emergentes

### ✅ Sistema Nuevo (12 niveles)
- Progresión clara de carrera
- Diferenciación de experiencia (Junior → Mid → Senior → Lead)
- Roles especializados modernos (DevSecOps, Security Champion, Bug Bounty)
- Path de crecimiento visible

---

## Próximos Roles Potenciales

- **Cloud Security Engineer**: Especialista en AWS/Azure/GCP security
- **SOC Analyst**: Detección y respuesta a incidentes
- **Forensics Analyst**: Análisis forense digital
- **Security Researcher**: Investigación académica/empresarial
- **Red Team / Blue Team**: Simulación de adversarios / defensa

---

Última actualización: 5 de enero de 2026  
Sistema: **12 Niveles de Experiencia + Roles Especializados**
