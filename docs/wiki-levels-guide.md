# Guía de Niveles de la Wiki

Esta guía define los niveles de dificultad de los artículos de la Wiki basados en la **experiencia del usuario**, no en la complejidad técnica del tema.

## Definición de Niveles

### 🟢 Principiante (0-6 meses de experiencia)
**Objetivo**: Personas que están dando sus primeros pasos en seguridad web.

**Características:**
- Sin conocimiento previo requerido
- Conceptos fundamentales y básicos
- Ejemplos simples y bien explicados
- Enfoque en "qué es" y "por qué importa"
- Práctica en entornos controlados/labs

**Ejemplos de artículos:**
- Fundamentos: HTTP Básico, Cookies y Sesiones, Autenticación/Autorización, CORS
- Vulnerabilidades: SQL Injection, XSS, IDOR, CSRF, Broken Authentication
- Defensas: Input Validation, Output Encoding, Parameterized Queries, Password Hashing
- Herramientas: Nikto, OWASP ZAP

### 🟡 Intermedio (6-18 meses de experiencia)
**Objetivo**: Personas que ya conocen los fundamentos y están aplicándolos en proyectos reales.

**Características:**
- Conocimiento básico previo de seguridad web
- Implementación en proyectos reales
- Configuraciones de producción
- Casos de uso más complejos
- Workflows y mejores prácticas

**Ejemplos de artículos:**
- Vulnerabilidades: Command Injection, XXE
- Defensas: CSP, Security Headers, Secure Session Management
- Herramientas: Burp Suite, SQLMap

### 🔴 Avanzado (18+ meses de experiencia)
**Objetivo**: Profesionales con experiencia en producción que buscan especializarse.

**Características:**
- Experiencia sustancial en seguridad web
- Optimización y casos edge
- Bypass de protecciones
- Investigación y variantes
- Automatización avanzada

**Ejemplos de artículos:**
- Vulnerabilidades: SSTI (variantes complejas, bypass de sandboxing)
- Defensas: WAF custom rules, Rate limiting avanzado
- Herramientas: Custom exploits, Fuzzing avanzado

## Criterios de Clasificación

Al crear o actualizar un artículo, pregúntate:

1. **¿Qué experiencia previa necesita el lector?**
   - Ninguna → Principiante
   - Fundamentos de web → Intermedio
   - Experiencia en producción → Avanzado

2. **¿En qué etapa de aprendizaje está?**
   - Aprendiendo conceptos → Principiante
   - Aplicando en proyectos → Intermedio
   - Optimizando y especializándose → Avanzado

3. **¿Cuál es el objetivo del artículo?**
   - Entender "qué es" → Principiante
   - Implementar correctamente → Intermedio
   - Dominar casos complejos → Avanzado

## Ejemplos de Clasificación

### ❌ Incorrecto (Basado en complejidad técnica)
- SQL Injection → Avanzado (porque puede ser técnicamente complejo)
- SSTI → Avanzado (porque requiere conocer templates)
- CSP → Intermedio (porque la sintaxis es confusa)

### ✅ Correcto (Basado en experiencia del usuario)
- SQL Injection → **Principiante** (primera vuln que todo principiante debe conocer)
- SSTI → **Avanzado** (requiere experiencia previa con múltiples tecnologías)
- CSP → **Intermedio** (implementación en producción, ya conoce XSS)

## Distribución Actual

**Fundamentos (6 artículos):**
- 6 Principiante ✅

**Vulnerabilidades (8 artículos):**
- 5 Principiante (SQLi, XSS, IDOR, CSRF, Broken Auth)
- 2 Intermedio (Command Injection, XXE)
- 1 Avanzado (SSTI)

**Defensas (7 artículos):**
- 4 Principiante (Input Validation, Output Encoding, Parameterized Queries, Password Hashing)
- 3 Intermedio (CSP, Security Headers, Secure Sessions)

**Herramientas (4 artículos):**
- 2 Principiante (Nikto, OWASP ZAP)
- 2 Intermedio (Burp Suite, SQLMap)

**Total: 25 artículos**
- Principiante: 17 (68%)
- Intermedio: 7 (28%)
- Avanzado: 1 (4%)

## Notas para el Futuro

- **NO** basarse en si el tema es "fácil" o "difícil técnicamente
- **SÍ** basarse en qué experiencia tiene el usuario que lee
- Los artículos de Principiante deben ser la mayoría (60-70%)
- Mantener balance: más Principiante e Intermedio, pocos Avanzados
- Al agregar nuevos artículos, considerar la curva de aprendizaje del usuario

---

Última actualización: 5 de enero de 2026
