# 📚 Guía de Escritura Pedagógica para Artículos Wiki

## Principios Fundamentales

### ❌ Antes (Enfoque Técnico)
- Artículos llenos de código
- Explicaciones técnicas densas
- Asume conocimiento previo
- Poco contexto del "por qué"

### ✅ Ahora (Enfoque Pedagógico)
- **Explicaciones primero, código después**
- Uso de analogías del mundo real
- Estructura de aprendizaje progresivo
- Enfoque en "entender antes de aplicar"

---

## Estructura Recomendada por Artículo

### 1. **Introducción (Engagement)**
```tsx
<Section id="introduccion" title="[Título con Hook]">
  <Paragraph>
    Imagina que... [Analogía del mundo real]
  </Paragraph>

  <Paragraph>
    Esto es <Strong>[Concepto]</Strong>: [Definición simple]
  </Paragraph>

  <AlertInfo title="¿Por qué es importante?">
    <ul>
      <ListItem>[Beneficio 1]</ListItem>
      <ListItem>[Beneficio 2]</ListItem>
      <ListItem>[Beneficio 3]</ListItem>
    </ul>
  </AlertInfo>

  <Subsection title="¿Qué puede salir mal?">
    <HighlightBox>
      <ul>
        <ListItem>🔓 [Consecuencia 1]</ListItem>
        <ListItem>📧 [Consecuencia 2]</ListItem>
        <ListItem>🎭 [Consecuencia 3]</ListItem>
      </ul>
    </HighlightBox>
  </Subsection>
</Section>
```

### 2. **Conceptos Fundamentales (Educación)**
```tsx
<Section id="conceptos" title="Entendiendo [Concepto] Sin Tecnicismos">
  <Paragraph>
    Antes de ver los ataques, necesitas entender...
  </Paragraph>

  <HighlightBox>
    <Paragraph><Strong>Analogía del [Algo Familiar]</Strong></Paragraph>
    <ul>
      <ListItem><Strong>Componente 1</Strong> = Equivalente real</ListItem>
      <ListItem><Strong>Componente 2</Strong> = Equivalente real</ListItem>
    </ul>
    <Paragraph className="mt-3">
      [Explicación de la analogía]
    </Paragraph>
  </HighlightBox>

  <Subsection title="Flujo Paso a Paso (Versión Simple)">
    <AlertInfo title="Paso 1: [Acción]">
      <Paragraph className="mt-2">
        [Explicación simple del paso]
      </Paragraph>
    </AlertInfo>
    
    <AlertInfo title="Paso 2: [Acción]">
      <Paragraph className="mt-2">
        [Explicación simple del paso]
      </Paragraph>
    </AlertInfo>
    
    <!-- Repetir para cada paso -->
  </Subsection>
</Section>
```

### 3. **Cada Ataque Específico**
```tsx
<Section id="ataque-1" title="Ataque: [Nombre Descriptivo]">
  <Subsection title="¿Qué es este ataque?">
    <Paragraph>
      [Explicación en lenguaje simple]
    </Paragraph>

    <HighlightBox>
      <Paragraph className="text-lg">
        💡 <Strong>Analogía:</Strong> [Comparación con algo del mundo real]
      </Paragraph>
    </HighlightBox>
  </Subsection>

  <Subsection title="¿Cómo funciona el ataque?">
    <AlertWarning title="Paso 1: [Fase del ataque]">
      <Paragraph className="mt-2">
        [Explicación de qué hace el atacante]
      </Paragraph>
      <!-- Código SOLO si es necesario -->
      <CodeBlock
        language="text"
        code={`[Ejemplo visual simple]`}
      />
    </AlertWarning>

    <AlertDanger title="Paso 2: [Fase crítica]">
      <Paragraph className="mt-2">
        [Qué sucede cuando se activa]
      </Paragraph>
    </AlertDanger>

    <AlertDanger title="Paso 3: [Consecuencia]">
      <Paragraph className="mt-2">
        [Resultado del ataque]
      </Paragraph>
      <ul className="mt-2 space-y-1">
        <ListItem>✅ [Qué logra el atacante]</ListItem>
        <ListItem>🚨 [Impacto en la víctima]</ListItem>
        <ListItem>💀 [Consecuencia adicional]</ListItem>
      </ul>
    </AlertDanger>
  </Subsection>

  <Subsection title="¿Por qué funciona?">
    <Paragraph>
      [Explicación de la falla de seguridad subyacente]
    </Paragraph>

    <HighlightBox>
      <ul className="space-y-2">
        <ListItem>❌ [Error común 1]</ListItem>
        <ListItem>❌ [Error común 2]</ListItem>
        <ListItem>❌ [Error común 3]</ListItem>
      </ul>
    </HighlightBox>
  </Subsection>

  <Subsection title="¿Cómo detectar esta vulnerabilidad?">
    <AlertTip title="Prueba manual en Bug Bounty">
      <ol className="mt-2 space-y-2 list-decimal list-inside">
        <ListItem>[Paso accionable 1]</ListItem>
        <ListItem>[Paso accionable 2]</ListItem>
        <ListItem>[Paso accionable 3]</ListItem>
        <ListItem>Si [resultado] → <Strong>VULNERABLE</Strong></ListItem>
      </ol>
    </AlertTip>

    <Paragraph>
      [Consejos adicionales de detección]
    </Paragraph>
  </Subsection>

  <Subsection title="Mitigación correcta">
    <CodeBlock
      language="javascript"
      title="✅ Implementación segura"
      code={`// Código comentado con explicaciones
// NO solo código crudo`}
    />
  </Subsection>
</Section>
```

---

## Reglas de Oro

### ✅ HACER
1. **Empezar con una analogía del mundo real**
   - OAuth = Hotel con tarjetas de acceso temporal
   - CSRF = Falsificación de firma en un cheque
   - XSS = Inyectar grafiti en una página web

2. **Explicar el "por qué" antes del "cómo"**
   - ¿Por qué existe esta vulnerabilidad?
   - ¿Qué problema intentaba resolver?
   - ¿Por qué los desarrolladores cometen este error?

3. **Usar lenguaje conversacional**
   - "Imagina que..."
   - "Esto es como..."
   - "¿Qué pasaría si...?"

4. **Dividir conceptos complejos en pasos simples**
   - Numeración clara (Paso 1, 2, 3...)
   - Un concepto por párrafo
   - AlertInfo para cada paso del flujo

5. **Código como apoyo, no como protagonista**
   - Máximo 30% del contenido debe ser código
   - Código debe tener comentarios explicativos
   - Preferir diagramas de flujo en texto

6. **Incluir sección "¿Cómo detectar?" práctica**
   - Checklist accionable
   - Pasos específicos de Bug Bounty
   - Herramientas recomendadas

### ❌ EVITAR
1. **Bloques de código sin contexto**
   - NO poner código crudo sin explicación previa

2. **Jerga técnica sin definir**
   - Definir términos la primera vez
   - Usar <InlineCode> para términos técnicos

3. **Asumir conocimiento previo**
   - Explicar desde cero
   - Enlaces a artículos relacionados para profundizar

4. **Explicaciones abstractas**
   - Usar ejemplos concretos
   - Casos de uso reales

---

## Componentes Pedagógicos Clave

### 🎯 HighlightBox (Conceptos Importantes)
```tsx
<HighlightBox>
  <ul className="space-y-2">
    <ListItem>🔓 [Consecuencia visual]</ListItem>
    <ListItem>📧 [Impacto claro]</ListItem>
  </ul>
</HighlightBox>
```

### 💡 AlertInfo (Información Neutral)
```tsx
<AlertInfo title="Paso X: [Título descriptivo]">
  <Paragraph className="mt-2">
    [Explicación del paso]
  </Paragraph>
</AlertInfo>
```

### ⚠️ AlertWarning (Fases del Ataque)
```tsx
<AlertWarning title="Paso 1: Atacante prepara trampa">
  <Paragraph className="mt-2">
    [Qué hace el atacante]
  </Paragraph>
  <CodeBlock language="text" code={`[Ejemplo visual]`} />
</AlertWarning>
```

### 🚨 AlertDanger (Consecuencias Críticas)
```tsx
<AlertDanger title="Paso 2: Consecuencia grave">
  <Paragraph className="mt-2">
    [Qué sale mal]
  </Paragraph>
  <ul className="mt-2 space-y-1">
    <ListItem>✅ [Lo que logra el atacante]</ListItem>
    <ListItem>🚨 [Daño causado]</ListItem>
  </ul>
</AlertDanger>
```

### ✅ AlertTip (Detección y Mitigación)
```tsx
<AlertTip title="Checklist de pruebas">
  <ol className="mt-2 space-y-2 list-decimal list-inside">
    <ListItem>[Paso accionable]</ListItem>
    <ListItem>Si [condición] → <Strong>VULNERABLE</Strong></ListItem>
  </ol>
</AlertTip>
```

---

## Ejemplo de Transformación

### ❌ ANTES (Mal - Solo Código)
```tsx
<Section id="sql-injection" title="SQL Injection">
  <CodeBlock
    language="sql"
    code={`SELECT * FROM users WHERE username = '$input'`}
  />
  
  <Paragraph>Vulnerable a inyección SQL.</Paragraph>
  
  <CodeBlock
    language="sql"
    code={`SELECT * FROM users WHERE username = ?`}
  />
</Section>
```

### ✅ DESPUÉS (Bien - Pedagógico)
```tsx
<Section id="sql-injection" title="Ataque: SQL Injection (Inyectar Comandos en la Base de Datos)">
  <Subsection title="¿Qué es SQL Injection?">
    <Paragraph>
      Imagina que le pides a un bibliotecario: "Dame el libro de [nombre]". 
      Pero en lugar de un nombre, le dices: "Dame el libro de Juan' O dame TODOS los libros--". 
      El bibliotecario, confundido, te da acceso a toda la biblioteca.
    </Paragraph>

    <HighlightBox>
      <Paragraph className="text-lg">
        💡 <Strong>Analogía:</Strong> SQL Injection es como modificar una pregunta para 
        que la base de datos responda más de lo que debería.
      </Paragraph>
    </HighlightBox>
  </Subsection>

  <Subsection title="¿Cómo funciona el ataque?">
    <AlertWarning title="Paso 1: Código vulnerable">
      <Paragraph className="mt-2">
        La aplicación construye consultas SQL concatenando texto del usuario:
      </Paragraph>
      <CodeBlock
        language="sql"
        code={`-- Si el usuario escribe: admin' OR '1'='1
SELECT * FROM users WHERE username = 'admin' OR '1'='1'
                                               👆 Siempre verdadero`}
      />
    </AlertWarning>

    <AlertDanger title="Paso 2: Atacante inyecta código SQL">
      <Paragraph className="mt-2">
        La consulta modificada devuelve TODOS los usuarios porque la condición 
        <InlineCode>'1'='1'</InlineCode> siempre es verdadera.
      </Paragraph>
    </AlertDanger>
  </Subsection>

  <Subsection title="Mitigación">
    <CodeBlock
      language="javascript"
      title="✅ Usar Prepared Statements"
      code={`// El signo ? es un placeholder que se escapa automáticamente
db.query(
  'SELECT * FROM users WHERE username = ?',
  [userInput]  // Valores se pasan por separado
);`}
    />
  </Subsection>
</Section>
```

---

## Métricas de Calidad

Un artículo pedagógico debe tener:
- ✅ 1-2 analogías del mundo real
- ✅ Explicación paso a paso (mínimo 3 pasos)
- ✅ Sección "¿Por qué funciona?"
- ✅ Sección "¿Cómo detectar?"
- ✅ Código ≤ 30% del contenido total
- ✅ Al menos 5 AlertInfo/Warning/Danger combinados
- ✅ HighlightBox para conceptos clave
- ✅ Lenguaje conversacional (evitar pasiva)

---

## Aplicar a Artículos Existentes

### Prioridad Alta (Más Visitados)
1. sql-injection-avanzada.tsx
2. xss-stored.tsx
3. xss-dom-based.tsx
4. jwt-vulnerabilities.tsx
5. csrf-advanced.tsx

### Prioridad Media
6. ssrf-basico.tsx
7. idor.tsx
8. cors-misconfiguration.tsx
9. csp-bypass.tsx
10. mongodb-injection.tsx

### Resto de artículos
- Aplicar mismo patrón progresivamente
- Mantener consistencia de estilo
- Revisar que compile sin errores

---

## Checklist Final

Antes de commitear un artículo mejorado:
- [ ] Tiene analogía del mundo real en intro
- [ ] Pasos del ataque están numerados y explicados
- [ ] Sección "¿Por qué funciona?" presente
- [ ] Sección "¿Cómo detectar?" con checklist
- [ ] Código tiene comentarios explicativos
- [ ] AlertInfo/Warning/Danger usados apropiadamente
- [ ] HighlightBox para conceptos clave
- [ ] No más del 30% es código
- [ ] Lenguaje conversacional y accesible
- [ ] Sin errores de compilación

---

**Creado:** 5 de enero de 2026  
**Autor:** Equipo Aitana.cloud  
**Propósito:** Guía de referencia para escribir contenido educativo de calidad
