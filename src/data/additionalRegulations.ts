// Normativas Adicionales - Marco Regulatorio Europeo, Español, Industrial y Sectorial
// Este archivo complementa regulations.ts con las nuevas regulaciones 2024-2025

import { type Regulation } from './regulations';

export const additionalRegulationsData: Record<string, Regulation> = {
  // ========================================
  // 1. MARCO REGULATORIO EUROPEO (UE)
  // ========================================
  
  'nis2': {
    id: 'nis2',
    name: 'NIS2',
    fullName: 'Directiva (UE) 2022/2555 - Network and Information Security Directive 2',
    category: 'european' as const,
    jurisdiction: ['EU'],
    description: 'Directiva sobre seguridad de redes y sistemas de información que reemplaza a NIS1. Obliga a medidas de ciberseguridad y resiliencia operativa para entidades esenciales e importantes.',
    purpose: 'Fortalecer la resiliencia operativa y seguridad de la cadena de suministro en sectores críticos y digitales',
    applicability: [
      'Entidades esenciales: Energía, Transporte, Banca, Infraestructura Mercados Financieros, Salud, Agua, Infraestructura Digital',
      'Entidades importantes: Proveedores digitales, gestión residuos, fabricación, alimentos',
      'Proveedores de servicios digitales (cloud, DNS, motores búsqueda, redes sociales)',
      'Cadena de suministro TIC'
    ],
    effectiveDate: '2024-10-17',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Art. 21',
        title: 'Medidas de Gestión de Riesgos de Ciberseguridad',
        description: 'Implementar medidas técnicas, operativas y organizativas apropiadas y proporcionadas para gestionar riesgos',
        literal: 'Los Estados miembros garantizarán que las entidades esenciales e importantes adopten medidas técnicas, operativas y organizativas apropiadas y proporcionadas para gestionar los riesgos que se plantean para la seguridad de las redes y los sistemas de información que utilizan dichas entidades en sus operaciones o en la prestación de sus servicios, así como para prevenir o minimizar el impacto de los incidentes en los destinatarios de sus servicios y en otros servicios.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'operations', 'monitoring']
      },
      {
        article: 'Art. 21.2(e)',
        title: 'Seguridad en Desarrollo y Adquisición de Sistemas',
        description: 'Gestión de vulnerabilidades y divulgación coordinada',
        literal: 'Políticas y procedimientos para evaluar la eficacia de las medidas de gestión de riesgos de ciberseguridad; prácticas básicas de ciberhigiene informática y formación en ciberseguridad; políticas y procedimientos relativos al uso de la criptografía y, en su caso, del cifrado; seguridad de los recursos humanos, políticas de control de acceso y gestión de activos; el uso de soluciones de autenticación multifactor o autenticación continua, comunicaciones de voz, vídeo y texto seguras y sistemas de comunicación de emergencia seguras dentro de la entidad, cuando proceda.',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: 'Art. 23',
        title: 'Notificación de Incidentes',
        description: 'Notificación en 24h (alerta temprana), 72h (notificación de incidente), informe final',
        literal: 'Las entidades esenciales e importantes notificarán, sin demora indebida, cualquier incidente que tenga un impacto significativo en la prestación de sus servicios. Se establecen tres fases: notificación de alerta temprana (24h), notificación de incidente (72h) e informe final.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'Art. 21.2(h)',
        title: 'Seguridad de la Cadena de Suministro',
        description: 'Medidas de seguridad en relaciones con proveedores y calidad de productos/servicios TIC',
        literal: 'Políticas y procedimientos en relación con la seguridad de la cadena de suministro, incluidos aspectos de seguridad relativos a las relaciones entre cada entidad y sus proveedores directos o proveedores de servicios, la calidad de los productos y las prácticas de desarrollo de ciberseguridad de sus proveedores, incluidas las evaluaciones de seguridad de proveedores críticos.',
        ssdlcPhases: ['requirements', 'design', 'deployment', 'operations']
      }
    ],
    penalties: 'Hasta €10M o 2% facturación para entidades esenciales; €7M o 1,4% para entidades importantes. Responsabilidad personal directivos.',
    certificationRequired: false,
    references: {
      official: 'https://eur-lex.europa.eu/eli/dir/2022/2555/oj',
      guidelines: [
        'https://www.enisa.europa.eu/topics/cybersecurity-policy/nis-directive-new',
        'https://www.incibe.es/empresas/nis2'
      ],
      tools: [
        'ENISA NIS Toolkit',
        'ISO 27001 ISMS',
        'NIST Cybersecurity Framework'
      ]
    },
    relatedStandards: ['ISO 27001', 'NIST CSF', 'CIS Controls', 'ENS']
  },

  'dora': {
    id: 'dora',
    name: 'DORA',
    fullName: 'Reglamento (UE) 2022/2554 - Digital Operational Resilience Act',
    category: 'european' as const,
    jurisdiction: ['EU'],
    description: 'Reglamento sobre resiliencia operativa digital para el sector financiero. Establece requisitos uniformes de gestión de riesgos TIC, notificación de incidentes y pruebas de resiliencia.',
    purpose: 'Garantizar la resiliencia operativa digital de entidades financieras y sus proveedores TIC críticos',
    applicability: [
      'Entidades financieras: Bancos, aseguradoras, empresas de inversión, fondos de pensiones, entidades de pago',
      'Proveedores de servicios TIC críticos (CSPs, cloud providers)',
      'Infraestructura de mercados financieros (ESMA, EBA)'
    ],
    effectiveDate: '2025-01-17',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Art. 8',
        title: 'Identificación, Clasificación y Documentación',
        description: 'Mantener registro actualizado de funciones críticas/importantes, procesos y activos TIC',
        literal: 'Las entidades financieras dispondrán de sistemas y herramientas completos de información que permitan a la dirección disponer de datos agregados sobre todos los acuerdos contractuales sobre el uso de servicios TIC prestados por proveedores de servicios TIC, así como los procesos de seguimiento asociados.',
        ssdlcPhases: ['requirements', 'design', 'operations']
      },
      {
        article: 'Art. 11',
        title: 'Gestión de Riesgos Relacionados con Proveedores TIC',
        description: 'Evaluación y control de riesgos de terceros, especialmente proveedores críticos',
        literal: 'Las entidades financieras gestionarán los riesgos relacionados con los proveedores de servicios TIC y la subcontratación de funciones TIC como parte integrante del riesgo TIC dentro de su marco de gestión del riesgo TIC.',
        ssdlcPhases: ['requirements', 'design', 'deployment']
      },
      {
        article: 'Art. 24-27',
        title: 'Pruebas de Resiliencia Operativa Digital Basadas en Amenazas (TLPT)',
        description: 'Test de penetración avanzados con escenarios de amenazas realistas',
        literal: 'Las entidades financieras llevarán a cabo, a intervalos de al menos tres años, pruebas avanzadas de resiliencia operativa digital basadas en amenazas en sistemas y aplicaciones críticos o importantes. Las pruebas se basarán en las orientaciones específicas del sector desarrolladas por las AES y en la inteligencia sobre amenazas.',
        ssdlcPhases: ['testing', 'operations', 'monitoring']
      },
      {
        article: 'Art. 19',
        title: 'Notificación de Incidentes TIC Graves',
        description: 'Notificación inmediata (incidente grave), informe intermedio (72h), informe final',
        literal: 'Las entidades financieras comunicarán los incidentes TIC graves a la autoridad competente pertinente. Notificación inicial sin demora, informe intermedio a más tardar 72 horas tras la notificación inicial, informe final cuando se determine la causa raíz.',
        ssdlcPhases: ['operations', 'monitoring']
      }
    ],
    penalties: 'Multas hasta €10M o 5% facturación anual neta. Suspensión temporal directivos. Publicación de sanciones.',
    certificationRequired: false,
    references: {
      official: 'https://eur-lex.europa.eu/eli/reg/2022/2554/oj',
      guidelines: [
        'https://www.eba.europa.eu/regulation-and-policy/single-rulebook/interactive-single-rulebook/5063',
        'https://www.esma.europa.eu/policy-activities/digital-operational-resilience-dora'
      ],
      tools: [
        'TIBER-EU Framework (TLPT)',
        'ISO 22301 (Business Continuity)',
        'COBIT 2019',
        'NIST Cybersecurity Framework'
      ]
    },
    relatedStandards: ['ISO 27001', 'ISO 22301', 'NIST CSF', 'COBIT', 'PCI-DSS']
  },

  'cra': {
    id: 'cra',
    name: 'CRA',
    fullName: 'Cyber Resilience Act - Ley de Ciberresiliencia',
    category: 'european' as const,
    jurisdiction: ['EU'],
    description: 'Reglamento que introduce requisitos de ciberseguridad obligatorios para productos con elementos digitales (hardware y software). Incluye marcado CE para ciberseguridad.',
    purpose: 'Garantizar que productos digitales sean seguros por defecto durante todo su ciclo de vida',
    applicability: [
      'Fabricantes de hardware con elementos digitales',
      'Desarrolladores de software comercial (no open source puro)',
      'Productos IoT, dispositivos conectados',
      'Software embebido en productos físicos',
      'Productos críticos Clase I y II (requisitos más estrictos)'
    ],
    effectiveDate: '2027-2028 (estimado)',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Anexo I - Parte I',
        title: 'Seguridad desde el Diseño (Security by Design)',
        description: 'Productos sin vulnerabilidades conocidas, configuración segura por defecto, reducción superficie ataque',
        literal: 'Los productos con elementos digitales se diseñarán, desarrollarán y producirán de forma que garanticen un nivel adecuado de ciberseguridad basado en los riesgos. Sin vulnerabilidades conocidas que puedan ser explotadas. Entregados sin contraseñas predeterminadas. Proteger datos adecuadamente. Minimizar superficie de ataque y impacto.',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: 'Anexo I - Parte II',
        title: 'Gestión de Vulnerabilidades durante todo el Ciclo de Vida',
        description: 'Identificar, documentar, resolver y divulgar vulnerabilidades. Actualizaciones de seguridad durante al menos 5 años o vida útil del producto',
        literal: 'Los fabricantes identificarán y documentarán las vulnerabilidades y componentes, incluidas las dependencias de código abierto. Tratarán y resolverán eficazmente las vulnerabilidades sin demora. Aplicarán mecanismos de divulgación responsable. Proporcionarán actualizaciones de seguridad durante al menos 5 años desde introducción en mercado o durante vida útil esperada.',
        ssdlcPhases: ['development', 'testing', 'deployment', 'operations', 'monitoring']
      },
      {
        article: 'Art. 11',
        title: 'Reporte de Vulnerabilidades Explotadas Activamente',
        description: 'Notificar vulnerabilidades explotadas activamente a ENISA en 24 horas',
        literal: 'Los fabricantes notificarán a ENISA, sin dilación indebida y, en cualquier caso, en un plazo de 24 horas tras tener conocimiento, cualquier vulnerabilidad explotada activamente de un producto con elementos digitales que haya introducido en el mercado.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'Anexo II',
        title: 'Marcado CE y Declaración de Conformidad UE',
        description: 'Evaluación de conformidad (autoevaluación o tercera parte según clase), marcado CE obligatorio',
        literal: 'Los productos con elementos digitales que cumplan los requisitos esenciales llevarán el marcado CE. Los fabricantes de productos Clase I (críticos) deberán someterse a evaluación de conformidad por organismo notificado. Clase II (importantes) también requieren evaluación por terceros. Productos no críticos: autoevaluación.',
        ssdlcPhases: ['testing', 'deployment']
      }
    ],
    penalties: 'Hasta €15M o 2,5% facturación mundial anual (mayor). Prohibición comercialización. Retirada productos. Publicación infracciones.',
    certificationRequired: true,
    references: {
      official: 'https://www.europarl.europa.eu/doceo/document/TA-9-2024-0130_EN.html',
      guidelines: [
        'https://www.enisa.europa.eu/topics/cybersecurity-policy/cyber-resilience-act',
        'https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act'
      ],
      tools: [
        'SBOM (Software Bill of Materials) - SPDX, CycloneDX',
        'Dependabot, Snyk, WhiteSource',
        'OWASP Dependency-Check',
        'Trivy, Grype'
      ]
    },
    relatedStandards: ['ETSI EN 303 645 (IoT)', 'IEC 62443', 'ISO 27034', 'NIST SSDF']
  },

  'ai-act': {
    id: 'ai-act',
    name: 'EU AI Act',
    fullName: 'Reglamento de Inteligencia Artificial de la UE',
    category: 'ai' as const,
    jurisdiction: ['EU'],
    description: 'Primera regulación integral del mundo sobre IA. Clasifica sistemas IA según nivel de riesgo (inaceptable, alto, limitado, mínimo) y establece obligaciones específicas.',
    purpose: 'Garantizar que los sistemas de IA comercializados en la UE sean seguros, transparentes, trazables, no discriminatorios y ambientalmente sostenibles',
    applicability: [
      'Proveedores de sistemas IA de alto riesgo',
      'IA en infraestructuras críticas',
      'IA en educación y formación profesional',
      'IA en empleo, gestión trabajadores',
      'IA en servicios públicos y privados esenciales',
      'IA en aplicación de la ley',
      'IA de uso general (GPAI) como LLMs'
    ],
    effectiveDate: '2024-2026 (entrada gradual)',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Art. 5',
        title: 'Prácticas de IA Prohibidas (Riesgo Inaceptable)',
        description: 'Manipulación subliminal, social scoring, identificación biométrica remota en tiempo real (con excepciones)',
        literal: 'Se prohibirán las siguientes prácticas de inteligencia artificial: a) comercialización, puesta en servicio o utilización de sistemas de IA que desplieguen técnicas subliminales más allá de la consciencia de una persona; b) sistemas que exploten vulnerabilidades relacionadas con edad, discapacidad; c) evaluación o clasificación de personas por autoridades públicas basada en social scoring; d) uso de sistemas de identificación biométrica remota en tiempo real en espacios públicos por autoridades (salvo excepciones).',
        ssdlcPhases: ['requirements', 'design']
      },
      {
        article: 'Art. 9-15',
        title: 'Requisitos para Sistemas IA de Alto Riesgo',
        description: 'Gestión riesgos, calidad datos, documentación técnica, transparencia, supervisión humana, ciberseguridad',
        literal: 'Los sistemas de IA de alto riesgo se diseñarán y desarrollarán de manera que alcancen un nivel adecuado de exactitud, robustez y ciberseguridad. Sistema de gestión de riesgos durante todo el ciclo de vida. Datos de entrenamiento, validación y prueba de alta calidad. Documentación técnica completa. Trazabilidad mediante registro automático de eventos (logs). Transparencia para usuarios. Diseño que permita supervisión humana efectiva. Robustez, exactitud y ciberseguridad.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'operations', 'monitoring']
      },
      {
        article: 'Art. 52',
        title: 'Obligaciones de Transparencia',
        description: 'Informar cuando interactúan con IA, etiquetado de deepfakes y contenido generado por IA',
        literal: 'Los proveedores garantizarán que los sistemas de IA destinados a interactuar con personas físicas se diseñen y desarrollen de tal manera que las personas sean informadas de que están interactuando con un sistema de IA. Contenido de audio, imagen, vídeo o texto generado o manipulado por IA que se parezca a personas, objetos, lugares existentes se etiquetará de forma clara y perceptible como generado o manipulado artificialmente.',
        ssdlcPhases: ['design', 'development', 'deployment']
      },
      {
        article: 'Anexo IV',
        title: 'Documentación Técnica',
        description: 'Descripción detallada del sistema IA, datos de entrenamiento, validación, arquitectura, métricas rendimiento',
        literal: 'La documentación técnica incluirá: descripción general del sistema IA y uso previsto; descripción detallada de elementos del sistema y proceso de desarrollo; descripción completa de conjuntos de datos de entrenamiento, validación y prueba; metodología y técnicas de evaluación; información sobre arquitectura computacional y lógica. Métricas utilizadas para medir exactitud, robustez, ciberseguridad.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing']
      }
    ],
    penalties: 'Hasta €35M o 7% facturación (prácticas prohibidas), €15M o 3% (sistemas alto riesgo), €7,5M o 1,5% (obligaciones información)',
    certificationRequired: true,
    references: {
      official: 'https://artificialintelligenceact.eu/',
      guidelines: [
        'https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai',
        'https://www.europarl.europa.eu/topics/en/article/20230601STO93804/eu-ai-act-first-regulation-on-artificial-intelligence'
      ],
      tools: [
        'AI Risk Assessment Tools',
        'MLflow (model tracking)',
        'DVC (Data Version Control)',
        'Fairness toolkits (AI Fairness 360, What-If Tool)',
        'Model Cards, Data Cards'
      ]
    },
    relatedStandards: ['ISO/IEC 42001 (AI Management)', 'ISO/IEC 23894 (AI Risk Management)', 'NIST AI RMF']
  },

  // ========================================
  // 2. MARCO REGULATORIO ESPAÑOL
  // ========================================

  'ens': {
    id: 'ens',
    name: 'ENS',
    fullName: 'Esquema Nacional de Seguridad - RD 311/2022',
    category: 'spanish' as const,
    jurisdiction: ['España'],
    description: 'Marco regulatorio de seguridad TIC para el Sector Público español y empresas que suministran servicios/soluciones. Clasifica sistemas según niveles (Bajo, Medio, Alto).',
    purpose: 'Crear condiciones de confianza en uso de medios electrónicos, estableciendo política de seguridad en utilización de medios electrónicos',
    applicability: [
      'Administraciones Públicas (AGE, CCAA, EELL)',
      'Empresas privadas que prestan servicios a AAPP',
      'Proveedores de soluciones tecnológicas al sector público',
      'Entidades que manejan información pública'
    ],
    effectiveDate: '2022-05-05',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Anexo II - mp.sw.1',
        title: 'Desarrollo de Aplicaciones',
        description: 'El desarrollo de aplicaciones se realizará siguiendo metodología formal que minimice número de problemas de seguridad',
        literal: 'El desarrollo de aplicaciones se realizará mediante una metodología que permita: definir formalmente los requisitos del sistema, realizar el análisis de riesgos, especificar fases desarrollo, realizar pruebas de seguridad, planificar el mantenimiento, registrar los cambios. Se utilizarán entornos de desarrollo, pruebas y explotación separados.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing']
      },
      {
        article: 'Anexo II - mp.sw.2',
        title: 'Aceptación y Puesta en Servicio',
        description: 'Realizar pruebas de seguridad previas a la puesta en producción',
        literal: 'Antes de pasar a producción se verificará que se cumplen las especificaciones de seguridad y se comprobará que no existen puertas traseras. Se realizarán pruebas de funcionalidad en un entorno de pruebas separado. Se documentarán las configuraciones de seguridad.',
        ssdlcPhases: ['testing', 'deployment']
      },
      {
        article: 'Anexo II - op.pl.4',
        title: 'Registro de Actividad',
        description: 'Registro y conservación de logs para permitir detección, análisis e investigación de incidentes',
        literal: 'Los sistemas de información llevarán un registro de actividad que permita conocer en todo momento quién accedió a qué información, cuándo y desde dónde. Los registros contendrán fecha y hora, identidad usuario, tipo de evento, éxito o fracaso. Conservación mínima según nivel del sistema.',
        ssdlcPhases: ['development', 'operations', 'monitoring']
      },
      {
        article: 'Anexo II - op.exp.8',
        title: 'Gestión de Vulnerabilidades',
        description: 'Identificación, evaluación, tratamiento de vulnerabilidades de forma sistemática',
        literal: 'Se establecerá un proceso de gestión de vulnerabilidades que incluya: identificación mediante herramientas automáticas, análisis del riesgo que suponen, priorización del tratamiento, aplicación de parches y actualizaciones, verificación de la corrección. El tiempo de reacción dependerá del nivel del sistema y criticidad de la vulnerabilidad.',
        ssdlcPhases: ['operations', 'monitoring']
      }
    ],
    penalties: 'Régimen sancionador Ley 40/2015 LRJSP. Infracciones graves y muy graves.',
    certificationRequired: true,
    references: {
      official: 'https://www.ccn-cert.cni.es/es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad.html',
      guidelines: [
        'https://www.ccn-cert.cni.es/guias-de-acceso-publico-ccn-stic/1217-ccn-stic-800-esquema-nacional-de-seguridad.html',
        'https://www.ccn-cert.cni.es/guias-de-acceso-publico-ccn-stic.html'
      ],
      tools: [
        'CCN-STIC 800 Series (guías técnicas)',
        'PILAR (herramienta análisis riesgos CCN)',
        'INES (Índice Nacional de Ciberseguridad)'
      ]
    },
    relatedStandards: ['ISO 27001', 'ISO 27002', 'NIST 800-53', 'CCN-STIC series']
  },

  'ccn-stic': {
    id: 'ccn-stic',
    name: 'CCN-STIC',
    fullName: 'Guías de Seguridad CCN-STIC del Centro Criptológico Nacional',
    category: 'spanish' as const,
    jurisdiction: ['España'],
    description: 'Serie de guías técnicas y procedimientos de seguridad TIC desarrolladas por el CCN-CERT. Implementan y desarrollan el ENS.',
    purpose: 'Proporcionar guías técnicas detalladas para implementación de medidas de seguridad en sistemas de información',
    applicability: [
      'Administraciones Públicas españolas',
      'Organismos públicos',
      'Empresas proveedoras de AAPP',
      'Infraestructuras críticas nacionales'
    ],
    effectiveDate: 'Continua (actualizaciones regulares)',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'CCN-STIC-817',
        title: 'Esquema Nacional de Seguridad - Gestión de Ciberincidentes',
        description: 'Procedimientos de gestión y notificación de incidentes de seguridad',
        literal: 'Se define el proceso de gestión de incidentes: detección y registro, clasificación y priorización, investigación y diagnóstico, contención y erradicación, recuperación, seguimiento, cierre y lecciones aprendidas. Obligación de notificación al CCN-CERT de incidentes significativos en plazos definidos.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'CCN-STIC-821',
        title: 'Esquema Nacional de Seguridad - Auditoría',
        description: 'Realización de auditorías periódicas de seguridad según nivel del sistema',
        literal: 'Se establecen criterios y procedimientos de auditoría para verificar cumplimiento del ENS. Nivel BAJO: autoauditoría bienal. Nivel MEDIO: auditoría externa bienal. Nivel ALTO: auditoría externa anual. Alcance mínimo: organización e implantación, análisis riesgos, gestión personal, profesionales externos, acceso información, arquitectura equipamiento, adquisición, gestión configuración.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'CCN-STIC-840',
        title: 'Guía de Desarrollo Seguro',
        description: 'Metodología y mejores prácticas para desarrollo seguro de aplicaciones',
        literal: 'Se establecen requisitos de seguridad en todas las fases: formación de desarrolladores, definición de requisitos de seguridad, análisis de amenazas (threat modeling), diseño seguro, codificación segura (OWASP), revisión código estático/dinámico (SAST/DAST), pruebas de penetración, gestión de dependencias, despliegue seguro, documentación de seguridad.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'deployment']
      },
      {
        article: 'CCN-STIC-883',
        title: 'Certificación de Seguridad de las TIC',
        description: 'Procedimiento de certificación de productos y servicios TIC',
        literal: 'Define el proceso de certificación de seguridad: solicitud, evaluación técnica por laboratorio acreditado, auditoría por organismo certificación, emisión certificado. Catálogo de productos certificados. Renovación periódica obligatoria.',
        ssdlcPhases: ['testing', 'deployment']
      }
    ],
    penalties: 'Vinculado al ENS - Infracciones administrativas',
    certificationRequired: true,
    references: {
      official: 'https://www.ccn-cert.cni.es/guias-de-acceso-publico-ccn-stic.html',
      guidelines: [
        'https://www.ccn-cert.cni.es/es/series-ccn-stic/800-guia-esquema-nacional-de-seguridad.html',
        'https://www.ccn-cert.cni.es/publico/seriesCCN-STIC/series/'
      ],
      tools: [
        'PILAR (Análisis de riesgos)',
        'INES (Informe Nacional Estado Seguridad)',
        'CLAUDIA (logs y evidencias)'
      ]
    },
    relatedStandards: ['ENS', 'ISO 27001', 'Common Criteria', 'NIST 800-53']
  },

  // ========================================
  // 3. ESTÁNDARES INTERNACIONALES ESPECÍFICOS
  // ========================================

  'iso27034': {
    id: 'iso27034',
    name: 'ISO 27034',
    fullName: 'ISO/IEC 27034 - Application Security',
    category: 'security' as const,
    jurisdiction: ['International'],
    description: 'Estándar internacional específico para seguridad en el ciclo de vida de desarrollo de aplicaciones',
    purpose: 'Proporcionar guidance para integrar seguridad en el proceso de desarrollo de aplicaciones',
    applicability: [
      'Desarrolladores de software',
      'Organizaciones que desarrollan aplicaciones críticas',
      'Equipos DevSecOps',
      'Auditores de seguridad de aplicaciones'
    ],
    effectiveDate: '2011 (última actualización)',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'Part 1 - Clause 7',
        title: 'Organizational Normative Framework (ONF)',
        description: 'Marco normativo organizacional que define políticas, procesos y controles de seguridad de aplicaciones',
        literal: 'The ONF contains the set of business and technical policies, processes, and practices that define how application security is managed within an organization. It provides a repository of Application Security Controls (ASCs), best practices, and standardized ways of implementing security throughout the application lifecycle.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'deployment', 'operations']
      },
      {
        article: 'Part 1 - Clause 8',
        title: 'Application Security Management Process',
        description: 'Proceso de gestión de seguridad de aplicaciones integrado en SDLC',
        literal: 'The Application Security Management Process specifies how to: identify security requirements based on business context, select and tailor Application Security Controls (ASCs) from the ONF, integrate security activities throughout SDLC phases, measure and report security posture, maintain continuous improvement.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'deployment', 'operations', 'monitoring']
      },
      {
        article: 'Part 1 - Clause 9',
        title: 'Application Security Controls (ASC)',
        description: 'Controles de seguridad específicos para aplicaciones (autenticación, autorización, validación input, etc.)',
        literal: 'ASCs are specific security measures implemented in applications. Examples: input validation controls, authentication and session management, access control mechanisms, cryptographic controls, error handling and logging, secure configuration management. Each ASC includes implementation guidance, verification procedures, and metrics.',
        ssdlcPhases: ['design', 'development', 'testing']
      },
      {
        article: 'Part 1 - Clause 10',
        title: 'Application Security Assurance',
        description: 'Verificación y validación continua de la seguridad de aplicaciones',
        literal: 'Security assurance activities include: threat modeling, security requirements verification, secure code review (SAST), dynamic testing (DAST), penetration testing, security regression testing, vulnerability management, security metrics and KPIs.',
        ssdlcPhases: ['testing', 'operations', 'monitoring']
      }
    ],
    penalties: 'N/A - Estándar voluntario',
    certificationRequired: false,
    references: {
      official: 'https://www.iso.org/standard/44378.html',
      guidelines: [
        'https://www.iso.org/obp/ui/#iso:std:iso-iec:27034:-1:ed-1:v1:en',
        'OWASP SAMM (complementario)',
        'NIST SSDF (complementario)'
      ],
      tools: [
        'OWASP ASVS',
        'OWASP SAMM',
        'Secure SDLC frameworks'
      ]
    },
    relatedStandards: ['ISO 27001', 'ISO 27002', 'OWASP ASVS', 'NIST SSDF', 'BSIMM']
  },

  'iso62443': {
    id: 'iso62443',
    name: 'IEC 62443',
    fullName: 'IEC 62443 - Industrial Automation and Control Systems Security',
    category: 'industrial' as const,
    jurisdiction: ['International'],
    description: 'Estándar de oro para ciberseguridad en entornos industriales (OT), sistemas de control (ICS/SCADA) e Industria 4.0',
    purpose: 'Proteger sistemas de automatización y control industrial contra amenazas cibernéticas',
    applicability: [
      'Industria manufacturera (OT)',
      'Sistemas SCADA',
      'Infraestructuras críticas (energía, agua, transporte)',
      'Industria 4.0',
      'Fabricantes de dispositivos ICS',
      'Integradores de sistemas'
    ],
    effectiveDate: 'Serie completa (2009-2024)',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: '62443-4-1',
        title: 'Secure Product Development Lifecycle Requirements',
        description: 'Requisitos de ciclo de vida de desarrollo seguro para productos ICS',
        literal: 'Product suppliers shall establish and maintain a secure development lifecycle that includes: security requirements specification, secure design principles (defense in depth, least privilege), security testing and validation, vulnerability management, security documentation, security update management. Mandatory practices include threat modeling, security code review, penetration testing.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'deployment', 'operations']
      },
      {
        article: '62443-3-3',
        title: 'System Security Requirements and Security Levels',
        description: 'Requisitos técnicos de seguridad organizados en 7 fundamentos y 4 niveles de seguridad (SL 1-4)',
        literal: 'Technical security requirements organized in 7 foundational requirements (FRs): Identification and Authentication Control (IAC), Use Control (UC), System Integrity (SI), Data Confidentiality (DC), Restricted Data Flow (RDF), Timely Response to Events (TRE), Resource Availability (RA). Four Security Levels: SL 1 (protection against casual violation), SL 2 (intentional using simple means), SL 3 (sophisticated means with moderate resources), SL 4 (extended resources and skills).',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: '62443-2-4',
        title: 'Security Program Requirements for IACS Service Providers',
        description: 'Requisitos de programa de seguridad para integradores y proveedores de servicios',
        literal: 'Service providers (integrators, maintenance providers) shall implement: security management system, risk assessment methodology, secure integration practices, security testing procedures, incident response capabilities, security awareness training, documentation and change management, supply chain security requirements.',
        ssdlcPhases: ['requirements', 'design', 'deployment', 'operations']
      },
      {
        article: '62443-4-2',
        title: 'Technical Security Requirements for IACS Components',
        description: 'Requisitos técnicos para componentes individuales (PLCs, HMIs, sensores)',
        literal: 'Components shall implement: software application security, security for embedded devices, network and security services, secure communication, authentication and authorization mechanisms, security event logging, update and patch management. Protection against injection attacks, buffer overflows, denial of service.',
        ssdlcPhases: ['design', 'development', 'testing']
      }
    ],
    penalties: 'N/A - Estándar voluntario (puede ser requisito contractual o regulatorio sectorial)',
    certificationRequired: true,
    references: {
      official: 'https://www.isa.org/standards-and-publications/isa-standards/isa-iec-62443-series-of-standards',
      guidelines: [
        'https://www.iec.ch/cyber-security',
        'https://www.isa.org/training-and-certifications/isa-certification/isa99iec-62443-cybersecurity-certificate-programs'
      ],
      tools: [
        'Nozomi Networks',
        'Claroty',
        'Dragos Platform',
        'Tenable.ot',
        'Armis'
      ]
    },
    relatedStandards: ['NIST 800-82', 'ISO 27001', 'NIS2', 'CRA']
  },

  'iso21434': {
    id: 'iso21434',
    name: 'ISO 21434',
    fullName: 'ISO/SAE 21434:2021 - Road Vehicles Cybersecurity Engineering',
    category: 'automotive' as const,
    jurisdiction: ['International'],
    description: 'Estándar de ciberseguridad para vehículos de carretera. Define requisitos de gestión de riesgos cibernéticos durante todo el ciclo de vida del vehículo.',
    purpose: 'Garantizar la ciberseguridad en el diseño, producción y operación de vehículos conectados y autónomos',
    applicability: [
      'Fabricantes de automóviles (OEMs)',
      'Proveedores de componentes automotrices (Tier 1, Tier 2)',
      'Desarrolladores de software embebido vehicular',
      'Proveedores de servicios conectados (V2X, OTA)',
      'Vehículos autónomos y conectados'
    ],
    effectiveDate: '2021-08',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'Clause 5',
        title: 'Organizational Cybersecurity Management',
        description: 'Sistema de gestión de ciberseguridad organizacional',
        literal: 'Organizations shall establish, document, implement and maintain a cybersecurity management system. This includes: cybersecurity culture and awareness, competence management, information sharing (vulnerability disclosure, threat intelligence), cybersecurity event management, cybersecurity governance structure, resource allocation.',
        ssdlcPhases: ['requirements', 'design', 'development', 'operations', 'monitoring']
      },
      {
        article: 'Clause 8',
        title: 'Continuous Cybersecurity Activities',
        description: 'Monitorización continua, gestión de vulnerabilidades, incidentes y actualizaciones',
        literal: 'Throughout the operational phase: cybersecurity monitoring of threats and vulnerabilities, cybersecurity event response, updates and patches management (OTA), end-of-cybersecurity support planning, decommissioning procedures. Field monitoring and vulnerability scanning. Incident response within defined timeframes.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'Clause 9',
        title: 'Threat Analysis and Risk Assessment (TARA)',
        description: 'Análisis de amenazas y evaluación de riesgos específico para vehículos',
        literal: 'TARA methodology includes: asset identification (vehicle functions, data, interfaces), threat scenario identification (STRIDE, attack trees), impact rating (safety, financial, operational, privacy), attack path analysis, attack feasibility rating, risk determination, risk treatment decisions. Iterative process throughout development.',
        ssdlcPhases: ['requirements', 'design']
      },
      {
        article: 'Clause 10',
        title: 'Cybersecurity Concept and Requirements',
        description: 'Definición de arquitectura de seguridad y requisitos técnicos',
        literal: 'Cybersecurity concept shall specify: security architecture, cybersecurity goals derived from TARA, cybersecurity requirements (secure communication, authentication, access control, intrusion detection, logging, secure boot, secure OTA updates), cybersecurity claims for validation. Requirements traceability to design and implementation.',
        ssdlcPhases: ['requirements', 'design', 'development']
      }
    ],
    penalties: 'N/A - Estándar voluntario (puede ser requisito regulatorio nacional, ej. UNECE WP.29)',
    certificationRequired: true,
    references: {
      official: 'https://www.iso.org/standard/70918.html',
      guidelines: [
        'https://unece.org/transport/vehicle-regulations/wp29-regulations/world-forum-documents',
        'https://www.automotiveisac.com/'
      ],
      tools: [
        'Threat modeling tools (Microsoft Threat Modeling Tool)',
        'CANalyzer Security',
        'Vector vTESTstudio',
        'Argus Cyber Security'
      ]
    },
    relatedStandards: ['UNECE WP.29 R155/R156', 'ISO 26262 (Safety)', 'SAE J3061']
  },

  'iec81001': {
    id: 'iec81001',
    name: 'IEC 81001-5-1',
    fullName: 'IEC 81001-5-1 - Health Software and Health IT Systems Safety, Effectiveness and Security',
    category: 'healthcare' as const,
    jurisdiction: ['International'],
    description: 'Estándar de seguridad, eficacia y protección para software de salud y dispositivos médicos con software',
    purpose: 'Garantizar la seguridad cibernética de software médico durante todo su ciclo de vida',
    applicability: [
      'Fabricantes de dispositivos médicos',
      'Desarrolladores de software de salud (SaMD - Software as Medical Device)',
      'Sistemas de información hospitalaria (HIS, EMR)',
      'Aplicaciones de telemedicina',
      'Wearables y dispositivos IoMT'
    ],
    effectiveDate: '2021',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'Clause 7',
        title: 'Security Risk Management Process',
        description: 'Proceso de gestión de riesgos de seguridad específico para software de salud',
        literal: 'Manufacturers shall establish security risk management process: identification of assets and security properties (confidentiality, integrity, availability of patient data and device function), threat modeling, vulnerability analysis, security risk evaluation considering patient safety impact, security controls specification, residual risk evaluation. Integration with ISO 14971 (medical device risk management).',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'operations']
      },
      {
        article: 'Clause 9',
        title: 'Security by Design',
        description: 'Principios de diseño seguro para software médico',
        literal: 'Security shall be integrated into design: defense in depth, least privilege, secure defaults, fail-safe, minimize attack surface, isolation/segregation, authentication and authorization, cryptographic protection of data at rest and in transit, audit logging, secure communication protocols, input validation, protection against common vulnerabilities (OWASP).',
        ssdlcPhases: ['design', 'development']
      },
      {
        article: 'Clause 10',
        title: 'Security Testing and Validation',
        description: 'Pruebas de seguridad obligatorias antes de lanzamiento',
        literal: 'Security verification and validation activities include: vulnerability scanning, penetration testing by qualified testers, fuzz testing, security code review, validation of security controls effectiveness, testing of security updates and patches. Documentation of test results and remediation.',
        ssdlcPhases: ['testing']
      },
      {
        article: 'Clause 11',
        title: 'Post-Market Security Management',
        description: 'Vigilancia de seguridad post-comercialización, gestión de vulnerabilidades y actualizaciones',
        literal: 'Manufacturers shall monitor security threats and vulnerabilities, participate in information sharing (ISAO, ICS-CERT), coordinate vulnerability disclosure, provide security updates throughout product lifecycle, maintain cybersecurity bill of materials (CBOM), report security incidents to authorities, plan for end-of-support.',
        ssdlcPhases: ['operations', 'monitoring']
      }
    ],
    penalties: 'N/A - Regulaciones nacionales (FDA, MDR EU) pueden requerir cumplimiento',
    certificationRequired: true,
    references: {
      official: 'https://www.iec.ch/homepage',
      guidelines: [
        'https://www.fda.gov/medical-devices/digital-health-center-excellence/cybersecurity',
        'https://www.fda.gov/regulatory-information/search-fda-guidance-documents/cybersecurity-medical-devices-quality-system-considerations-and-content-premarket-submissions'
      ],
      tools: [
        'NIST Cybersecurity Framework',
        'MITRE ATT&CK for ICS',
        'FDA Pre-market Cybersecurity Guidance',
        'Medical Device SBOM'
      ]
    },
    relatedStandards: ['ISO 14971', 'IEC 62304', 'HIPAA', 'GDPR', 'FDA Guidance']
  }
};

// Combinar todas las normativas
export const getAllRegulations = () => {
  // Esta función se exportará para ser usada en conjunto con regulations.ts
  return additionalRegulationsData;
};

// Exportar categorías extendidas
export const regulationCategories = [
  'privacy',
  'security',
  'financial',
  'healthcare',
  'european',
  'spanish',
  'industrial',
  'automotive',
  'ai',
  'general'
] as const;

export type RegulationCategory = typeof regulationCategories[number];
