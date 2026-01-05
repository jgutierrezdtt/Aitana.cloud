// Base de datos completa de normativas y regulaciones
// Incluye marco regulatorio Europeo, Español, Internacional y Sectorial

export interface Regulation {
  id: string;
  name: string;
  fullName: string;
  category: 'privacy' | 'security' | 'financial' | 'healthcare' | 'general' | 'european' | 'spanish' | 'industrial' | 'automotive' | 'ai';
  jurisdiction: string[];
  description: string;
  purpose: string;
  applicability: string[];
  effectiveDate?: string;
  mandatoryCompliance: boolean;
  keyRequirements: {
    article: string;
    title: string;
    description: string;
    literal: string;
    ssdlcPhases: string[];
  }[];
  penalties: string;
  certificationRequired: boolean;
  references: {
    official: string;
    guidelines: string[];
    tools: string[];
  };
  relatedStandards: string[];
}

export const regulationsData: Record<string, Regulation> = {
  'gdpr': {
    id: 'gdpr',
    name: 'GDPR',
    fullName: 'General Data Protection Regulation',
    category: 'privacy',
    jurisdiction: ['EU', 'EEA'],
    description: 'Regulación de la UE sobre protección de datos y privacidad para individuos dentro de la Unión Europea y el Espacio Económico Europeo',
    purpose: 'Dar control a los ciudadanos sobre sus datos personales y simplificar el entorno regulatorio para negocios internacionales',
    applicability: [
      'Organizaciones que procesan datos de residentes UE',
      'Empresas establecidas en la UE que procesan datos personales',
      'Procesadores de datos fuera de la UE que ofrecen servicios a residentes UE'
    ],
    effectiveDate: '2018-05-25',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Art. 25',
        title: 'Data Protection by Design and by Default',
        description: 'Implementar medidas técnicas y organizativas apropiadas para protección de datos desde el diseño',
        literal: 'El responsable del tratamiento aplicará, tanto en el momento de determinar los medios de tratamiento como en el momento del propio tratamiento, medidas técnicas y organizativas apropiadas, como la seudonimización, concebidas para aplicar de forma efectiva los principios de protección de datos.',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: 'Art. 32',
        title: 'Security of Processing',
        description: 'Implementar medidas técnicas y organizativas apropiadas para garantizar nivel de seguridad adecuado al riesgo',
        literal: 'El responsable y el encargado del tratamiento aplicarán medidas técnicas y organizativas apropiadas para garantizar un nivel de seguridad adecuado al riesgo, que en su caso incluya, entre otros: a) la seudonimización y el cifrado de datos personales; b) la capacidad de garantizar la confidencialidad, integridad, disponibilidad y resiliencia permanentes de los sistemas y servicios de tratamiento.',
        ssdlcPhases: ['design', 'development', 'testing', 'operations']
      },
      {
        article: 'Art. 33',
        title: 'Notification of Personal Data Breach',
        description: 'Notificar violaciones de datos a la autoridad supervisora en 72 horas',
        literal: 'En caso de violación de la seguridad de los datos personales, el responsable del tratamiento la notificará a la autoridad de control competente sin dilación indebida y, de ser posible, a más tardar 72 horas después de que haya tenido constancia de ella.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'Art. 35',
        title: 'Data Protection Impact Assessment',
        description: 'Realizar evaluación de impacto cuando el tratamiento entrañe alto riesgo para derechos y libertades',
        literal: 'Cuando sea probable que un tipo de tratamiento, en particular si utiliza nuevas tecnologías, entrañe un alto riesgo para los derechos y libertades de las personas físicas, el responsable del tratamiento realizará, antes del tratamiento, una evaluación del impacto de las operaciones de tratamiento en la protección de datos personales.',
        ssdlcPhases: ['requirements', 'design']
      }
    ],
    penalties: 'Hasta €20 millones o 4% de la facturación anual global, lo que sea mayor',
    certificationRequired: false,
    references: {
      official: 'https://gdpr.eu/tag/gdpr/',
      guidelines: [
        'https://edpb.europa.eu/our-work-tools/general-guidance/guidelines-recommendations-best-practices_en',
        'https://ico.org.uk/for-organisations/guide-to-data-protection/guide-to-the-general-data-protection-regulation-gdpr/'
      ],
      tools: [
        'OneTrust Privacy Management',
        'TrustArc Privacy Platform',
        'Osano Consent Management'
      ]
    },
    relatedStandards: ['ISO 27001', 'ISO 27701', 'SOC 2']
  },
  
  'iso27001': {
    id: 'iso27001',
    name: 'ISO 27001',
    fullName: 'ISO/IEC 27001:2022 Information Security Management',
    category: 'security',
    jurisdiction: ['International'],
    description: 'Estándar internacional para sistemas de gestión de seguridad de la información (ISMS)',
    purpose: 'Proporcionar requisitos para establecer, implementar, mantener y mejorar continuamente un ISMS',
    applicability: [
      'Organizaciones de cualquier tamaño e industria',
      'Empresas que manejan información sensible',
      'Proveedores de servicios tecnológicos'
    ],
    effectiveDate: '2022-10-25',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'A.8.2.1',
        title: 'Classification of Information',
        description: 'La información debe clasificarse según su valor, requisitos legales, sensibilidad y criticidad',
        literal: 'Information should be classified in terms of legal requirements, value, criticality and sensitivity to unauthorised disclosure or modification.',
        ssdlcPhases: ['requirements', 'design']
      },
      {
        article: 'A.14.1.2',
        title: 'Securing Application Services on Public Networks',
        description: 'Proteger información involucrada en servicios de aplicaciones sobre redes públicas',
        literal: 'Information involved in application services passing over public networks shall be protected from fraudulent activity, contract dispute and unauthorised disclosure and modification.',
        ssdlcPhases: ['design', 'development', 'deployment']
      },
      {
        article: 'A.14.2.1',
        title: 'Secure Development Policy',
        description: 'Establecer y aplicar reglas para el desarrollo de software y sistemas',
        literal: 'Rules for the development of software and systems shall be established and applied to developments within the organization.',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: 'A.14.2.8',
        title: 'System Security Testing',
        description: 'Pruebas de funcionalidad de seguridad durante el desarrollo',
        literal: 'Testing of security functionality shall be carried out during development.',
        ssdlcPhases: ['testing']
      }
    ],
    penalties: 'No hay multas legales, pero pérdida de certificación y reputación',
    certificationRequired: true,
    references: {
      official: 'https://www.iso.org/standard/27001',
      guidelines: [
        'https://www.iso.org/isoiec-27001-information-security.html',
        'https://www.itgovernance.co.uk/iso27001'
      ],
      tools: [
        'ISMS.online',
        'Vanta Compliance Automation',
        'Secureframe'
      ]
    },
    relatedStandards: ['ISO 27002', 'ISO 27017', 'ISO 27018', 'NIST CSF']
  },

  'pci-dss': {
    id: 'pci-dss',
    name: 'PCI-DSS',
    fullName: 'Payment Card Industry Data Security Standard v4.0',
    category: 'financial',
    jurisdiction: ['International'],
    description: 'Estándar de seguridad para organizaciones que manejan tarjetas de crédito de marcas principales',
    purpose: 'Proteger datos de tarjetas de pago y reducir fraude mediante controles de seguridad',
    applicability: [
      'Comerciantes que aceptan tarjetas de pago',
      'Procesadores de pagos',
      'Proveedores de servicios que almacenan, procesan o transmiten datos de tarjetas'
    ],
    effectiveDate: '2022-03-31',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: 'Req. 6.3.2',
        title: 'Security Code Reviews',
        description: 'Revisar código personalizado antes de liberar a producción',
        literal: 'Custom application code is reviewed prior to release to production or customers in order to identify any potential coding vulnerability.',
        ssdlcPhases: ['development', 'testing']
      },
      {
        article: 'Req. 6.5.1',
        title: 'Injection Flaws',
        description: 'Desarrollar aplicaciones protegidas contra inyección (SQL, LDAP, OS command)',
        literal: 'Injection flaws, particularly SQL injection. Also consider OS Command Injection, LDAP and XPath injection flaws as well as other injection flaws.',
        ssdlcPhases: ['design', 'development', 'testing']
      },
      {
        article: 'Req. 8.2',
        title: 'User Authentication',
        description: 'Asegurar que todos los usuarios estén autenticados mediante MFA',
        literal: 'In addition to assigning a unique ID, ensure proper user-authentication management for non-consumer users and administrators on all system components.',
        ssdlcPhases: ['requirements', 'design', 'development']
      },
      {
        article: 'Req. 10.1',
        title: 'Audit Trails',
        description: 'Implementar audit trails para vincular acceso a usuarios individuales',
        literal: 'Implement audit trails to link all access to system components to each individual user.',
        ssdlcPhases: ['development', 'deployment', 'operations']
      }
    ],
    penalties: 'Multas de $5,000 a $100,000 por mes, pérdida de capacidad de procesar pagos',
    certificationRequired: true,
    references: {
      official: 'https://www.pcisecuritystandards.org/',
      guidelines: [
        'https://docs-prv.pcisecuritystandards.org/PCI%20DSS/Standard/PCI-DSS-v4_0.pdf',
        'https://www.pcisecuritystandards.org/document_library/'
      ],
      tools: [
        'Qualys PCI Compliance',
        'Trustwave PCI Scanning',
        'SecurityMetrics PCI Tools'
      ]
    },
    relatedStandards: ['ISO 27001', 'NIST CSF', 'SOC 2']
  },

  'nist-800-53': {
    id: 'nist-800-53',
    name: 'NIST SP 800-53',
    fullName: 'NIST Special Publication 800-53 Rev. 5',
    category: 'security',
    jurisdiction: ['USA'],
    description: 'Catálogo de controles de seguridad y privacidad para sistemas de información federales',
    purpose: 'Proporcionar controles de seguridad para proteger operaciones, activos e individuos',
    applicability: [
      'Agencias federales de USA',
      'Contratistas del gobierno federal',
      'Organizaciones que buscan framework de seguridad robusto'
    ],
    effectiveDate: '2020-09-23',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'SI-10',
        title: 'Information Input Validation',
        description: 'Verificar validez de información de entrada',
        literal: 'Check the validity of the following information inputs: [Assignment: organization-defined information inputs to the system].',
        ssdlcPhases: ['design', 'development', 'testing']
      },
      {
        article: 'SA-11',
        title: 'Developer Testing and Evaluation',
        description: 'Requerir que desarrolladores creen y ejecuten planes de testing de seguridad',
        literal: 'Require the developer of the system, system component, or system service to create and implement a security and privacy test and evaluation plan.',
        ssdlcPhases: ['testing']
      },
      {
        article: 'AU-2',
        title: 'Event Logging',
        description: 'Identificar tipos de eventos que el sistema es capaz de auditar',
        literal: 'Identify the types of events that the system is capable of logging in support of the audit function.',
        ssdlcPhases: ['design', 'development', 'operations']
      },
      {
        article: 'RA-5',
        title: 'Vulnerability Monitoring and Scanning',
        description: 'Monitorear y escanear vulnerabilidades en el sistema',
        literal: 'Monitor and scan for vulnerabilities in the system and hosted applications.',
        ssdlcPhases: ['testing', 'operations', 'monitoring']
      }
    ],
    penalties: 'Pérdida de contratos federales, sanciones administrativas',
    certificationRequired: false,
    references: {
      official: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final',
      guidelines: [
        'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf',
        'https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search'
      ],
      tools: [
        'Xacta 360',
        'RSA Archer GRC',
        'ServiceNow GRC'
      ]
    },
    relatedStandards: ['NIST CSF', 'ISO 27001', 'FedRAMP']
  },

  'soc2': {
    id: 'soc2',
    name: 'SOC 2',
    fullName: 'Service Organization Control 2',
    category: 'security',
    jurisdiction: ['USA', 'International'],
    description: 'Marco de auditoría para proveedores de servicios que almacenan datos de clientes en la nube',
    purpose: 'Evaluar controles internos de una organización relevantes a seguridad, disponibilidad, integridad, confidencialidad y privacidad',
    applicability: [
      'Proveedores de servicios SaaS',
      'Empresas de cloud computing',
      'Data centers y hosting providers'
    ],
    effectiveDate: '2017 (última actualización Trust Services Criteria)',
    mandatoryCompliance: false,
    keyRequirements: [
      {
        article: 'CC6.1',
        title: 'Logical and Physical Access Controls',
        description: 'Implementar controles lógicos y físicos de acceso',
        literal: 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events to meet the entity\'s objectives.',
        ssdlcPhases: ['design', 'development', 'deployment', 'operations']
      },
      {
        article: 'CC6.6',
        title: 'Vulnerability Management',
        description: 'Identificar, reportar y actuar sobre vulnerabilidades de seguridad',
        literal: 'The entity identifies, reports, and acts upon identified security events and vulnerabilities to meet the entity\'s objectives.',
        ssdlcPhases: ['testing', 'deployment', 'operations', 'monitoring']
      },
      {
        article: 'CC7.2',
        title: 'System Monitoring',
        description: 'Monitorear sistema para detectar cambios que puedan indicar vulnerabilidades',
        literal: 'The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts, natural disasters, and errors affecting the entity\'s ability to meet its objectives.',
        ssdlcPhases: ['operations', 'monitoring']
      },
      {
        article: 'CC8.1',
        title: 'Change Management',
        description: 'Autorizar, diseñar, desarrollar, configurar, documentar, probar, aprobar e implementar cambios',
        literal: 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures to meet its objectives.',
        ssdlcPhases: ['requirements', 'design', 'development', 'testing', 'deployment']
      }
    ],
    penalties: 'Pérdida de clientes enterprise, daño reputacional, pérdida de contratos',
    certificationRequired: true,
    references: {
      official: 'https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/aicpasoc2report.html',
      guidelines: [
        'https://us.aicpa.org/content/dam/aicpa/interestareas/frc/assuranceadvisoryservices/downloadabledocuments/trust-services-criteria.pdf'
      ],
      tools: [
        'Vanta SOC 2 Automation',
        'Drata Compliance Platform',
        'Secureframe'
      ]
    },
    relatedStandards: ['ISO 27001', 'SOC 1', 'NIST CSF']
  },

  'hipaa': {
    id: 'hipaa',
    name: 'HIPAA',
    fullName: 'Health Insurance Portability and Accountability Act',
    category: 'healthcare',
    jurisdiction: ['USA'],
    description: 'Ley federal de USA que protege información médica sensible',
    purpose: 'Establecer estándares nacionales para proteger registros médicos y otra información de salud personal',
    applicability: [
      'Proveedores de salud',
      'Planes de salud',
      'Cámaras de compensación de salud',
      'Business Associates que manejan PHI'
    ],
    effectiveDate: '1996 (Security Rule: 2003)',
    mandatoryCompliance: true,
    keyRequirements: [
      {
        article: '164.308(a)(1)',
        title: 'Security Management Process',
        description: 'Implementar políticas y procedimientos para prevenir, detectar y contener violaciones de seguridad',
        literal: 'Implement policies and procedures to prevent, detect, contain, and correct security violations.',
        ssdlcPhases: ['requirements', 'design', 'operations']
      },
      {
        article: '164.312(a)(1)',
        title: 'Access Control',
        description: 'Implementar especificaciones técnicas para permitir acceso solo a personas autorizadas',
        literal: 'Implement technical policies and procedures for electronic information systems that maintain electronic protected health information to allow access only to those persons or software programs that have been granted access rights.',
        ssdlcPhases: ['design', 'development', 'deployment']
      },
      {
        article: '164.312(b)',
        title: 'Audit Controls',
        description: 'Implementar mecanismos de hardware, software y procedimientos para registrar y examinar actividad',
        literal: 'Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use electronic protected health information.',
        ssdlcPhases: ['development', 'operations', 'monitoring']
      },
      {
        article: '164.312(e)(1)',
        title: 'Transmission Security',
        description: 'Implementar medidas técnicas para proteger PHI transmitida por redes electrónicas',
        literal: 'Implement technical security measures to guard against unauthorized access to electronic protected health information that is being transmitted over an electronic communications network.',
        ssdlcPhases: ['design', 'development', 'deployment']
      }
    ],
    penalties: 'De $100 a $50,000 por violación, hasta $1.5M por año por violación idéntica',
    certificationRequired: false,
    references: {
      official: 'https://www.hhs.gov/hipaa/index.html',
      guidelines: [
        'https://www.hhs.gov/hipaa/for-professionals/security/guidance/index.html',
        'https://www.hhs.gov/sites/default/files/ocr/privacy/hipaa/administrative/securityrule/techsafeguards.pdf'
      ],
      tools: [
        'HIPAA Vault',
        'Compliancy Group',
        'Atlantic.Net HIPAA Hosting'
      ]
    },
    relatedStandards: ['HITRUST', 'ISO 27001', 'NIST 800-66']
  }
};

// Helper para obtener regulaciones por categoría
export const getRegulationsByCategory = (category: string) => {
  return Object.values(regulationsData).filter(reg => reg.category === category);
};

// Helper para obtener regulaciones por fase SSDLC
export const getRegulationsByPhase = (phase: string) => {
  return Object.values(regulationsData).filter(reg =>
    reg.keyRequirements.some(req => req.ssdlcPhases.includes(phase))
  );
};
