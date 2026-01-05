"use client";

import { useState, useEffect } from "react";
import Navigation from "@/components/Navigation";

interface ApiEndpoint {
  path: string;
  method: string;
  summary: string;
  description: string;
  parameters?: any[];
  responses?: any;
  tags?: string[];
}

export default function ApiDocsPage() {
  const [activeSection, setActiveSection] = useState("introduction");
  const [activeEndpoint, setActiveEndpoint] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [editableParams, setEditableParams] = useState<Record<string, Record<string, string>>>({});
  const [response, setResponse] = useState<{ endpoint: string; data: any; status: number } | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const getDefaultValue = (endpointPath: string, paramName: string, paramType: string): string => {
    const defaults: Record<string, Record<string, string>> = {
      "/api/lab/sqli": { 
        search: "admin' OR '1'='1" 
      },
      "/api/lab/xss": { 
        input: "<script>alert('XSS')</script>",
        reflect: "true"
      },
      "/api/lab/command-injection": { 
        cmd: "ls -la" 
      },
      "/api/lab/ssti": { 
        template: "{{7*7}}" 
      },
      "/api/lab/ldap": { 
        filter: "*)(uid=*))(|(uid=*" 
      },
      "/api/auth/login": { 
        email: "admin@aitana.cloud",
        password: "admin123"
      },
      "/api/auth/register": { 
        email: "test@aitana.cloud",
        password: "password123"
      },
      "/api/users/:id": { 
        id: "1" 
      },
      "/api/notes/:id": { 
        id: "1" 
      }
    };

    return defaults[endpointPath]?.[paramName] || (paramType === "file" ? "" : "example");
  };

  const endpoints: ApiEndpoint[] = [
    {
      path: "/api/lab/sqli",
      method: "GET",
      summary: "SQL Injection Lab",
      description: "Endpoint vulnerable a inyección SQL. Permite manipular queries SQL directamente.",
      tags: ["Injection", "Critical"],
      parameters: [
        { name: "search", type: "string", description: "Término de búsqueda vulnerable a SQL injection" }
      ],
      responses: {
        "200": "Resultados de la búsqueda",
        "500": "Error del servidor"
      }
    },
    {
      path: "/api/lab/xss",
      method: "GET",
      summary: "Cross-Site Scripting Lab",
      description: "Endpoint vulnerable a XSS. Refleja entrada del usuario sin sanitización.",
      tags: ["Injection", "High"],
      parameters: [
        { name: "input", type: "string", description: "Payload XSS a probar" },
        { name: "reflect", type: "boolean", description: "Si se debe reflejar la entrada" }
      ],
      responses: {
        "200": "Respuesta con payload reflejado",
        "400": "Solicitud incorrecta"
      }
    },
    {
      path: "/api/lab/command-injection",
      method: "GET",
      summary: "Command Injection Lab",
      description: "Ejecuta comandos del sistema operativo sin validación.",
      tags: ["Injection", "Critical"],
      parameters: [
        { name: "cmd", type: "string", description: "Comando del sistema a ejecutar" }
      ],
      responses: {
        "200": "Resultado de la ejecución del comando",
        "500": "Error de ejecución"
      }
    },
    {
      path: "/api/lab/xxe",
      method: "POST",
      summary: "XML External Entity Lab",
      description: "Procesa XML sin deshabilitar entidades externas.",
      tags: ["Injection", "High"],
      parameters: [
        { name: "xml", type: "string", description: "Contenido XML a procesar" }
      ],
      responses: {
        "200": "XML procesado",
        "400": "XML inválido"
      }
    },
    {
      path: "/api/lab/ldap",
      method: "GET",
      summary: "LDAP Injection Lab",
      description: "Construye consultas LDAP con entrada del usuario sin sanitización.",
      tags: ["Injection", "High"],
      parameters: [
        { name: "filter", type: "string", description: "Filtro LDAP vulnerable" }
      ],
      responses: {
        "200": "Resultados LDAP",
        "500": "Error LDAP"
      }
    },
    {
      path: "/api/lab/ssti",
      method: "GET",
      summary: "Server-Side Template Injection",
      description: "Renderiza plantillas con entrada del usuario sin sanitización.",
      tags: ["Injection", "Critical"],
      parameters: [
        { name: "template", type: "string", description: "Expresión de template a evaluar" }
      ],
      responses: {
        "200": "Template renderizado",
        "500": "Error de renderizado"
      }
    },
    {
      path: "/api/auth/login",
      method: "POST",
      summary: "Login de Usuario",
      description: "Autenticación con contraseñas en texto plano y JWT débil.",
      tags: ["Authentication", "Critical"],
      parameters: [
        { name: "email", type: "string", description: "Email del usuario" },
        { name: "password", type: "string", description: "Contraseña en texto plano" }
      ],
      responses: {
        "200": "Login exitoso con JWT",
        "401": "Credenciales inválidas"
      }
    },
    {
      path: "/api/auth/register",
      method: "POST",
      summary: "Registro de Usuario",
      description: "Crea usuario con contraseña almacenada en texto plano.",
      tags: ["Authentication", "Critical"],
      parameters: [
        { name: "email", type: "string", description: "Email del usuario" },
        { name: "password", type: "string", description: "Contraseña" }
      ],
      responses: {
        "201": "Usuario creado",
        "400": "Datos inválidos"
      }
    },
    {
      path: "/api/users",
      method: "GET",
      summary: "Listar Usuarios",
      description: "Expone datos sensibles de todos los usuarios sin autenticación.",
      tags: ["Data Exposure", "High"],
      responses: {
        "200": "Lista de usuarios con contraseñas expuestas"
      }
    },
    {
      path: "/api/users/:id",
      method: "GET",
      summary: "Obtener Usuario",
      description: "Accede a datos de usuario sin verificación de permisos (IDOR).",
      tags: ["Access Control", "High"],
      parameters: [
        { name: "id", type: "string", description: "ID del usuario" }
      ],
      responses: {
        "200": "Datos del usuario",
        "404": "Usuario no encontrado"
      }
    },
    {
      path: "/api/notes",
      method: "GET",
      summary: "Listar Notas",
      description: "Accede a notas de todos los usuarios sin autenticación.",
      tags: ["Access Control", "Critical"],
      responses: {
        "200": "Lista de notas de todos los usuarios"
      }
    },
    {
      path: "/api/notes/:id",
      method: "GET",
      summary: "Obtener Nota",
      description: "Accede a nota específica sin verificar propiedad (IDOR).",
      tags: ["Access Control", "Critical"],
      parameters: [
        { name: "id", type: "string", description: "ID de la nota" }
      ],
      responses: {
        "200": "Datos de la nota",
        "404": "Nota no encontrada"
      }
    },
    {
      path: "/api/system-info",
      method: "GET",
      summary: "Información del Sistema",
      description: "Expone configuración interna y versiones del servidor.",
      tags: ["Misconfiguration", "Medium"],
      responses: {
        "200": "Información del sistema expuesta"
      }
    },
    {
      path: "/api/env-status",
      method: "GET",
      summary: "Variables de Entorno",
      description: "Expone variables de entorno sensibles públicamente.",
      tags: ["Data Exposure", "High"],
      responses: {
        "200": "Variables de entorno"
      }
    },
    {
      path: "/api/upload",
      method: "POST",
      summary: "Subir Archivo",
      description: "Acepta archivos sin validación de tipo o contenido.",
      tags: ["File Upload", "High"],
      parameters: [
        { name: "file", type: "file", description: "Archivo a subir" }
      ],
      responses: {
        "200": "Archivo subido",
        "400": "Error de subida"
      }
    }
  ];

  const sections = [
    { id: "introduction", name: "Introducción", icon: "📖" },
    { id: "authentication", name: "Autenticación", icon: "🔐" },
    { id: "injection", name: "Inyección", icon: "💉" },
    { id: "access-control", name: "Control de Acceso", icon: "🚪" },
    { id: "data-exposure", name: "Exposición de Datos", icon: "📊" },
    { id: "misconfiguration", name: "Configuración", icon: "⚙️" },
    { id: "file-upload", name: "Subida de Archivos", icon: "📁" }
  ];

  const filteredEndpoints = endpoints.filter(endpoint =>
    endpoint.path.toLowerCase().includes(searchTerm.toLowerCase()) ||
    endpoint.summary.toLowerCase().includes(searchTerm.toLowerCase()) ||
    endpoint.description.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const groupedEndpoints = filteredEndpoints.reduce((acc, endpoint) => {
    const tag = endpoint.tags?.[0] || "Other";
    if (!acc[tag]) acc[tag] = [];
    acc[tag].push(endpoint);
    return acc;
  }, {} as Record<string, ApiEndpoint[]>);

  const getMethodColor = (method: string) => {
    switch (method.toUpperCase()) {
      case "GET": return "bg-blue-500/20 text-blue-300 border-blue-400/30";
      case "POST": return "bg-green-500/20 text-green-300 border-green-400/30";
      case "PUT": return "bg-yellow-500/20 text-yellow-300 border-yellow-400/30";
      case "DELETE": return "bg-red-500/20 text-red-300 border-red-400/30";
      default: return "bg-gray-500/20 text-gray-300 border-gray-400/30";
    }
  };

  const getSeverityColor = (tags?: string[]) => {
    const severity = tags?.[1];
    switch (severity) {
      case "Critical": return "bg-red-500/20 text-red-300 border-red-400/30";
      case "High": return "bg-orange-500/20 text-orange-300 border-orange-400/30";
      case "Medium": return "bg-yellow-500/20 text-yellow-300 border-yellow-400/30";
      default: return "bg-blue-500/20 text-blue-300 border-blue-400/30";
    }
  };

  const handleParamChange = (endpointPath: string, paramName: string, value: string) => {
    setEditableParams(prev => ({
      ...prev,
      [endpointPath]: {
        ...(prev[endpointPath] || {}),
        [paramName]: value
      }
    }));
  };

  const getParamValue = (endpointPath: string, paramName: string, paramType: string = "string") => {
    return editableParams[endpointPath]?.[paramName] || getDefaultValue(endpointPath, paramName, paramType);
  };

  const executeRequest = async (endpoint: ApiEndpoint) => {
    setIsLoading(true);
    setResponse(null);

    try {
      let url = endpoint.path;
      const params = editableParams[endpoint.path] || {};

      // Replace path parameters
      url = url.replace(/:id/g, params.id || "1");

      // Add query parameters for GET requests
      if (endpoint.method === "GET" && endpoint.parameters) {
        const queryParams = new URLSearchParams();
        endpoint.parameters.forEach(param => {
          if (!param.name.includes("id") || !url.includes("/")) {
            const value = params[param.name] || getDefaultValue(endpoint.path, param.name, param.type);
            queryParams.append(param.name, value);
          }
        });
        const queryString = queryParams.toString();
        if (queryString) {
          url += `?${queryString}`;
        }
      }

      const options: RequestInit = {
        method: endpoint.method,
        headers: {
          'Content-Type': 'application/json',
        },
      };

      // Add body for POST requests
      if (endpoint.method === "POST" && endpoint.parameters) {
        const body: Record<string, any> = {};
        endpoint.parameters.forEach(param => {
          body[param.name] = params[param.name] || getDefaultValue(endpoint.path, param.name, param.type);
        });
        options.body = JSON.stringify(body);
      }

      const res = await fetch(url, options);
      const data = await res.json();

      setResponse({
        endpoint: url,
        data,
        status: res.status
      });
    } catch (error: any) {
      setResponse({
        endpoint: endpoint.path,
        data: { error: error.message },
        status: 500
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900">
      <div className="absolute inset-0 z-0">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMzYjgyZjYiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHptMTAgMTBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHpNMjYgMzRjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHptMTAgMjBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0xMCAwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHptLTIwIDBjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00eiIvPjwvZz48L2c+PC9zdmc+')] opacity-20"></div>
      </div>

      <Navigation />

      <div className="relative z-10 max-w-7xl mx-auto px-6 py-12">
        {/* Header */}
        <div className="mb-12">
          <h1 className="text-6xl font-black mb-4 bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 bg-clip-text text-transparent">
            API Documentation
          </h1>
          <p className="text-xl text-blue-200/80 max-w-3xl">
            Documentación completa de la API vulnerable de Aitana Security Lab. Explora todos los endpoints y aprende sobre vulnerabilidades comunes.
          </p>
        </div>

        {/* Search */}
        <div className="mb-8">
          <div className="relative">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar endpoints..."
              className="w-full px-6 py-4 pl-14 bg-white/10 border border-white/20 rounded-2xl text-white placeholder-blue-300/50 focus:outline-none focus:border-blue-400 transition-colors"
            />
            <svg className="w-6 h-6 text-blue-300 absolute left-4 top-1/2 -translate-y-1/2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="sticky top-6 bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-6">
              <h3 className="text-blue-200 font-bold mb-4 text-sm uppercase tracking-wide">Secciones</h3>
              <nav className="space-y-2">
                {sections.map((section) => (
                  <button
                    key={section.id}
                    onClick={() => setActiveSection(section.id)}
                    className={`w-full text-left px-4 py-3 rounded-xl transition-all ${
                      activeSection === section.id
                        ? "bg-blue-500/20 text-blue-300 border border-blue-400/30"
                        : "text-blue-200/60 hover:bg-white/5 hover:text-blue-200"
                    }`}
                  >
                    <span className="mr-2">{section.icon}</span>
                    {section.name}
                  </button>
                ))}
              </nav>

              {/* Stats */}
              <div className="mt-8 pt-6 border-t border-white/10">
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-blue-200/60">Total Endpoints</span>
                    <span className="text-blue-300 font-bold">{endpoints.length}</span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-blue-200/60">Críticos</span>
                    <span className="text-red-400 font-bold">
                      {endpoints.filter(e => e.tags?.includes("Critical")).length}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-blue-200/60">Altos</span>
                    <span className="text-orange-400 font-bold">
                      {endpoints.filter(e => e.tags?.includes("High")).length}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3 space-y-8">
            {/* Introduction */}
            {activeSection === "introduction" && (
              <div className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-8">
                <h2 className="text-3xl font-bold text-white mb-4">Bienvenido a la API de Aitana</h2>
                <div className="prose prose-invert max-w-none">
                  <p className="text-blue-200/80 leading-relaxed mb-4">
                    Esta API está diseñada intencionalmente con vulnerabilidades para propósitos educativos. 
                    Cada endpoint demuestra una vulnerabilidad común de seguridad web.
                  </p>
                  
                  <div className="bg-red-500/10 border border-red-400/30 rounded-xl p-6 my-6">
                    <div className="flex items-start gap-3">
                      <svg className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                      </svg>
                      <div>
                        <h4 className="text-red-300 font-bold mb-2">Advertencia Importante</h4>
                        <p className="text-red-200/70 text-sm">
                          Esta aplicación es vulnerable por diseño. NO uses estas prácticas en producción. 
                          Solo para aprendizaje y testing en entornos controlados.
                        </p>
                      </div>
                    </div>
                  </div>

                  <h3 className="text-2xl font-bold text-white mt-8 mb-4">Características</h3>
                  <ul className="space-y-3 text-blue-200/80">
                    <li className="flex items-start gap-3">
                      <span className="text-blue-400 mt-1">✓</span>
                      <span>Endpoints RESTful con ejemplos de vulnerabilidades reales</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="text-blue-400 mt-1">✓</span>
                      <span>Documentación detallada de cada vulnerabilidad</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="text-blue-400 mt-1">✓</span>
                      <span>Ejemplos de payloads y exploits</span>
                    </li>
                    <li className="flex items-start gap-3">
                      <span className="text-blue-400 mt-1">✓</span>
                      <span>Respuestas JSON con información detallada</span>
                    </li>
                  </ul>

                  <h3 className="text-2xl font-bold text-white mt-8 mb-4">Comenzar</h3>
                  <p className="text-blue-200/80 leading-relaxed mb-4">
                    Usa el menú lateral para navegar por las diferentes categorías de vulnerabilidades. 
                    Cada endpoint incluye ejemplos de cómo explotarlo de forma segura en este entorno de laboratorio.
                  </p>

                  <div className="bg-blue-500/10 border border-blue-400/30 rounded-xl p-6 mt-6">
                    <h4 className="text-blue-300 font-bold mb-2">URL Base</h4>
                    <code className="text-sm text-green-400 bg-slate-900/50 px-4 py-2 rounded-lg block font-mono">
                      http://localhost:3000
                    </code>
                  </div>
                </div>
              </div>
            )}

            {/* Endpoints by Category */}
            {Object.entries(groupedEndpoints).map(([category, categoryEndpoints]) => (
              activeSection.toLowerCase() === category.toLowerCase() && (
                <div key={category} className="space-y-4">
                  {categoryEndpoints.map((endpoint, index) => (
                    <div
                      key={index}
                      className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl overflow-hidden hover:border-blue-400/30 transition-all"
                    >
                      <button
                        onClick={() => setActiveEndpoint(activeEndpoint === endpoint.path ? null : endpoint.path)}
                        className="w-full p-6 text-left"
                      >
                        <div className="flex items-start justify-between gap-4 mb-3">
                          <div className="flex items-center gap-3 flex-wrap">
                            <span className={`px-3 py-1 rounded-lg text-xs font-bold border ${getMethodColor(endpoint.method)}`}>
                              {endpoint.method}
                            </span>
                            <code className="text-blue-300 font-mono text-sm">{endpoint.path}</code>
                          </div>
                          {endpoint.tags && endpoint.tags[1] && (
                            <span className={`px-3 py-1 rounded-lg text-xs font-bold border ${getSeverityColor(endpoint.tags)}`}>
                              {endpoint.tags[1]}
                            </span>
                          )}
                        </div>
                        <h3 className="text-xl font-bold text-white mb-2">{endpoint.summary}</h3>
                        <p className="text-blue-200/60 text-sm">{endpoint.description}</p>
                      </button>

                      {activeEndpoint === endpoint.path && (
                        <div className="border-t border-white/10 p-6 bg-slate-900/30">
                          {/* Parameters */}
                          {endpoint.parameters && endpoint.parameters.length > 0 && (
                            <div className="mb-6">
                              <h4 className="text-blue-200 font-bold mb-3">Parámetros Editables</h4>
                              <div className="space-y-3">
                                {endpoint.parameters.map((param, idx) => (
                                  <div key={idx} className="bg-white/5 border border-white/10 rounded-lg p-4">
                                    <div className="flex items-center gap-3 mb-3">
                                      <code className="text-blue-300 font-mono text-sm">{param.name}</code>
                                      <span className="text-xs px-2 py-1 bg-purple-500/20 text-purple-300 border border-purple-400/30 rounded">
                                        {param.type}
                                      </span>
                                    </div>
                                    <p className="text-blue-200/60 text-sm mb-3">{param.description}</p>
                                    <input
                                      type="text"
                                      value={getParamValue(endpoint.path, param.name, param.type)}
                                      onChange={(e) => handleParamChange(endpoint.path, param.name, e.target.value)}
                                      placeholder={`Ingresa ${param.name}...`}
                                      className="w-full px-4 py-2 bg-slate-900/50 border border-white/20 rounded-lg text-white placeholder-blue-300/30 focus:outline-none focus:border-blue-400 transition-colors font-mono text-sm"
                                    />
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Responses */}
                          {endpoint.responses && (
                            <div className="mb-6">
                              <h4 className="text-blue-200 font-bold mb-3">Respuestas</h4>
                              <div className="space-y-2">
                                {Object.entries(endpoint.responses).map(([code, description]) => (
                                  <div key={code} className="flex items-start gap-3 bg-white/5 border border-white/10 rounded-lg p-3">
                                    <span className={`px-2 py-1 rounded text-xs font-bold ${
                                      code.startsWith('2') ? 'bg-green-500/20 text-green-300' :
                                      code.startsWith('4') ? 'bg-yellow-500/20 text-yellow-300' :
                                      'bg-red-500/20 text-red-300'
                                    }`}>
                                      {code}
                                    </span>
                                    <span className="text-blue-200/60 text-sm">{description as string}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Example */}
                          <div>
                            <h4 className="text-blue-200 font-bold mb-3">Ejemplo de Uso</h4>
                            <div className="bg-slate-900/50 border border-white/10 rounded-lg p-4">
                              <div className="flex items-center justify-between mb-3">
                                <span className="text-xs text-blue-300 font-mono">Curl</span>
                                <button 
                                  onClick={() => {
                                    const params = editableParams[endpoint.path] || {};
                                    let url = endpoint.path.replace(/:id/g, params.id || "1");
                                    if (endpoint.method === "GET" && endpoint.parameters) {
                                      const queryParams = endpoint.parameters
                                        .filter(p => !p.name.includes("id") || !url.includes("/"))
                                        .map(p => `${p.name}=${params[p.name] || getDefaultValue(endpoint.path, p.name, p.type)}`)
                                        .join("&");
                                      if (queryParams) url += `?${queryParams}`;
                                    }
                                    const curlCmd = `curl -X ${endpoint.method} "http://localhost:3000${url}"`;
                                    navigator.clipboard.writeText(curlCmd);
                                  }}
                                  className="text-xs text-blue-400 hover:text-blue-300"
                                >
                                  Copiar
                                </button>
                              </div>
                              <pre className="text-green-400 text-sm font-mono overflow-x-auto">
{(() => {
  const params = editableParams[endpoint.path] || {};
  let url = endpoint.path.replace(/:id/g, params.id || "1");
  if (endpoint.method === "GET" && endpoint.parameters) {
    const queryParams = endpoint.parameters
      .filter(p => !p.name.includes("id") || !url.includes("/"))
      .map(p => `${p.name}=${params[p.name] || getDefaultValue(endpoint.path, p.name, p.type)}`)
      .join("&");
    if (queryParams) url += `?${queryParams}`;
  }
  return `curl -X ${endpoint.method} "http://localhost:3000${url}"`;
})()}
                              </pre>
                            </div>
                          </div>

                          {/* Execute button */}
                          <div className="mt-4 flex justify-end">
                            <button
                              onClick={() => executeRequest(endpoint)}
                              disabled={isLoading}
                              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 disabled:from-gray-500 disabled:to-gray-600 text-white rounded-xl font-medium transition-all shadow-lg disabled:cursor-not-allowed"
                            >
                              {isLoading ? (
                                <>
                                  <svg className="animate-spin w-5 h-5" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                  </svg>
                                  Ejecutando...
                                </>
                              ) : (
                                <>
                                  <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                  </svg>
                                  Ejecutar Petición
                                </>
                              )}
                            </button>
                          </div>

                          {/* Response */}
                          {response && response.endpoint.includes(endpoint.path.split('?')[0].replace(/:id/g, '')) && (
                            <div className="mt-6 border-t border-white/10 pt-6">
                              <h4 className="text-blue-200 font-bold mb-3 flex items-center gap-2">
                                <span>Respuesta</span>
                                <span className={`px-2 py-1 rounded text-xs font-bold ${
                                  response.status >= 200 && response.status < 300 ? 'bg-green-500/20 text-green-300' :
                                  response.status >= 400 && response.status < 500 ? 'bg-yellow-500/20 text-yellow-300' :
                                  'bg-red-500/20 text-red-300'
                                }`}>
                                  {response.status}
                                </span>
                              </h4>
                              <div className="bg-slate-900/50 border border-white/10 rounded-lg p-4">
                                <div className="flex items-center justify-between mb-3">
                                  <span className="text-xs text-blue-300 font-mono">JSON Response</span>
                                  <button 
                                    onClick={() => navigator.clipboard.writeText(JSON.stringify(response.data, null, 2))}
                                    className="text-xs text-blue-400 hover:text-blue-300"
                                  >
                                    Copiar
                                  </button>
                                </div>
                                <pre className="text-green-400 text-sm font-mono overflow-x-auto max-h-96">
{JSON.stringify(response.data, null, 2)}
                                </pre>
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )
            ))}
          </div>
        </div>
      </div>

      {/* Footer */}
      <div className="relative z-10 border-t border-white/10 backdrop-blur-sm bg-white/5 mt-20">
        <div className="max-w-7xl mx-auto px-6 py-8">
          <div className="text-center text-blue-200/40 text-sm">
            <p>Esta aplicación es vulnerable por diseño - Solo para propósitos educativos</p>
            <p className="mt-2">© 2025 Aitana Security Lab</p>
          </div>
        </div>
      </div>
    </div>
  );
}
