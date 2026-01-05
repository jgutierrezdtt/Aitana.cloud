'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { BookOpen, Shield, Code, Lock, Database, AlertTriangle, CheckCircle, Terminal } from 'lucide-react';

export default function WikiPage() {
  const params = useParams();
  const locale = params.locale as string;

  const categories = [
    {
      id: 'fundamentos',
      title: 'Fundamentos de Seguridad Web',
      icon: BookOpen,
      color: 'from-blue-600 to-cyan-600',
      description: 'Conceptos básicos necesarios para entender la seguridad en aplicaciones web',
      articles: [
        { slug: 'http-basico', title: 'HTTP: El Protocolo de la Web', level: 'Principiante', time: '10 min' },
        { slug: 'cookies-sesiones', title: 'Cookies y Sesiones', level: 'Principiante', time: '15 min' },
        { slug: 'autenticacion', title: 'Autenticación vs Autorización', level: 'Principiante', time: '12 min' },
        { slug: 'apis-rest', title: 'APIs REST y JSON', level: 'Principiante', time: '15 min' },
        { slug: 'cliente-servidor', title: 'Modelo Cliente-Servidor', level: 'Principiante', time: '10 min' },
        { slug: 'cors', title: 'CORS: Control de Acceso entre Dominios', level: 'Intermedio', time: '20 min' },
      ]
    },
    {
      id: 'vulnerabilidades',
      title: 'Vulnerabilidades Comunes',
      icon: AlertTriangle,
      color: 'from-red-600 to-orange-600',
      description: 'Explicación de las vulnerabilidades más frecuentes en aplicaciones web',
      articles: [
        { slug: 'sql-injection', title: 'SQL Injection (SQLi)', level: 'Principiante', time: '20 min' },
        { slug: 'xss', title: 'Cross-Site Scripting (XSS)', level: 'Principiante', time: '18 min' },
        { slug: 'csrf', title: 'Cross-Site Request Forgery (CSRF)', level: 'Intermedio', time: '15 min' },
        { slug: 'idor', title: 'IDOR: Acceso Directo a Objetos', level: 'Principiante', time: '12 min' },
        { slug: 'xxe', title: 'XML External Entities (XXE)', level: 'Intermedio', time: '18 min' },
        { slug: 'command-injection', title: 'Command Injection', level: 'Intermedio', time: '15 min' },
        { slug: 'ssti', title: 'Server-Side Template Injection', level: 'Avanzado', time: '25 min' },
        { slug: 'broken-auth', title: 'Autenticación Rota', level: 'Intermedio', time: '20 min' },
      ]
    },
    {
      id: 'defensas',
      title: 'Defensas y Mitigaciones',
      icon: Shield,
      color: 'from-green-600 to-emerald-600',
      description: 'Técnicas y mejores prácticas para proteger tus aplicaciones',
      articles: [
        { slug: 'input-validation', title: 'Validación de Entrada', level: 'Principiante', time: '15 min' },
        { slug: 'output-encoding', title: 'Codificación de Salida', level: 'Principiante', time: '12 min' },
        { slug: 'parameterized-queries', title: 'Consultas Parametrizadas', level: 'Principiante', time: '10 min' },
        { slug: 'csp', title: 'Content Security Policy', level: 'Intermedio', time: '20 min' },
        { slug: 'security-headers', title: 'Cabeceras de Seguridad HTTP', level: 'Intermedio', time: '18 min' },
        { slug: 'password-hashing', title: 'Hashing de Contraseñas', level: 'Intermedio', time: '15 min' },
        { slug: 'secure-sessions', title: 'Gestión Segura de Sesiones', level: 'Intermedio', time: '20 min' },
      ]
    },
    {
      id: 'herramientas',
      title: 'Herramientas de Seguridad',
      icon: Terminal,
      color: 'from-purple-600 to-pink-600',
      description: 'Herramientas esenciales para testing y auditoría de seguridad',
      articles: [
        { slug: 'burp-suite', title: 'Burp Suite: Proxy de Intercepción', level: 'Intermedio', time: '25 min' },
        { slug: 'owasp-zap', title: 'OWASP ZAP: Scanner Automático', level: 'Principiante', time: '20 min' },
        { slug: 'sqlmap', title: 'SQLMap: Explotación de SQLi', level: 'Intermedio', time: '18 min' },
        { slug: 'nikto', title: 'Nikto: Web Server Scanner', level: 'Principiante', time: '15 min' },
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Hero Section */}
      <div className="relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 py-20">
        <div className="absolute inset-0 bg-[url('/grid.svg')] bg-center opacity-20"></div>
        <div className="relative max-w-7xl mx-auto px-6">
          <div className="text-center">
            <div className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-sm px-4 py-2 rounded-full mb-6">
              <BookOpen className="w-5 h-5 text-white" />
              <span className="text-white font-medium">Knowledge Base</span>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold text-white mb-6">
              Wiki de Seguridad
            </h1>
            <p className="text-xl text-blue-100 max-w-3xl mx-auto leading-relaxed">
              Aprende los conceptos fundamentales de ciberseguridad desde cero. Guías estructuradas, 
              ejemplos prácticos y explicaciones claras para todos los niveles.
            </p>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="max-w-7xl mx-auto px-6 -mt-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          {[
            { icon: BookOpen, label: 'Artículos', value: '25+', color: 'blue' },
            { icon: Code, label: 'Ejemplos de Código', value: '100+', color: 'purple' },
            { icon: Lock, label: 'Vulnerabilidades', value: '15+', color: 'red' },
            { icon: Shield, label: 'Defensas', value: '20+', color: 'green' }
          ].map((stat, idx) => (
            <div key={idx} className="bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-6 text-center">
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br from-${stat.color}-500 to-${stat.color}-600 flex items-center justify-center mx-auto mb-3`}>
                <stat.icon className="w-6 h-6 text-white" />
              </div>
              <div className="text-3xl font-bold text-white mb-1">{stat.value}</div>
              <div className="text-sm text-slate-400">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Categories */}
      <div className="max-w-7xl mx-auto px-6 py-20">
        <div className="space-y-16">
          {categories.map((category) => {
            const Icon = category.icon;
            return (
              <div key={category.id} className="space-y-6">
                {/* Category Header */}
                <div className="flex items-center gap-4">
                  <div className={`w-16 h-16 rounded-2xl bg-gradient-to-br ${category.color} flex items-center justify-center flex-shrink-0 shadow-lg`}>
                    <Icon className="w-8 h-8 text-white" />
                  </div>
                  <div>
                    <h2 className="text-3xl font-bold text-white mb-2">{category.title}</h2>
                    <p className="text-slate-400 text-lg">{category.description}</p>
                  </div>
                </div>

                {/* Articles Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {category.articles.map((article) => (
                    <Link
                      key={article.slug}
                      href={`/${locale}/wiki/${category.id}/${article.slug}`}
                      className="group bg-white/5 backdrop-blur-sm border border-white/10 rounded-2xl p-6 hover:bg-white/10 hover:border-white/20 transition-all duration-300 hover:scale-105"
                    >
                      <div className="flex items-start justify-between mb-4">
                        <div className={`px-3 py-1 rounded-lg text-xs font-medium ${
                          article.level === 'Principiante' 
                            ? 'bg-green-500/20 text-green-300' 
                            : article.level === 'Intermedio'
                            ? 'bg-yellow-500/20 text-yellow-300'
                            : 'bg-red-500/20 text-red-300'
                        }`}>
                          {article.level}
                        </div>
                        <div className="text-xs text-slate-400">{article.time}</div>
                      </div>
                      
                      <h3 className="text-xl font-bold text-white mb-2 group-hover:text-blue-400 transition-colors">
                        {article.title}
                      </h3>
                      
                      <div className="flex items-center gap-2 text-sm text-slate-400">
                        <BookOpen className="w-4 h-4" />
                        <span>Leer artículo</span>
                      </div>
                    </Link>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* CTA Section */}
      <div className="max-w-7xl mx-auto px-6 pb-20">
        <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 rounded-3xl p-12 text-center">
          <h2 className="text-4xl font-bold text-white mb-4">
            ¿Listo para practicar?
          </h2>
          <p className="text-xl text-blue-100 mb-8 max-w-2xl mx-auto">
            Aplica lo aprendido en nuestros laboratorios prácticos de vulnerabilidades
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link
              href={`/${locale}/labs/blue-team`}
              className="px-8 py-4 bg-white text-blue-600 rounded-xl font-bold hover:bg-blue-50 transition-all transform hover:scale-105 shadow-lg"
            >
              Ir a los Labs
            </Link>
            <Link
              href={`/${locale}/docs`}
              className="px-8 py-4 bg-white/10 backdrop-blur-sm text-white rounded-xl font-bold hover:bg-white/20 transition-all border border-white/20"
            >
              Ver API Docs
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
