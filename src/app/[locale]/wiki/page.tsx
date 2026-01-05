'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { BookOpen, Shield, Code, Lock, Database, AlertTriangle, CheckCircle, Terminal } from 'lucide-react';

export default function WikiPage() {
  const params = useParams();
  const locale = params.locale as string;

  // Solo artículos que existen (los que hemos creado)
  const categories = [
    {
      id: 'bug-bounty',
      title: 'Bug Bounty Techniques',
      icon: Terminal,
      color: 'from-orange-600 to-red-600',
      description: 'Técnicas avanzadas de Bug Bounty y explotación de vulnerabilidades',
      articles: [
        // Database Attacks
        { slug: 'sql-injection-avanzada', title: 'SQL Injection Manual Avanzada', level: 'Pentester', time: '25 min' },
        { slug: 'mongodb-injection', title: 'MongoDB Operator Injection', level: 'Pentester', time: '20 min' },
        { slug: 'redis-rce', title: 'Redis RCE via Lua Sandboxing', level: 'Pentester', time: '22 min' },
        { slug: 'cassandra-injection', title: 'Cassandra (CQL) Injection', level: 'Pentester', time: '18 min' },
        { slug: 'sqlite-local-injection', title: 'SQLite Local Injections', level: 'Pentester', time: '16 min' },
        { slug: 'firebase-misconfiguration', title: 'Firebase Realtime DB Misconfiguration', level: 'Pentester', time: '14 min' },
        
        // SSRF Attacks
        { slug: 'ssrf-basico', title: 'SSRF Básico', level: 'Pentester', time: '18 min' },
        { slug: 'ssrf-to-rce', title: 'SSRF to RCE', level: 'Pentester', time: '24 min' },
        
        // Access Control
        { slug: 'idor', title: 'IDOR (Insecure Direct Object References)', level: 'Pentester', time: '16 min' },
        { slug: 'race-conditions', title: 'Race Conditions', level: 'Pentester', time: '20 min' },
        { slug: 'jwt-vulnerabilities', title: 'JWT Vulnerabilities', level: 'Pentester', time: '22 min' },
        { slug: 'oauth-attacks', title: 'OAuth 2.0 Attacks', level: 'Pentester', time: '28 min' },
        
        // XSS Variants
        { slug: 'xss-stored', title: 'XSS Stored (Persistente)', level: 'Pentester', time: '20 min' },
        { slug: 'xss-dom-based', title: 'XSS DOM-based', level: 'Pentester', time: '22 min' },
        { slug: 'csp-bypass', title: 'CSP Bypass Techniques', level: 'Pentester', time: '26 min' },
        
        // Template & Injection
        { slug: 'xxe', title: 'XXE (XML External Entity)', level: 'Pentester', time: '20 min' },
        { slug: 'ssti', title: 'SSTI (Server-Side Template Injection)', level: 'Pentester', time: '24 min' },
        { slug: 'command-injection', title: 'Command Injection', level: 'Pentester', time: '18 min' },
        { slug: 'path-traversal', title: 'Path Traversal', level: 'Pentester', time: '16 min' },
        
        // File Upload
        { slug: 'file-upload', title: 'File Upload Vulnerabilities', level: 'Pentester', time: '22 min' },
        
        // API Security
        { slug: 'graphql-injection', title: 'GraphQL Injection', level: 'Pentester', time: '20 min' },
        { slug: 'prototype-pollution', title: 'Prototype Pollution', level: 'Pentester', time: '24 min' },
        
        // Web Security
        { slug: 'cors-misconfiguration', title: 'CORS Misconfiguration', level: 'Pentester', time: '18 min' },
        { slug: 'subdomain-takeover', title: 'Subdomain Takeover', level: 'Pentester', time: '20 min' },
        { slug: 'open-redirect', title: 'Open Redirect', level: 'Pentester', time: '14 min' },
        { slug: 'csrf-advanced', title: 'CSRF Advanced', level: 'Pentester', time: '22 min' },
        { slug: 'websocket-hijacking', title: 'WebSocket Hijacking', level: 'Pentester', time: '20 min' },
        
        // HTTP Advanced
        { slug: 'http-request-smuggling', title: 'HTTP Request Smuggling', level: 'Pentester', time: '26 min' },
      ]
    },
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-slate-100 dark:from-slate-950 dark:via-slate-900 dark:to-slate-950">
      {/* Hero Section */}
      <div className="relative overflow-hidden bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 dark:from-blue-900 dark:via-purple-900 dark:to-pink-900 py-20">
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
            <p className="text-xl text-blue-100 dark:text-purple-200 max-w-3xl mx-auto leading-relaxed">
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
            { icon: BookOpen, label: 'Artículos', value: '28', color: 'blue' },
            { icon: Code, label: 'Ejemplos de Código', value: '100+', color: 'purple' },
            { icon: Lock, label: 'Técnicas Bug Bounty', value: '28', color: 'red' },
            { icon: Shield, label: 'Traducciones EN', value: '10', color: 'green' }
          ].map((stat, idx) => (
            <div key={idx} className="bg-white dark:bg-slate-800/50 backdrop-blur-sm border border-slate-200 dark:border-slate-700 rounded-2xl p-6 text-center shadow-lg">
              <div className={`w-12 h-12 rounded-xl bg-gradient-to-br from-${stat.color}-500 to-${stat.color}-600 flex items-center justify-center mx-auto mb-3`}>
                <stat.icon className="w-6 h-6 text-white" />
              </div>
              <div className="text-3xl font-bold text-slate-900 dark:text-white mb-1">{stat.value}</div>
              <div className="text-sm text-slate-600 dark:text-slate-400">{stat.label}</div>
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
                    <h2 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">{category.title}</h2>
                    <p className="text-slate-600 dark:text-slate-400 text-lg">{category.description}</p>
                  </div>
                </div>

                {/* Articles Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                  {category.articles.map((article) => (
                    <Link
                      key={article.slug}
                      href={`/${locale}/wiki/${category.id}/${article.slug}`}
                      className="group bg-white dark:bg-slate-800/50 backdrop-blur-sm border border-slate-200 dark:border-slate-700 rounded-2xl p-6 hover:bg-slate-50 dark:hover:bg-slate-700/50 hover:border-slate-300 dark:hover:border-slate-600 transition-all duration-300 hover:scale-105"
                    >
                      <div className="flex items-start justify-between mb-4">
                        <div className={`px-3 py-1 rounded-lg text-xs font-medium ${
                          article.level === 'Principiante' 
                            ? 'bg-green-500/20 text-green-700 dark:text-green-300' 
                            : article.level === 'Intermedio'
                            ? 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-300'
                            : 'bg-red-500/20 text-red-700 dark:text-red-300'
                        }`}>
                          {article.level}
                        </div>
                        <div className="text-xs text-slate-600 dark:text-slate-400">{article.time}</div>
                      </div>
                      
                      <h3 className="text-xl font-bold text-slate-900 dark:text-white mb-2 group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                        {article.title}
                      </h3>
                      
                      <div className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-400">
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
        <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 dark:from-blue-900 dark:via-purple-900 dark:to-pink-900 rounded-3xl p-12 text-center">
          <h2 className="text-4xl font-bold text-white mb-4">
            ¿Listo para practicar?
          </h2>
          <p className="text-xl text-blue-100 dark:text-purple-200 mb-8 max-w-2xl mx-auto">
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
