"use client";

import Link from "next/link";
import { ArrowLeft, Database, Code, Lock, Eye, Shield, Server, Bug, Terminal, FileCode, Settings, AlertTriangle, Upload, Target } from "lucide-react";
import Navigation from "@/components/Navigation";
import AnimatedSection from "@/components/AnimatedSection";
import { useTranslations } from 'next-intl';
import { useParams } from 'next/navigation';

export default function BlueTeamLabs() {
  const t = useTranslations();
  const params = useParams();
  const locale = params.locale as string;

  const labs = [
    {
      icon: Database,
      title: "SQL Injection",
      description: "Aprende a detectar y explotar inyecciones SQL en aplicaciones web",
      path: `/${locale}/lab/sqli`,
      cvss: "9.8",
      difficulty: "Medium",
      category: "Injection"
    },
    {
      icon: Code,
      title: "Cross-Site Scripting (XSS)",
      description: "Domina técnicas de XSS reflejado, almacenado y basado en DOM",
      path: `/${locale}/lab/xss`,
      cvss: "7.1",
      difficulty: "Easy",
      category: "Injection"
    },
    {
      icon: Lock,
      title: "Broken Authentication",
      description: "Explota vulnerabilidades en sistemas de autenticación y sesiones",
      path: `/${locale}/lab/auth`,
      cvss: "9.1",
      difficulty: "Medium",
      category: "Authentication"
    },
    {
      icon: Eye,
      title: "Sensitive Data Exposure",
      description: "Identifica y explota exposición de datos sensibles",
      path: `/${locale}/lab/sensitive-data`,
      cvss: "7.5",
      difficulty: "Easy",
      category: "Data Protection"
    },
    {
      icon: Shield,
      title: "Broken Access Control",
      description: "Bypass de controles de acceso y escalación de privilegios",
      path: `/${locale}/lab/access-control`,
      cvss: "8.8",
      difficulty: "Medium",
      category: "Authorization"
    },
    {
      icon: Server,
      title: "Security Misconfiguration",
      description: "Explota configuraciones inseguras en servidores y aplicaciones",
      path: `/${locale}/lab/misconfig`,
      cvss: "7.5",
      difficulty: "Easy",
      category: "Configuration"
    },
    {
      icon: Bug,
      title: "XML External Entities (XXE)",
      description: "Ataca parsers XML vulnerables para acceder a archivos internos",
      path: `/${locale}/lab/xxe`,
      cvss: "8.2",
      difficulty: "Medium",
      category: "Injection"
    },
    {
      icon: Terminal,
      title: "Command Injection",
      description: "Ejecuta comandos del sistema a través de inyección de comandos",
      path: `/${locale}/lab/command-injection`,
      cvss: "9.8",
      difficulty: "Hard",
      category: "Injection"
    },
    {
      icon: FileCode,
      title: "LDAP Injection",
      description: "Manipula consultas LDAP para acceso no autorizado",
      path: `/${locale}/lab/ldap`,
      cvss: "8.1",
      difficulty: "Medium",
      category: "Injection"
    },
    {
      icon: Code,
      title: "Server-Side Template Injection",
      description: "Explota motores de plantillas para ejecución remota de código",
      path: `/${locale}/lab/ssti`,
      cvss: "9.0",
      difficulty: "Hard",
      category: "Injection"
    },
    {
      icon: Settings,
      title: "Session Fixation",
      description: "Fija sesiones de usuario para secuestro de cuentas",
      path: `/${locale}/lab/session-fixation`,
      cvss: "7.5",
      difficulty: "Medium",
      category: "Authentication"
    },
    {
      icon: AlertTriangle,
      title: "Content Security Policy Bypass",
      description: "Bypass de políticas de seguridad de contenido",
      path: `/${locale}/lab/csp`,
      cvss: "6.5",
      difficulty: "Hard",
      category: "Configuration"
    },
    {
      icon: Upload,
      title: "Unrestricted File Upload",
      description: "Explota cargas de archivos sin restricciones para RCE",
      path: `/${locale}/lab/file-upload`,
      cvss: "8.8",
      difficulty: "Medium",
      category: "Validation"
    }
  ];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Easy': return 'bg-green-50 dark:bg-green-500/20 border-green-200 dark:border-green-500/40 text-green-700 dark:text-green-300';
      case 'Medium': return 'bg-yellow-50 dark:bg-yellow-500/20 border-yellow-200 dark:border-yellow-500/40 text-yellow-700 dark:text-yellow-300';
      case 'Hard': return 'bg-red-50 dark:bg-red-500/20 border-red-200 dark:border-red-500/40 text-red-700 dark:text-red-300';
      default: return 'bg-gray-50 dark:bg-gray-500/20 border-gray-200 dark:border-gray-500/40 text-gray-700 dark:text-gray-300';
    }
  };

  return (
    <div className="min-h-screen bg-primary">
      <Navigation />

      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-blue-600 to-indigo-700 dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] py-20 border-b border-gray-200 dark:border-white/10">
        <div className="container max-w-[1240px] mx-auto px-6">
          <Link
            href={`/${locale}`}
            className="inline-flex items-center gap-2 text-white dark:text-white/80 hover:text-white mb-8 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            <span className="font-dm-sans">Volver al inicio</span>
          </Link>

          <AnimatedSection direction="up">
            <div className="max-w-3xl">
              <div className="inline-block mb-4 px-4 py-2 bg-white/10 dark:bg-blue-500/10 backdrop-blur-sm border border-white/20 dark:border-blue-500/30 rounded-cyber">
                <span className="text-white dark:text-accent-blue font-urbanist text-sm font-bold">🛡️ OWASP Top 10</span>
              </div>
              <h1 className="font-urbanist text-[56px] font-bold text-white mb-6 leading-[1.1em]">
                Blue Team Labs
              </h1>
              <p className="font-dm-sans text-white/90 dark:text-white/80 text-[19px] leading-[1.7em] mb-8">
                Entrena en los 13 laboratorios más críticos de seguridad web. Aprende a identificar, explotar y mitigar 
                vulnerabilidades reales basadas en el OWASP Top 10 y frameworks de compliance.
              </p>
              <div className="flex flex-wrap gap-4 text-white/80 dark:text-white/70 font-dm-sans">
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5" />
                  <span>13 Vulnerability Labs</span>
                </div>
                <div className="flex items-center gap-2">
                  <Target className="w-5 h-5" />
                  <span>OWASP Top 10</span>
                </div>
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5" />
                  <span>Real-World Scenarios</span>
                </div>
              </div>
            </div>
          </AnimatedSection>
        </div>
      </section>

      {/* Labs Grid */}
      <section className="bg-white dark:bg-secondary py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid lg:grid-cols-3 md:grid-cols-2 gap-6">
            {labs.map((lab, idx) => {
              const IconComponent = lab.icon;
              return (
                <AnimatedSection key={idx} direction="up" delay={idx * 0.05}>
                  <Link
                    href={lab.path}
                    className="block relative group bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-blue-500/20 hover:border-gray-400 dark:hover:border-blue-400/50 text-gray-900 dark:text-white rounded-xl p-6 overflow-hidden hover:scale-[1.02] transition-all duration-300 shadow-md hover:shadow-2xl dark:shadow-[0_0_30px_rgba(59,130,246,0.15)] dark:hover:shadow-[0_0_50px_rgba(59,130,246,0.3)]"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-gray-50 to-gray-100/50 dark:from-blue-600/10 dark:via-purple-600/5 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    
                    <div className="relative z-10">
                      {/* Icon */}
                      <div className="mb-4 bg-gray-100 dark:bg-gradient-to-br dark:from-blue-500/30 dark:to-purple-500/20 w-14 h-14 rounded-lg flex items-center justify-center border border-gray-200 dark:border-blue-400/30 shadow-sm dark:shadow-[0_0_20px_rgba(59,130,246,0.2)] group-hover:scale-110 transition-transform duration-300">
                        <IconComponent className="w-7 h-7 text-gray-700 dark:text-blue-400" strokeWidth={2} />
                      </div>

                      {/* Title */}
                      <h3 className="font-urbanist text-lg font-bold mb-2 text-gray-900 dark:text-white">
                        {lab.title}
                      </h3>

                      {/* Description */}
                      <p className="font-dm-sans text-gray-600 dark:text-white/70 text-sm mb-4 leading-relaxed min-h-[60px]">
                        {lab.description}
                      </p>

                      {/* Badges */}
                      <div className="flex flex-wrap items-center gap-2 mb-3">
                        <span className="px-2.5 py-1 bg-red-50 dark:bg-red-500/20 border border-red-200 dark:border-red-500/40 text-red-700 dark:text-red-300 rounded-md text-xs font-bold">
                          CVSS {lab.cvss}
                        </span>
                        <span className={`px-2.5 py-1 border rounded-md text-xs font-bold ${getDifficultyColor(lab.difficulty)}`}>
                          {lab.difficulty}
                        </span>
                      </div>

                      {/* Category */}
                      <div className="text-gray-500 dark:text-white/50 text-xs font-dm-sans">
                        {lab.category}
                      </div>
                    </div>
                    
                    {/* Background Icon */}
                    <div className="absolute right-4 bottom-4 opacity-[0.03] dark:opacity-5 group-hover:opacity-[0.06] dark:group-hover:opacity-10 transition-opacity pointer-events-none">
                      <IconComponent className="w-20 h-20 text-gray-400 dark:text-white/10" strokeWidth={1} />
                    </div>
                    
                    {/* Glow effect */}
                    <div className="hidden dark:block absolute -inset-1 bg-gradient-to-r from-blue-600/20 via-purple-600/20 to-blue-600/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 -z-10"></div>
                  </Link>
                </AnimatedSection>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}
