"use client";

import Link from "next/link";
import Navigation from "@/components/Navigation";
import { useState, useEffect } from "react";

export default function Home() {
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    {
      title: "Your Partner in Total Cybersecurity",
      subtitle: "Security Assessment Platform",
      teaser: "Hands-on Training with Real-World Attack Scenarios",
      cta: "Start Training Now",
      ctaLink: "/lab/prompt-injection"
    },
    {
      title: "AI Security Red Team Laboratory",
      subtitle: "Prompt Injection Training",
      teaser: "8 Levels • 3450 Points • 14 Achievement Badges",
      cta: "Begin AI Red Team",
      ctaLink: "/lab/prompt-injection"
    }
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentSlide((prev) => (prev + 1) % slides.length);
    }, 7000);
    return () => clearInterval(timer);
  }, []);

  const services = [
    { icon: "🛡️", title: "SQL Injection", desc: "Database query manipulation through unvalidated user input", path: "/lab/sqli", cvss: "9.8" },
    { icon: "⚡", title: "Cross-Site Scripting", desc: "Client-side code injection enabling session hijacking", path: "/lab/xss", cvss: "7.1" },
    { icon: "🔐", title: "Broken Authentication", desc: "Weak authentication mechanisms enabling unauthorized access", path: "/lab/auth", cvss: "9.1" },
    { icon: "📡", title: "Sensitive Data Exposure", desc: "Inadequate protection of sensitive information", path: "/lab/sensitive-data", cvss: "7.5" },
    { icon: "🔑", title: "Broken Access Control", desc: "Insufficient enforcement of user permission boundaries", path: "/lab/access-control", cvss: "8.8" },
    { icon: "⚙️", title: "Security Misconfiguration", desc: "Insecure default configurations and incomplete hardening", path: "/lab/misconfig", cvss: "7.5" }
  ];

  const stats = [
    { icon: "🎯", value: "14", label: "Vulnerability Scenarios" },
    { icon: "📊", value: "100%", label: "OWASP Coverage" },
    { icon: "✓", value: "12+", label: "Compliance Frameworks" },
    { icon: "⚠️", value: "8.1", label: "Average CVSS Score" }
  ];

  return (
    <div className="min-h-screen bg-cyber-dark-3">
      <Navigation />

      {/* Hero Slider - CyberGuard Style */}
      <section className="relative overflow-hidden bg-cyber-dark-2">
        <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMxQjE2NjMiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHoiLz48L2c+PC9nPjwvc3ZnPg==')] opacity-20"></div>
        
        <div className="relative container max-w-[1240px] mx-auto px-6 py-32">
          <div className="text-center mb-16">
            <div className="inline-block mb-6 px-5 py-2.5 bg-cyber-dark-1 border border-blue-500/40 rounded-cyber shadow-lg">
              <span className="text-blue-300 font-urbanist text-sm font-bold tracking-wider uppercase">{slides[currentSlide].subtitle}</span>
            </div>
            <h2 className="font-urbanist text-[60px] md:text-[72px] font-bold text-white mb-6 leading-[1.15em] tracking-tight">
              {slides[currentSlide].title}
            </h2>
            <h3 className="font-dm-sans text-[24px] text-white/80 mb-8 leading-[1.4em]">
              {slides[currentSlide].teaser}
            </h3>
            <Link
              href={slides[currentSlide].ctaLink}
              className="inline-flex items-center gap-2 px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-urbanist text-[16px] font-bold rounded-cyber transition-all shadow-xl hover:shadow-2xl hover:scale-105"
            >
              <span>{slides[currentSlide].cta}</span>
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </Link>
          </div>

          {/* Slider Navigation Dots */}
          <div className="flex justify-center gap-3">
            {slides.map((_, idx) => (
              <button
                key={idx}
                onClick={() => setCurrentSlide(idx)}
                className={`w-3 h-3 rounded-full transition-all ${
                  idx === currentSlide ? 'bg-blue-500 w-8' : 'bg-white/30 hover:bg-white/50'
                }`}
              />
            ))}
          </div>
        </div>
      </section>

      {/* CTA Banner - CyberGuard Style */}
      <section className="bg-cyber-dark-3 border-y border-white/10 py-12">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <h3 className="font-urbanist text-[32px] font-bold text-white">
              Need 24/7 Protection From Cyber Attacks?
            </h3>
            <Link
              href="/evaluacion-madurez"
              className="px-8 py-3 bg-white/5 border-2 border-white/30 hover:border-blue-400/60 hover:bg-white/10 text-white font-urbanist font-bold rounded-cyber transition-all"
            >
              Start For Free
            </Link>
          </div>
        </div>
      </section>

      {/* About Section - CyberGuard Style */}
      <section className="bg-cyber-dark-2 py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <div className="text-center lg:text-left">
              <div className="inline-block mb-6 px-4 py-2 bg-blue-500/10 border border-blue-500/30 rounded-cyber">
                <span className="text-blue-300 font-urbanist text-sm font-bold">Cybersecurity Experts</span>
              </div>
              <h2 className="font-urbanist text-[48px] font-bold text-white mb-6 leading-[1.2em]">
                Comprehensive Cybersecurity Solutions for Modern Threats
              </h2>
              <p className="font-dm-sans text-white/80 text-[17px] mb-8 leading-[1.7em]">
                We safeguard your business against evolving cyber threats with proactive defense, cutting-edge tools, and a dedicated team of experts. From small businesses to large enterprises, we deliver tailored protection that keeps your data, systems, and reputation secure 24/7.
              </p>
              <ul className="space-y-3 mb-8 text-left">
                {[
                  "Certified Cybersecurity Professionals",
                  "Advanced Threat Detection & Response",
                  "Custom Security Strategies for Your Needs",
                  "24/7 Network Monitoring & Support",
                  "End-to-End Data Protection",
                  "Proven Defense Against Cyber Attacks"
                ].map((item, idx) => (
                  <li key={idx} className="flex items-center gap-3 font-dm-sans text-white/90 font-semibold">
                    <svg className="w-5 h-5 text-green-400 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
              <Link
                href="/evaluacion-madurez"
                className="inline-flex items-center gap-2 px-8 py-4 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-urbanist font-bold rounded-cyber transition-all shadow-xl"
              >
                Request a Security Audit
              </Link>
            </div>

            <div className="relative">
              <div className="relative bg-cyber-dark-1 rounded-[20px] p-8 border-2 border-white/10">
                <div className="absolute -top-6 -right-6 bg-gradient-to-br from-blue-600 to-indigo-600 text-white rounded-[20px] p-6 shadow-2xl z-10">
                  <h2 className="font-urbanist text-[48px] font-bold mb-0 leading-none">99.9%</h2>
                  <p className="font-dm-sans text-sm mt-2">Threat detection rate</p>
                </div>
                <div className="aspect-[4/3] bg-gradient-to-br from-blue-900/20 to-purple-900/20 rounded-[12px] flex items-center justify-center">
                  <svg className="w-32 h-32 text-blue-400/30" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                  </svg>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Services Marquee */}
      <section className="bg-cyber-dark-1 py-6 overflow-hidden border-y border-white/10">
        <div className="flex whitespace-nowrap animate-marquee">
          {["Network Security", "Endpoint Protection", "Threat Intelligence", "Penetration Testing", "Security Audits", "Incident Response"].map((service, idx) => (
            <div key={idx} className="inline-flex items-center px-8">
              <span className="font-urbanist text-[28px] font-semibold text-white">{service}</span>
              <span className="mx-6 text-white/30 text-[28px]">/</span>
            </div>
          ))}
        </div>
      </section>

      {/* Services Grid - CyberGuard Style */}
      <section className="bg-cyber-dark-2 py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="text-center mb-16">
            <div className="inline-block mb-4 px-4 py-2 bg-purple-500/10 border border-purple-500/30 rounded-cyber">
              <span className="text-purple-300 font-urbanist text-sm font-bold">What We Provide</span>
            </div>
            <h2 className="font-urbanist text-[48px] font-bold text-white mb-6">
              Robust Cybersecurity Services for Today's Threats
            </h2>
            <p className="font-dm-sans text-white/70 text-[19px] max-w-4xl mx-auto leading-[1.7em]">
              Protect your business from ever-evolving cyber risks with our end-to-end security solutions. We offer advanced threat detection, real-time monitoring, and proactive defense strategies tailored to your infrastructure.
            </p>
          </div>

          <div className="grid lg:grid-cols-3 md:grid-cols-2 gap-6">
            {services.map((service, idx) => (
              <Link
                key={idx}
                href={service.path}
                className="relative group bg-dark-gradient text-white rounded-[20px] p-10 overflow-hidden hover:scale-105 transition-all duration-300"
              >
                <div className="relative z-10">
                  <div className="text-6xl mb-4 bg-cyber-dark-1 w-20 h-20 rounded-cyber flex items-center justify-center">
                    {service.icon}
                  </div>
                  <h4 className="font-urbanist text-[22px] font-bold mb-3">{service.title}</h4>
                  <p className="font-dm-sans text-white/80 text-[15px] mb-6 leading-relaxed">{service.desc}</p>
                  <div className="flex items-center justify-between">
                    <span className="px-3 py-1 bg-red-500/20 border border-red-500/40 text-red-300 rounded text-xs font-bold">
                      CVSS {service.cvss}
                    </span>
                    <span className="text-blue-400 font-urbanist font-bold">Learn More →</span>
                  </div>
                </div>
                <div className="absolute right-0 bottom-0 text-[120px] opacity-5 group-hover:opacity-10 transition-opacity">
                  {service.icon}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="bg-cyber-dark-3 py-20">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, idx) => (
              <div key={idx} className="text-center">
                <div className="inline-flex items-center justify-center w-20 h-20 bg-cyber-dark-1 border-2 border-blue-500/30 rounded-full mb-4 text-4xl">
                  {stat.icon}
                </div>
                <h3 className="font-urbanist text-[40px] font-bold text-white mb-2">{stat.value}</h3>
                <p className="font-dm-sans text-white/70 text-[15px]">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* AI Red Team Lab Feature */}
      <section className="bg-cyber-dark-2 py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="relative overflow-hidden bg-gradient-to-br from-purple-900/40 via-pink-900/30 to-red-900/40 border-2 border-purple-500/30 rounded-[20px] p-12">
            <div className="grid md:grid-cols-2 gap-12 items-center relative z-10">
              <div>
                <div className="inline-block mb-6 px-5 py-2.5 bg-purple-500/20 border-2 border-purple-500/50 rounded-cyber">
                  <span className="text-purple-300 font-urbanist text-sm font-bold">🆕 NUEVO LABORATORIO</span>
                </div>
                <h2 className="font-urbanist text-[48px] font-bold text-white mb-6">🎯 AI Red Team Lab</h2>
                <p className="font-dm-sans text-[19px] text-white/80 mb-8 leading-[1.7em]">
                  Aprende a atacar y defender sistemas de IA con <span className="text-purple-300 font-bold">prompt injection</span>, 
                  <span className="text-pink-300 font-bold"> jailbreaking</span> y técnicas de 
                  <span className="text-red-300 font-bold"> red teaming</span> avanzadas.
                </p>
                <div className="grid grid-cols-3 gap-4 mb-8">
                  {[
                    { value: "8", label: "Niveles", color: "purple" },
                    { value: "3450", label: "Puntos", color: "pink" },
                    { value: "14", label: "Badges", color: "yellow" }
                  ].map((stat, idx) => (
                    <div key={idx} className={`bg-cyber-dark-1 border-2 border-white/10 hover:border-${stat.color}-500/50 rounded-cyber p-5 text-center transition-all`}>
                      <div className={`font-urbanist text-[36px] font-bold text-${stat.color}-400 mb-1`}>{stat.value}</div>
                      <div className="font-dm-sans text-xs text-white/60 font-medium">{stat.label}</div>
                    </div>
                  ))}
                </div>
                <Link
                  href="/lab/prompt-injection"
                  className="inline-flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-purple-600 via-pink-600 to-red-600 hover:from-purple-500 hover:via-pink-500 hover:to-red-500 text-white font-urbanist font-bold rounded-cyber transition-all shadow-2xl hover:scale-105"
                >
                  Empezar Entrenamiento
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M13 7l5 5m0 0l-5 5m5-5H6" />
                  </svg>
                </Link>
              </div>

              <div className="space-y-4">
                {[
                  { icon: "🔓", title: "Jailbreak de Seguridad", desc: "Bypass de filtros de contenido y restricciones de IA", color: "purple" },
                  { icon: "🕵️", title: "Extracción de Prompts", desc: "Técnicas para robar system prompts y datos secretos", color: "pink" },
                  { icon: "🧠", title: "Ataques Adversariales", desc: "Confunde modelos con encoding y multi-step attacks", color: "red" }
                ].map((feature, idx) => (
                  <div key={idx} className={`bg-cyber-dark-1 border-2 border-white/10 hover:border-${feature.color}-500/50 rounded-cyber p-6 transition-all group`}>
                    <div className="flex items-start gap-4">
                      <div className="text-5xl">{feature.icon}</div>
                      <div>
                        <h3 className="font-urbanist text-white text-[20px] font-bold mb-2">{feature.title}</h3>
                        <p className="font-dm-sans text-white/70 text-[15px]">{feature.desc}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiM5YzI3YjAiIGZpbGwtb3BhY2l0eT0iMC4xIj48Y2lyY2xlIGN4PSIzIiBjeT0iMyIgcj0iMyIvPjwvZz48L2c+PC9zdmc=')] opacity-30"></div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-cyber-dark-1 border-t-2 border-white/10 py-16">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid md:grid-cols-3 gap-12 mb-12">
            <div>
              <h3 className="font-urbanist text-white text-[20px] font-bold mb-5">About Aitana</h3>
              <p className="font-dm-sans text-white/70 text-[15px] leading-[1.7em]">
                Enterprise-grade security assessment platform designed for CISOs and security teams to understand, identify, and mitigate web application vulnerabilities.
              </p>
            </div>
            <div>
              <h3 className="font-urbanist text-white text-[20px] font-bold mb-5">Compliance Coverage</h3>
              <ul className="space-y-3">
                {["OWASP Top 10 2021", "PCI-DSS v4.0", "ISO 27001:2022", "GDPR, HIPAA, SOX", "NIST Cybersecurity Framework"].map((item, idx) => (
                  <li key={idx} className="flex items-center gap-2 font-dm-sans text-white/70 text-[15px]">
                    <svg className="w-4 h-4 text-green-400" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="font-urbanist text-white text-[20px] font-bold mb-5">Resources</h3>
              <ul className="space-y-3">
                {[
                  { label: "API Documentation", href: "/docs" },
                  { label: "Security Guides", href: "/guias" },
                  { label: "SSDLC Assessment", href: "/evaluacion-madurez" },
                  { label: "OWASP Top 10", href: "https://owasp.org/Top10/", external: true }
                ].map((link, idx) => (
                  <li key={idx}>
                    <Link
                      href={link.href}
                      className="flex items-center gap-2 font-dm-sans text-blue-400 hover:text-blue-300 text-[15px] transition-colors"
                      {...(link.external && { target: "_blank", rel: "noopener noreferrer" })}
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      {link.label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </div>
          <div className="border-t border-white/10 pt-8 text-center">
            <div className="mb-4">
              <span className="inline-flex items-center gap-2 px-4 py-2 bg-amber-500/10 border border-amber-500/30 text-amber-300 rounded-cyber font-urbanist text-sm font-bold">
                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                EDUCATIONAL PURPOSE ONLY
              </span>
            </div>
            <p className="font-dm-sans text-white/50 text-[14px]">
              This platform contains intentionally vulnerable code for security training purposes.<br />
              DO NOT deploy to production environments. © 2026 Aitana Security Lab
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
