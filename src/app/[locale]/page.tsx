"use client";

import Link from "next/link";
import { ArrowRight, Shield, CheckCircle, Target, BarChart3, AlertTriangle, Zap, Database, Lock, Eye, Code, Server, Bug, Brain, UserX, KeyRound, ChevronLeft, ChevronRight } from "lucide-react";
import Navigation from "@/components/Navigation";
import Logo from "@/components/Logo";
import AnimatedSection from "@/components/AnimatedSection";
import Testimonials from "@/components/Testimonials";
import ScrollToTop from "@/components/ScrollToTop";
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useTranslations } from 'next-intl';
import { useParams } from 'next/navigation';

export default function Home() {
  const t = useTranslations();
  const params = useParams();
  const locale = params.locale as string;
  
  const [currentSlide, setCurrentSlide] = useState(0);

  const slides = [
    {
      title: t('hero.slide1.title'),
      subtitle: t('hero.slide1.subtitle'),
      teaser: t('hero.slide1.teaser'),
      cta: t('hero.slide1.cta'),
      ctaLink: `/${locale}/labs/blue-team`,
      bgImage: "linear-gradient(135deg, rgba(102, 126, 234, 0.85) 0%, rgba(118, 75, 162, 0.85) 100%), url('/images/hero-slide-1.webp')"
    },
    {
      title: t('hero.slide2.title'),
      subtitle: t('hero.slide2.subtitle'),
      teaser: t('hero.slide2.teaser'),
      cta: t('hero.slide2.cta'),
      ctaLink: `/${locale}/labs/ai-red-team`,
      bgImage: "linear-gradient(135deg, rgba(240, 147, 251, 0.85) 0%, rgba(245, 87, 108, 0.85) 100%), url('/images/hero-slide-2.webp')"
    }
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentSlide((prev) => (prev + 1) % slides.length);
    }, 7000);
    return () => clearInterval(timer);
  }, [slides.length]);

  const services = [
    { icon: Database, title: t('services.items.sqli.title'), desc: t('services.items.sqli.description'), path: `/${locale}/lab/sqli`, cvss: "9.8", color: "blue" },
    { icon: Code, title: t('services.items.xss.title'), desc: t('services.items.xss.description'), path: `/${locale}/lab/xss`, cvss: "7.1", color: "yellow" },
    { icon: Lock, title: t('services.items.brokenAuth.title'), desc: t('services.items.brokenAuth.description'), path: `/${locale}/lab/auth`, cvss: "9.1", color: "red" },
    { icon: Eye, title: t('services.items.dataExposure.title'), desc: t('services.items.dataExposure.description'), path: `/${locale}/lab/sensitive-data`, cvss: "7.5", color: "purple" },
    { icon: Shield, title: t('services.items.accessControl.title'), desc: t('services.items.accessControl.description'), path: `/${locale}/lab/access-control`, cvss: "8.8", color: "green" },
    { icon: Server, title: t('services.items.misconfig.title'), desc: t('services.items.misconfig.description'), path: `/${locale}/lab/misconfig`, cvss: "7.5", color: "orange" }
  ];

  const stats = [
    { icon: Target, value: "14", label: t('stats.scenarios') },
    { icon: BarChart3, value: "100%", label: t('stats.coverage') },
    { icon: CheckCircle, value: "12+", label: t('stats.frameworks') },
    { icon: AlertTriangle, value: "8.1", label: t('stats.cvssScore') }
  ];

  // Hero features - CyberGuard style
  const heroFeatures = [
    {
      icon: Shield,
      title: t('heroFeatures.penetrationTesting.title'),
      description: t('heroFeatures.penetrationTesting.description')
    },
    {
      icon: Lock,
      title: t('heroFeatures.dataProtection.title'),
      description: t('heroFeatures.dataProtection.description')
    },
    {
      icon: AlertTriangle,
      title: t('heroFeatures.incidentResponse.title'),
      description: t('heroFeatures.incidentResponse.description')
    }
  ];

  return (
    <div className="min-h-screen bg-primary">
      <Navigation />

      {/* Hero Slider - Enhanced CyberGuard Style */}
      <section className="relative overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.div 
            key={currentSlide}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.7 }}
            className="relative min-h-[600px] flex items-center"
            style={{
              background: slides[currentSlide].bgImage,
              backgroundSize: 'cover',
              backgroundPosition: 'center'
            }}
          >
            {/* Overlay oscuro */}
            <div className="absolute inset-0 bg-black/40"></div>
            
            {/* Patrón de fondo */}
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiMxQjE2NjMiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRjMC0yLjIxLTEuNzktNC00LTRzLTQgMS43OS00IDQgMS43OSA0IDQgNCA0LTEuNzkgNC00em0wLTEwYzAtMi4yMS0xLjc5LTQtNC00cy00IDEuNzktNCA0IDEuNzkgNCA0IDQgNC0xLjc5IDQtNHoiLz48L2c+PC9nPjwvc3ZnPg==')] opacity-20"></div>
            
            {/* Navigation Arrows - CyberGuard Style */}
            <button
              onClick={() => setCurrentSlide((prev) => (prev - 1 + slides.length) % slides.length)}
              className="absolute left-4 top-1/2 -translate-y-1/2 z-20 w-12 h-12 flex items-center justify-center bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/30 rounded-cyber transition-all hover:scale-110"
              aria-label="Previous slide"
            >
              <ChevronLeft className="w-6 h-6 text-white" />
            </button>
            <button
              onClick={() => setCurrentSlide((prev) => (prev + 1) % slides.length)}
              className="absolute right-4 top-1/2 -translate-y-1/2 z-20 w-12 h-12 flex items-center justify-center bg-white/10 hover:bg-white/20 backdrop-blur-sm border border-white/30 rounded-cyber transition-all hover:scale-110"
              aria-label="Next slide"
            >
              <ChevronRight className="w-6 h-6 text-white" />
            </button>
            
            <div className="relative container max-w-[1240px] mx-auto px-6 py-32 z-10">
              <div className="text-center mb-16">
                <motion.div 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2, duration: 0.6 }}
                  className="inline-block mb-6 px-5 py-2.5 bg-white/10 backdrop-blur-sm border border-white/20 rounded-cyber shadow-lg"
                >
                  <span className="text-white font-urbanist text-sm font-bold tracking-wider uppercase">{slides[currentSlide].subtitle}</span>
                </motion.div>
                <motion.h2 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.3, duration: 0.6 }}
                  className="font-urbanist text-[60px] md:text-[72px] font-bold text-white mb-6 leading-[1.15em] tracking-tight drop-shadow-2xl"
                >
                  {slides[currentSlide].title}
                </motion.h2>
                <motion.h3 
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.4, duration: 0.6 }}
                  className="font-dm-sans text-[24px] text-white/90 mb-8 leading-[1.4em] drop-shadow-lg"
                >
                  {slides[currentSlide].teaser}
                </motion.h3>
                <motion.div
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.5, duration: 0.6 }}
                >
                  <Link
                    href={slides[currentSlide].ctaLink}
                    className="group inline-flex items-center gap-2 px-8 py-4 bg-white hover:bg-gray-100 text-gray-900 font-urbanist text-[16px] font-bold rounded-cyber transition-all shadow-xl hover:shadow-2xl hover:scale-105 relative overflow-hidden"
                  >
                    {/* Efecto de brillo al hover */}
                    <span className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent translate-x-[-200%] group-hover:translate-x-[200%] transition-transform duration-1000"></span>
                    <span className="relative">{slides[currentSlide].cta}</span>
                    <ArrowRight className="w-5 h-5 relative group-hover:translate-x-1 transition-transform" />
                  </Link>
                </motion.div>
              </div>

              {/* Slider Navigation Dots */}
              <div className="flex justify-center gap-3">
                {slides.map((_, idx) => (
                  <button
                    key={idx}
                    onClick={() => setCurrentSlide(idx)}
                    className={`h-3 rounded-full transition-all ${
                      idx === currentSlide ? 'bg-white w-8' : 'bg-white/30 hover:bg-white/50 w-3'
                    }`}
                    aria-label={`Ir al slide ${idx + 1}`}
                  />
                ))}
              </div>
            </div>
          </motion.div>
        </AnimatePresence>

        {/* Hero Features - CyberGuard Style (debajo del slider) */}
        <div className="relative bg-gradient-to-b from-gray-100 to-white dark:from-[#0A0525] dark:to-[#1B1663] border-t border-gray-300 dark:border-white/10">
          <div className="container max-w-[1240px] mx-auto px-6 py-16">
            <div className="grid md:grid-cols-3 gap-8">
              {heroFeatures.map((feature, idx) => (
                <AnimatedSection key={idx} delay={idx * 0.1} direction="up">
                  <div className="relative group">
                    <div className="absolute -inset-1 bg-gradient-to-r from-gray-300 to-gray-400 dark:from-blue-600 dark:to-purple-600 rounded-cyber opacity-0 dark:opacity-20 group-hover:opacity-30 dark:group-hover:opacity-100 blur transition-all duration-500"></div>
                    <div className="relative bg-gray-50 dark:bg-[#1B1663]/50 backdrop-blur-sm p-8 rounded-cyber border border-gray-300 dark:border-white/10 hover:border-gray-400 dark:hover:border-blue-500/50 transition-all">
                      <div className="w-16 h-16 mb-6 bg-gray-100 dark:bg-blue-500/20 rounded-cyber flex items-center justify-center group-hover:scale-110 transition-transform">
                        <feature.icon className="w-8 h-8 text-gray-700 dark:text-blue-400" />
                      </div>
                      <h4 className="font-urbanist text-xl font-bold text-gray-900 dark:text-white mb-3">
                        {feature.title}
                      </h4>
                      <p className="font-dm-sans text-gray-600 dark:text-gray-300 leading-relaxed">
                        {feature.description}
                      </p>
                    </div>
                  </div>
                </AnimatedSection>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* CTA Banner - CyberGuard Style */}
      <section className="bg-primary border-y border-default py-12">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <h3 className="font-urbanist text-[32px] font-bold text-primary">
              {t('ctaBanner.title')}
            </h3>
            <Link
              href={`/${locale}/labs/ai-red-team`}
              className="px-8 py-3 bg-secondary/50 border-2 border-default hover:border-accent-blue transition-all hover:bg-tertiary text-primary font-urbanist font-bold rounded-cyber"
            >
              {t('ctaBanner.button')}
            </Link>
          </div>
        </div>
      </section>

      {/* About Section - With Animations */}
      <section className="bg-secondary py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid lg:grid-cols-2 gap-16 items-center">
            <AnimatedSection direction="left">
              <div className="text-center lg:text-left">
                <div className="inline-block mb-6 px-4 py-2 bg-gray-100 dark:bg-blue-500/10 border border-gray-300 dark:border-blue-500/30 rounded-cyber">
                  <span className="text-gray-700 dark:text-accent-blue font-urbanist text-sm font-bold">{t('about.badge')}</span>
                </div>
                <h2 className="font-urbanist text-[48px] font-bold text-primary mb-6 leading-[1.2em]">
                  {t('about.title')}
                </h2>
                <p className="font-dm-sans text-secondary text-[17px] mb-8 leading-[1.7em]">
                  {t('about.description')}
                </p>
                <ul className="space-y-3 mb-8 text-left">
                  {(t.raw('about.features') as string[]).map((item, idx) => (
                    <motion.li 
                      key={idx} 
                      initial={{ opacity: 0, x: -20 }}
                      whileInView={{ opacity: 1, x: 0 }}
                      viewport={{ once: true }}
                      transition={{ delay: idx * 0.1, duration: 0.5 }}
                      className="flex items-center gap-3 font-dm-sans text-primary font-semibold"
                    >
                      <CheckCircle className="w-5 h-5 text-green-600 dark:text-accent-green flex-shrink-0" />
                      {item}
                    </motion.li>
                  ))}
                </ul>
                <Link
                  href={`/${locale}/labs/blue-team`}
                  className="group inline-flex items-center gap-2 px-8 py-4 bg-gray-800 dark:bg-gradient-to-r dark:from-blue-600 dark:to-indigo-600 hover:bg-gray-700 dark:hover:from-blue-500 dark:hover:to-indigo-500 text-white font-urbanist font-bold rounded-cyber transition-all shadow-xl relative overflow-hidden"
                >
                  {/* Shine effect */}
                  <span className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent translate-x-[-200%] group-hover:translate-x-[200%] transition-transform duration-1000"></span>
                  <span className="relative">Explore Labs</span>
                  <ArrowRight className="w-5 h-5 relative group-hover:translate-x-1 transition-transform" />
                </Link>
              </div>
            </AnimatedSection>

            <AnimatedSection direction="right" delay={0.2}>
              <div className="relative">
                {/* Main image container */}
                <div className="relative rounded-[20px] overflow-hidden">
                  <motion.div 
                    initial={{ opacity: 0, scale: 0.8 }}
                    whileInView={{ opacity: 1, scale: 1 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.4, duration: 0.6 }}
                    className="absolute -top-6 -right-6 bg-gray-800 dark:bg-gradient-to-br dark:from-blue-600 dark:to-indigo-600 text-white rounded-[20px] p-6 shadow-2xl z-20"
                  >
                    <h2 className="font-urbanist text-[48px] font-bold mb-0 leading-none">14+</h2>
                    <p className="font-dm-sans text-sm mt-2">Vulnerability Labs</p>
                  </motion.div>

                  {/* Large dashboard image */}
                  <motion.div
                    initial={{ opacity: 0, x: 50 }}
                    whileInView={{ opacity: 1, x: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.3, duration: 0.8 }}
                    className="relative z-10"
                  >
                    <img 
                      src="/images/dashboard-mockup.svg" 
                      alt="Security Dashboard"
                      className="w-full h-auto rounded-[20px] shadow-2xl"
                    />
                  </motion.div>

                  {/* Floating alert card - bottom right */}
                  <motion.div
                    initial={{ opacity: 0, scale: 0.5, y: 50 }}
                    whileInView={{ opacity: 1, scale: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.6, duration: 0.6 }}
                    className="absolute -bottom-4 -right-4 w-[200px] rounded-[12px] overflow-hidden shadow-2xl z-15 border-2 border-gray-300 dark:border-purple-500/30"
                  >
                    <img 
                      src="/images/security-alerts.svg" 
                      alt="Security Alerts"
                      className="w-full h-auto"
                    />
                  </motion.div>

                  {/* Floating analytics card - bottom left */}
                  <motion.div
                    initial={{ opacity: 0, scale: 0.5, y: 50 }}
                    whileInView={{ opacity: 1, scale: 1, y: 0 }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.7, duration: 0.6 }}
                    className="absolute -bottom-6 -left-6 w-[180px] rounded-[12px] overflow-hidden shadow-2xl z-15 border-2 border-gray-300 dark:border-blue-500/30"
                  >
                    <div className="aspect-square bg-gray-100 dark:bg-gradient-to-br dark:from-blue-500/20 dark:to-purple-500/20 p-4 flex items-center justify-center">
                      <div className="text-center">
                        <div className="text-[40px] font-bold text-gray-900 dark:text-blue-400 mb-1">99.9%</div>
                        <div className="text-xs text-gray-600 dark:text-white/70 font-medium">Threat Detection</div>
                      </div>
                    </div>
                  </motion.div>
                </div>
              </div>
            </AnimatedSection>
          </div>
        </div>
      </section>

      {/* Services Marquee */}
      <section className="bg-tertiary py-6 overflow-hidden border-y border-default">
        <div className="flex whitespace-nowrap animate-marquee">
          {["Network Security", "Endpoint Protection", "Threat Intelligence", "Penetration Testing", "Security Audits", "Incident Response"].map((service, idx) => (
            <div key={idx} className="inline-flex items-center px-8">
              <span className="font-urbanist text-[28px] font-semibold text-primary">{service}</span>
              <span className="mx-6 text-muted text-[28px]">/</span>
            </div>
          ))}
        </div>
      </section>

      {/* Services Grid - With Animations */}
      <section className="bg-secondary py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <AnimatedSection direction="up" className="text-center mb-16">
            <div className="inline-block mb-4 px-4 py-2 bg-gray-100 dark:bg-purple-500/10 border border-gray-300 dark:border-purple-500/30 rounded-cyber">
              <span className="text-gray-700 dark:text-accent-purple font-urbanist text-sm font-bold">{t('services.badge')}</span>
            </div>
            <h2 className="font-urbanist text-[48px] font-bold text-primary mb-6">
              {t('services.title')}
            </h2>
            <p className="font-dm-sans text-secondary text-[19px] max-w-4xl mx-auto leading-[1.7em]">
              {t('services.description')}
            </p>
          </AnimatedSection>

          <div className="grid lg:grid-cols-3 md:grid-cols-2 gap-6">
            {services.map((service, idx) => {
              const IconComponent = service.icon;
              return (
              <AnimatedSection key={idx} direction="up" delay={idx * 0.1}>
                <Link
                  href={service.path}
                  className="block relative group bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border border-gray-300 dark:border-blue-500/20 hover:border-gray-400 dark:hover:border-blue-400/50 text-gray-900 dark:text-white rounded-xl p-8 overflow-hidden hover:scale-[1.02] transition-all duration-300 shadow-md hover:shadow-2xl dark:shadow-[0_0_30px_rgba(59,130,246,0.15)] dark:hover:shadow-[0_0_50px_rgba(59,130,246,0.3)]">
                  <div className="absolute inset-0 bg-gradient-to-br from-gray-50 to-gray-100/50 dark:from-blue-600/10 dark:via-purple-600/5 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  
                  <div className="relative z-10">
                    <div className="mb-5 bg-gray-100 dark:bg-gradient-to-br dark:from-blue-500/30 dark:to-purple-500/20 w-16 h-16 rounded-lg flex items-center justify-center border border-gray-200 dark:border-blue-400/30 shadow-sm dark:shadow-[0_0_20px_rgba(59,130,246,0.2)] group-hover:scale-110 transition-transform duration-300">
                      <IconComponent className="w-8 h-8 text-gray-700 dark:text-blue-400" strokeWidth={2} />
                    </div>
                    <h4 className="font-urbanist text-xl font-bold mb-2 text-gray-900 dark:text-white">{service.title}</h4>
                    <p className="font-dm-sans text-gray-600 dark:text-white/70 text-sm mb-5 leading-relaxed">{service.desc}</p>
                    <div className="flex items-center justify-between">
                      <span className="px-3 py-1.5 bg-red-50 dark:bg-red-500/20 border border-red-200 dark:border-red-500/40 text-red-700 dark:text-red-300 rounded-md text-xs font-bold">
                        CVSS {service.cvss}
                      </span>
                      <span className="text-gray-700 dark:text-blue-400 font-urbanist text-sm font-semibold group-hover:text-gray-900 dark:group-hover:text-blue-300 transition-colors flex items-center gap-1">
                        Explorar <ArrowRight className="w-4 h-4" />
                      </span>
                    </div>
                  </div>
                  
                  <div className="absolute right-4 bottom-4 opacity-[0.03] dark:opacity-5 group-hover:opacity-[0.06] dark:group-hover:opacity-10 transition-opacity pointer-events-none">
                    <IconComponent className="w-24 h-24 text-gray-400 dark:text-white/10" strokeWidth={1} />
                  </div>
                  
                  {/* Glow effect - solo en dark */}
                  <div className="hidden dark:block absolute -inset-1 bg-gradient-to-r from-blue-600/20 via-purple-600/20 to-blue-600/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 -z-10"></div>
                </Link>
              </AnimatedSection>
              );
            })}
          </div>
        </div>
      </section>

      {/* Stats Section - With Animations */}
      <section className="bg-primary py-20">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat, idx) => {
              const IconComponent = stat.icon;
              return (
              <AnimatedSection key={idx} direction="zoom" delay={idx * 0.1}>
                <div className="text-center group cursor-default">
                  <motion.div 
                    whileHover={{ scale: 1.1, rotate: 5 }}
                    transition={{ duration: 0.3 }}
                    className="inline-flex items-center justify-center w-20 h-20 bg-gray-100 dark:bg-tertiary border-2 border-gray-300 dark:border-blue-500/30 rounded-full mb-4"
                  >
                    <IconComponent className="w-10 h-10 text-gray-700 dark:text-blue-400" strokeWidth={2} />
                  </motion.div>
                  <motion.h3 
                    initial={{ scale: 1 }}
                    whileInView={{ scale: [1, 1.1, 1] }}
                    viewport={{ once: true }}
                    transition={{ delay: idx * 0.1 + 0.3, duration: 0.5 }}
                    className="font-urbanist text-[40px] font-bold text-primary mb-2"
                  >
                    {stat.value}
                  </motion.h3>
                  <p className="font-dm-sans text-secondary text-[15px]">{stat.label}</p>
                </div>
              </AnimatedSection>
              );
            })}
          </div>
        </div>
      </section>

      {/* AI Red Team Lab Feature */}
      <section className="bg-secondary py-24">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="relative overflow-hidden bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border-2 border-gray-300 dark:border-purple-500/40 rounded-[20px] p-12 shadow-xl dark:shadow-[0_0_60px_rgba(147,51,234,0.3)]">
            <div className="grid md:grid-cols-2 gap-12 items-center relative z-10">
              <div>
                <div className="inline-block mb-6 px-5 py-2.5 bg-gray-100 dark:bg-purple-500/20 border-2 border-gray-300 dark:border-purple-500/50 rounded-[12px] shadow-sm dark:shadow-[0_0_20px_rgba(147,51,234,0.3)]">
                  <span className="text-gray-700 dark:text-purple-300 font-urbanist text-sm font-bold">{t('aiLab.badge')}</span>
                </div>
                <h2 className="font-urbanist text-[48px] font-bold text-gray-900 dark:text-white mb-6">{t('aiLab.title')}</h2>
                <p className="font-dm-sans text-[19px] text-gray-700 dark:text-white/80 mb-8 leading-[1.7em]">
                  {t.rich('aiLab.description', {
                    promptInjection: (chunks) => <span className="text-gray-900 dark:text-purple-300 font-bold">{chunks}</span>,
                    jailbreaking: (chunks) => <span className="text-gray-900 dark:text-pink-300 font-bold">{chunks}</span>,
                    redTeaming: (chunks) => <span className="text-gray-900 dark:text-red-300 font-bold">{chunks}</span>
                  })}
                </p>
                <div className="grid grid-cols-3 gap-4 mb-8">
                  {[
                    { value: "8", label: t('aiLab.stats.levels') },
                    { value: "3450", label: t('aiLab.stats.points') },
                    { value: "14", label: t('aiLab.stats.badges') }
                  ].map((stat, idx) => (
                    <div key={idx} className="relative group bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border-2 border-gray-300 dark:border-purple-500/40 hover:border-gray-400 dark:hover:border-purple-400/70 rounded-[12px] p-5 text-center transition-all shadow-md dark:shadow-[0_0_20px_rgba(147,51,234,0.2)] hover:shadow-lg dark:hover:shadow-[0_0_35px_rgba(147,51,234,0.4)] overflow-hidden">
                      <div className="absolute inset-0 bg-gradient-to-br from-gray-100 to-transparent dark:from-purple-600/10 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>
                      <div className="relative z-10 font-urbanist text-[36px] font-bold text-gray-900 dark:text-purple-400 mb-1">{stat.value}</div>
                      <div className="relative z-10 font-dm-sans text-xs text-gray-500 dark:text-white/60 font-medium">{stat.label}</div>
                    </div>
                  ))}
                </div>
                <Link
                  href={`/${locale}/lab/prompt-injection`}
                  className="inline-flex items-center gap-3 px-8 py-4 bg-gradient-to-r from-gray-700 to-gray-900 dark:from-purple-600 dark:via-pink-600 dark:to-red-600 hover:from-gray-600 hover:to-gray-800 dark:hover:from-purple-500 dark:hover:via-pink-500 dark:hover:to-red-500 text-white font-urbanist font-bold rounded-cyber transition-all shadow-2xl hover:scale-105"
                >
                  {t('aiLab.button')}
                  <ArrowRight className="w-6 h-6" />
                </Link>
              </div>

              <div className="space-y-4">
                {[
                  { icon: KeyRound, title: t('aiLab.features.jailbreak.title'), desc: t('aiLab.features.jailbreak.description') },
                  { icon: UserX, title: t('aiLab.features.extraction.title'), desc: t('aiLab.features.extraction.description') },
                  { icon: Brain, title: t('aiLab.features.adversarial.title'), desc: t('aiLab.features.adversarial.description') }
                ].map((feature, idx) => {
                  const IconComponent = feature.icon;
                  return (
                  <div key={idx} className="relative group bg-gray-50 dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border-2 border-gray-300 dark:border-purple-500/30 hover:border-gray-400 dark:hover:border-purple-400/60 rounded-[12px] p-6 transition-all shadow-md dark:shadow-[0_0_25px_rgba(147,51,234,0.15)] hover:shadow-lg dark:hover:shadow-[0_0_40px_rgba(147,51,234,0.3)] overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-gray-100 to-transparent dark:from-purple-600/10 dark:via-purple-500/5 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    
                    <div className="relative z-10 flex items-start gap-4">
                      <div className="bg-gray-100 dark:bg-purple-500/20 p-3 rounded-lg border border-gray-300 dark:border-purple-500/30">
                        <IconComponent className="w-8 h-8 text-gray-700 dark:text-purple-400" strokeWidth={2} />
                      </div>
                      <div>
                        <h3 className="font-urbanist text-gray-900 dark:text-white text-[20px] font-bold mb-2">{feature.title}</h3>
                        <p className="font-dm-sans text-gray-600 dark:text-white/70 text-[15px]">{feature.desc}</p>
                      </div>
                    </div>
                    
                    {/* Subtle glow - solo en dark */}
                    <div className="hidden dark:block absolute -inset-1 bg-gradient-to-r from-purple-600/10 to-purple-600/10 rounded-[12px] blur-lg opacity-0 group-hover:opacity-100 transition-opacity -z-10"></div>
                  </div>
                  );
                })}
              </div>
            </div>
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiM5YzI3YjAiIGZpbGwtb3BhY2l0eT0iMC4xIj48Y2lyY2xlIGN4PSIzIiBjeT0iMyIgcj0iMyIvPjwvZz48L2c+PC9zdmc=')] opacity-30"></div>
          </div>
        </div>
      </section>

      {/* Footer - CyberGuard Style */}
      <footer className="bg-tertiary border-t-2 border-default py-16">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid md:grid-cols-3 gap-12 mb-12">
            {/* Logo y descripción */}
            <div className="md:col-span-1">
              <Logo variant="footer" size="md" />
              <p className="font-dm-sans text-secondary text-[14px] mt-4 leading-relaxed">
                {t('footer.description')}
              </p>
            </div>

            {/* Laboratorios */}
            <div>
              <h3 className="font-urbanist text-primary text-[18px] font-bold mb-5">{t('footer.labs.title')}</h3>
              <ul className="space-y-3">
                <li><Link href={`/${locale}/lab/sqli`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.labs.items.sqli')}</Link></li>
                <li><Link href={`/${locale}/lab/xss`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.labs.items.xss')}</Link></li>
                <li><Link href={`/${locale}/lab/auth`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.labs.items.auth')}</Link></li>
                <li><Link href={`/${locale}/lab/sensitive-data`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.labs.items.sensitiveData')}</Link></li>
                <li><Link href={`/${locale}/labs/ai-red-team`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.labs.items.aiLab')}</Link></li>
              </ul>
            </div>

            {/* Recursos */}
            <div>
              <h3 className="font-urbanist text-primary text-[18px] font-bold mb-5">{t('footer.resources.title')}</h3>
              <ul className="space-y-3">
                <li><Link href={`/${locale}/docs`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.resources.items.docs')}</Link></li>
                <li><Link href={`/${locale}/guias`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.resources.items.guides')}</Link></li>
                <li><Link href={`/${locale}/evaluacion-madurez`} className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">{t('footer.resources.items.support')}</Link></li>
                <li><Link href="https://owasp.org/Top10/" target="_blank" className="font-dm-sans text-secondary hover:text-primary text-[14px] transition-colors">OWASP Top 10</Link></li>
              </ul>
            </div>
          </div>

          {/* Copyright */}
          <div className="border-t border-default pt-8">
            <div className="flex flex-col md:flex-row justify-between items-center gap-4 mb-4">
              <p className="font-dm-sans text-secondary text-[13px]">
                {t('footer.copyright')}
              </p>
              <div className="flex gap-6">
                <Link href={`/${locale}/terms`} className="font-dm-sans text-secondary hover:text-primary text-[13px] transition-colors">
                  {t('footer.terms')}
                </Link>
                <Link href={`/${locale}/privacy`} className="font-dm-sans text-secondary hover:text-primary text-[13px] transition-colors">
                  {t('footer.privacy')}
                </Link>
              </div>
            </div>
            <div className="text-center">
              <span className="inline-flex items-center gap-2 px-4 py-2 bg-gray-100 dark:bg-amber-500/10 border border-gray-300 dark:border-amber-500/30 text-gray-700 dark:text-accent-yellow rounded-cyber font-urbanist text-sm font-bold">
                <AlertTriangle className="w-5 h-5" />
                {t('footer.warning')}
              </span>
            </div>
          </div>
        </div>
      </footer>
    </div>
  );
}
