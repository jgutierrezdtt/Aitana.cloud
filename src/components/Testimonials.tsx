"use client";

import { motion } from "framer-motion";
import { Star, Quote } from "lucide-react";
import AnimatedSection from "./AnimatedSection";

interface Testimonial {
  name: string;
  role: string;
  company: string;
  content: string;
  rating: number;
  image?: string;
}

const testimonials: Testimonial[] = [
  {
    name: "Carlos Méndez",
    role: "CISO",
    company: "TechCorp Internacional",
    content: "La plataforma de Aitana.cloud ha transformado cómo nuestro equipo aborda la seguridad. Los laboratorios prácticos son increíblemente realistas y han mejorado significativamente nuestras capacidades de detección.",
    rating: 5,
  },
  {
    name: "Laura Rodríguez",
    role: "Security Engineer",
    company: "FinanceSecure",
    content: "El AI Red Team Lab es excepcional. Nunca había visto una plataforma que combine tan bien la teoría con la práctica. Los escenarios de prompt injection son extremadamente valiosos.",
    rating: 5,
  },
  {
    name: "Miguel Sánchez",
    role: "Pentester Senior",
    company: "SecOps Solutions",
    content: "Como profesional de seguridad con 10+ años de experiencia, puedo decir que estos laboratorios están a otro nivel. La cobertura del OWASP Top 10 es completa y actualizada.",
    rating: 5,
  },
];

export default function Testimonials() {
  return (
    <section className="bg-secondary py-24 overflow-hidden">
      <div className="container max-w-[1240px] mx-auto px-6">
        <AnimatedSection direction="up" className="text-center mb-16">
          <div className="inline-block mb-4 px-4 py-2 bg-gray-100 dark:bg-blue-500/10 border border-gray-300 dark:border-blue-500/30 rounded-cyber">
            <span className="text-gray-700 dark:text-accent-blue font-urbanist text-sm font-bold">Testimonios</span>
          </div>
          <h2 className="font-urbanist text-[48px] font-bold text-primary mb-6">
            Lo Que Dicen Nuestros Usuarios
          </h2>
          <p className="font-dm-sans text-secondary text-[19px] max-w-3xl mx-auto leading-[1.7em]">
            Profesionales de seguridad de todo el mundo confían en nuestra plataforma para mejorar sus habilidades
          </p>
        </AnimatedSection>

        <div className="grid md:grid-cols-3 gap-8">
          {testimonials.map((testimonial, idx) => (
            <AnimatedSection key={idx} direction="up" delay={idx * 0.15}>
              <motion.div
                whileHover={{ y: -10 }}
                transition={{ duration: 0.3 }}
                className="relative h-full"
              >
                {/* Glow effect */}
                <div className="absolute -inset-1 bg-gradient-to-r from-gray-300 to-gray-400 dark:from-blue-600 dark:to-purple-600 rounded-[20px] opacity-0 dark:opacity-20 group-hover:opacity-30 dark:group-hover:opacity-100 blur-xl transition-all duration-500"></div>
                
                {/* Card */}
                <div className="relative h-full bg-white dark:bg-gradient-to-br dark:from-[#0A0525] dark:via-[#1B1663] dark:to-[#0A0525] border-2 border-gray-300 dark:border-blue-500/30 rounded-[20px] p-8 shadow-xl dark:shadow-[0_0_40px_rgba(59,130,246,0.2)] hover:shadow-2xl dark:hover:shadow-[0_0_60px_rgba(59,130,246,0.4)] transition-all group">
                  
                  {/* Quote Icon */}
                  <div className="mb-6">
                    <div className="w-14 h-14 bg-gray-100 dark:bg-blue-500/20 rounded-full flex items-center justify-center">
                      <Quote className="w-7 h-7 text-gray-700 dark:text-blue-400" />
                    </div>
                  </div>

                  {/* Stars */}
                  <div className="flex gap-1 mb-4">
                    {[...Array(testimonial.rating)].map((_, i) => (
                      <Star
                        key={i}
                        className="w-4 h-4 fill-yellow-400 dark:fill-yellow-300 text-yellow-400 dark:text-yellow-300"
                      />
                    ))}
                  </div>

                  {/* Content */}
                  <p className="font-dm-sans text-gray-700 dark:text-white/80 text-[15px] leading-relaxed mb-6 italic">
                    "{testimonial.content}"
                  </p>

                  {/* Author */}
                  <div className="flex items-center gap-4 pt-6 border-t border-gray-200 dark:border-white/10">
                    {/* Avatar placeholder */}
                    <div className="w-12 h-12 rounded-full bg-gradient-to-br from-gray-300 to-gray-400 dark:from-blue-500 dark:to-purple-500 flex items-center justify-center">
                      <span className="font-urbanist font-bold text-white text-lg">
                        {testimonial.name.split(' ').map(n => n[0]).join('')}
                      </span>
                    </div>
                    
                    <div>
                      <h4 className="font-urbanist font-bold text-gray-900 dark:text-white text-[16px]">
                        {testimonial.name}
                      </h4>
                      <p className="font-dm-sans text-gray-600 dark:text-white/60 text-[13px]">
                        {testimonial.role} • {testimonial.company}
                      </p>
                    </div>
                  </div>

                  {/* Decorative element */}
                  <div className="absolute top-6 right-6 w-20 h-20 bg-gradient-to-br from-gray-100 to-transparent dark:from-blue-500/10 dark:to-transparent rounded-full blur-2xl"></div>
                </div>
              </motion.div>
            </AnimatedSection>
          ))}
        </div>
      </div>
    </section>
  );
}
