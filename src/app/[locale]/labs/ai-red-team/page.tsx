"use client";

import Link from "next/link";
import { ArrowLeft, Brain, Zap, Target, Shield, AlertCircle, Sparkles, BrainCircuit, Lock, Eye, Cpu, Network } from "lucide-react";
import Navigation from "@/components/Navigation";
import AnimatedSection from "@/components/AnimatedSection";
import { useTranslations } from 'next-intl';
import { useParams } from 'next/navigation';

export default function AIRedTeamLabs() {
  const t = useTranslations();
  const params = useParams();
  const locale = params.locale as string;

  const labs = [
    {
      icon: Brain,
      title: "Prompt Injection - Básico",
      description: "Aprende los fundamentos de prompt injection y cómo manipular modelos de lenguaje",
      path: `/${locale}/lab/prompt-injection/1`,
      difficulty: "Easy",
      category: "LLM Security",
      techniques: ["Direct Injection", "Delimiter Bypass"]
    },
    {
      icon: Zap,
      title: "Prompt Injection - Intermedio",
      description: "Técnicas avanzadas de injection incluyendo role-play y context manipulation",
      path: `/${locale}/lab/prompt-injection/2`,
      difficulty: "Medium",
      category: "LLM Security",
      techniques: ["Role-play", "Context Manipulation"]
    },
    {
      icon: BrainCircuit,
      title: "Prompt Injection - Avanzado",
      description: "Ataques sofisticados con multi-step injection y payload chaining",
      path: `/${locale}/lab/prompt-injection/3`,
      difficulty: "Hard",
      category: "LLM Security",
      techniques: ["Multi-step", "Payload Chaining"]
    },
    {
      icon: Target,
      title: "Jailbreaking LLMs",
      description: "Rompe las barreras de seguridad de modelos de lenguaje con técnicas de jailbreak",
      path: `/${locale}/lab/prompt-injection/jailbreak`,
      difficulty: "Hard",
      category: "LLM Security",
      techniques: ["DAN", "Universal Jailbreaks"]
    },
    {
      icon: Sparkles,
      title: "Adversarial Prompts",
      description: "Crea prompts adversarios para evadir filtros de contenido y moderación",
      path: `/${locale}/lab/prompt-injection/adversarial`,
      difficulty: "Medium",
      category: "LLM Security",
      techniques: ["Encoding", "Obfuscation"]
    },
    {
      icon: Lock,
      title: "Data Extraction Attacks",
      description: "Extrae información confidencial del entrenamiento del modelo",
      path: `/${locale}/lab/prompt-injection/data-extraction`,
      difficulty: "Hard",
      category: "LLM Security",
      techniques: ["Memory Extraction", "Training Data Leak"]
    },
    {
      icon: Eye,
      title: "Indirect Prompt Injection",
      description: "Ataca aplicaciones LLM a través de inyección indirecta en documentos",
      path: `/${locale}/lab/prompt-injection/indirect`,
      difficulty: "Medium",
      category: "LLM Security",
      techniques: ["Document Poisoning", "RAG Attacks"]
    },
    {
      icon: Cpu,
      title: "Model Inversion Attacks",
      description: "Reconstruye datos de entrenamiento mediante ataques de inversión",
      path: `/${locale}/lab/prompt-injection/model-inversion`,
      difficulty: "Expert",
      category: "LLM Security",
      techniques: ["Gradient Analysis", "Output Analysis"]
    },
    {
      icon: Network,
      title: "Chain-of-Thought Exploitation",
      description: "Manipula el razonamiento del modelo a través de CoT prompting",
      path: `/${locale}/lab/prompt-injection/cot`,
      difficulty: "Medium",
      category: "LLM Security",
      techniques: ["CoT Manipulation", "Reasoning Hijack"]
    },
    {
      icon: Shield,
      title: "Guardrail Bypass",
      description: "Evade mecanismos de seguridad y guardrails de aplicaciones LLM",
      path: `/${locale}/lab/prompt-injection/guardrail-bypass`,
      difficulty: "Hard",
      category: "LLM Security",
      techniques: ["Filter Evasion", "Safety Bypass"]
    }
  ];

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Easy': return 'bg-green-50 dark:bg-green-500/20 border-green-200 dark:border-green-500/40 text-green-700 dark:text-green-300';
      case 'Medium': return 'bg-yellow-50 dark:bg-yellow-500/20 border-yellow-200 dark:border-yellow-500/40 text-yellow-700 dark:text-yellow-300';
      case 'Hard': return 'bg-orange-50 dark:bg-orange-500/20 border-orange-200 dark:border-orange-500/40 text-orange-700 dark:text-orange-300';
      case 'Expert': return 'bg-red-50 dark:bg-red-500/20 border-red-200 dark:border-red-500/40 text-red-700 dark:text-red-300';
      default: return 'bg-gray-50 dark:bg-gray-500/20 border-gray-200 dark:border-gray-500/40 text-gray-700 dark:text-gray-300';
    }
  };

  return (
    <div className="min-h-screen bg-primary">
      <Navigation />

      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-purple-600 via-pink-600 to-red-600 dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] py-20 border-b border-gray-200 dark:border-white/10">
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
              <div className="inline-block mb-4 px-4 py-2 bg-white/10 dark:bg-purple-500/10 backdrop-blur-sm border border-white/20 dark:border-purple-500/30 rounded-cyber">
                <span className="text-white dark:text-accent-purple font-urbanist text-sm font-bold">🤖 AI Security</span>
              </div>
              <h1 className="font-urbanist text-[56px] font-bold text-white mb-6 leading-[1.1em]">
                AI Red Team Labs
              </h1>
              <p className="font-dm-sans text-white/90 dark:text-white/80 text-[19px] leading-[1.7em] mb-8">
                Domina las técnicas más avanzadas de ataque a sistemas de inteligencia artificial. Desde prompt injection 
                básico hasta ataques adversariales sofisticados contra LLMs y modelos generativos.
              </p>
              <div className="flex flex-wrap gap-4 text-white/80 dark:text-white/70 font-dm-sans">
                <div className="flex items-center gap-2">
                  <Brain className="w-5 h-5" />
                  <span>10 AI Security Labs</span>
                </div>
                <div className="flex items-center gap-2">
                  <Target className="w-5 h-5" />
                  <span>OWASP LLM Top 10</span>
                </div>
                <div className="flex items-center gap-2">
                  <Sparkles className="w-5 h-5" />
                  <span>Cutting-Edge Techniques</span>
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
                    className="block relative group bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-purple-500/20 hover:border-gray-400 dark:hover:border-purple-400/50 text-gray-900 dark:text-white rounded-xl p-6 overflow-hidden hover:scale-[1.02] transition-all duration-300 shadow-md hover:shadow-2xl dark:shadow-[0_0_30px_rgba(168,85,247,0.15)] dark:hover:shadow-[0_0_50px_rgba(168,85,247,0.3)]"
                  >
                    <div className="absolute inset-0 bg-gradient-to-br from-gray-50 to-gray-100/50 dark:from-purple-600/10 dark:via-pink-600/5 dark:to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    
                    <div className="relative z-10">
                      {/* Icon */}
                      <div className="mb-4 bg-gray-100 dark:bg-gradient-to-br dark:from-purple-500/30 dark:to-pink-500/20 w-14 h-14 rounded-lg flex items-center justify-center border border-gray-200 dark:border-purple-400/30 shadow-sm dark:shadow-[0_0_20px_rgba(168,85,247,0.2)] group-hover:scale-110 transition-transform duration-300">
                        <IconComponent className="w-7 h-7 text-gray-700 dark:text-purple-400" strokeWidth={2} />
                      </div>

                      {/* Title */}
                      <h3 className="font-urbanist text-lg font-bold mb-2 text-gray-900 dark:text-white">
                        {lab.title}
                      </h3>

                      {/* Description */}
                      <p className="font-dm-sans text-gray-600 dark:text-white/70 text-sm mb-4 leading-relaxed min-h-[60px]">
                        {lab.description}
                      </p>

                      {/* Techniques Tags */}
                      <div className="flex flex-wrap gap-1.5 mb-3">
                        {lab.techniques.map((technique, techIdx) => (
                          <span 
                            key={techIdx}
                            className="px-2 py-0.5 bg-gray-100 dark:bg-purple-500/10 border border-gray-200 dark:border-purple-500/30 text-gray-600 dark:text-purple-300 rounded text-[10px] font-semibold"
                          >
                            {technique}
                          </span>
                        ))}
                      </div>

                      {/* Badges */}
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`px-2.5 py-1 border rounded-md text-xs font-bold ${getDifficultyColor(lab.difficulty)}`}>
                          {lab.difficulty}
                        </span>
                        <span className="text-gray-500 dark:text-white/50 text-xs font-dm-sans">
                          {lab.category}
                        </span>
                      </div>
                    </div>
                    
                    {/* Background Icon */}
                    <div className="absolute right-4 bottom-4 opacity-[0.03] dark:opacity-5 group-hover:opacity-[0.06] dark:group-hover:opacity-10 transition-opacity pointer-events-none">
                      <IconComponent className="w-20 h-20 text-gray-400 dark:text-white/10" strokeWidth={1} />
                    </div>
                    
                    {/* Glow effect */}
                    <div className="hidden dark:block absolute -inset-1 bg-gradient-to-r from-purple-600/20 via-pink-600/20 to-purple-600/20 rounded-xl blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300 -z-10"></div>
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
