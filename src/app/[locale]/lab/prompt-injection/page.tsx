'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, Target, Award, Clock, Zap, Shield, Brain, Lock, Eye, Users, Unlock, Database, Mail, Link2, ArrowRight } from 'lucide-react';
import Navigation from '@/components/Navigation';
import AnimatedSection from '@/components/AnimatedSection';
import { challenges } from '@/data/prompt-injection-challenges';
import { badges } from '@/data/prompt-injection-badges';

export default function PromptInjectionLab() {
  const [selectedDifficulty, setSelectedDifficulty] = useState<string>('all');
  const [selectedCategory, setSelectedCategory] = useState<string>('all');

  const filteredChallenges = challenges.filter(c => {
    const matchesDifficulty = selectedDifficulty === 'all' || c.difficulty === selectedDifficulty;
    const matchesCategory = selectedCategory === 'all' || c.category === selectedCategory;
    return matchesDifficulty && matchesCategory;
  });

  const stats = {
    totalChallenges: challenges.length,
    totalPoints: challenges.reduce((sum, c) => sum + c.points, 0),
    totalBadges: badges.length,
    avgTime: Math.round(challenges.reduce((sum, c) => sum + c.estimatedTime, 0) / challenges.length),
  };

  return (
    <div className="min-h-screen bg-primary">
      <Navigation />

      {/* Hero Section */}
      <section className="relative bg-gradient-to-br from-purple-600 via-pink-600 to-red-600 dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] py-20 border-b border-gray-200 dark:border-white/10">
        <div className="container max-w-[1240px] mx-auto px-6">
          <Link
            href="/"
            className="inline-flex items-center gap-2 text-white dark:text-white/80 hover:text-white mb-8 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
            <span className="font-dm-sans">Volver al inicio</span>
          </Link>

          <AnimatedSection direction="up">
            <div className="max-w-3xl">
              <div className="inline-block mb-4 px-4 py-2 bg-red-500/20 dark:bg-red-500/10 backdrop-blur-sm border border-red-500/50 dark:border-red-500/30 rounded-cyber">
                <span className="text-white dark:text-red-300 font-urbanist text-sm font-bold">⚠️ SISTEMA VULNERABLE</span>
              </div>
              <h1 className="font-urbanist text-[56px] font-bold text-white mb-6 leading-[1.1em]">
                🎯 Prompt Injection Lab
              </h1>
              <p className="font-dm-sans text-white/90 dark:text-white/80 text-[19px] leading-[1.7em] mb-8">
                Aprende a atacar y defender sistemas de IA a través de ejercicios prácticos de red teaming.
                Completa desafíos, gana badges y domina las técnicas de prompt injection.
              </p>
            </div>
          </AnimatedSection>
        </div>
      </section>

      {/* Stats Section */}
      <section className="bg-white dark:bg-secondary py-12 border-b border-gray-200 dark:border-white/10">
        <div className="container max-w-[1240px] mx-auto px-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <AnimatedSection direction="up" delay={0}>
              <div className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-purple-500/20 rounded-xl p-6 text-center">
                <Target className="w-8 h-8 text-purple-600 dark:text-purple-400 mx-auto mb-3" />
                <div className="text-4xl font-bold text-gray-900 dark:text-white mb-2">{stats.totalChallenges}</div>
                <div className="text-gray-600 dark:text-gray-300 text-sm font-dm-sans">Desafíos</div>
              </div>
            </AnimatedSection>

            <AnimatedSection direction="up" delay={0.1}>
              <div className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-yellow-500/20 rounded-xl p-6 text-center">
                <Zap className="w-8 h-8 text-yellow-600 dark:text-yellow-400 mx-auto mb-3" />
                <div className="text-4xl font-bold text-yellow-600 dark:text-yellow-400 mb-2">{stats.totalPoints}</div>
                <div className="text-gray-600 dark:text-gray-300 text-sm font-dm-sans">Puntos Totales</div>
              </div>
            </AnimatedSection>

            <AnimatedSection direction="up" delay={0.2}>
              <div className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-purple-500/20 rounded-xl p-6 text-center">
                <Award className="w-8 h-8 text-purple-600 dark:text-purple-400 mx-auto mb-3" />
                <div className="text-4xl font-bold text-purple-600 dark:text-purple-400 mb-2">{stats.totalBadges}</div>
                <div className="text-gray-600 dark:text-gray-300 text-sm font-dm-sans">Badges</div>
              </div>
            </AnimatedSection>

            <AnimatedSection direction="up" delay={0.3}>
              <div className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-blue-500/20 rounded-xl p-6 text-center">
                <Clock className="w-8 h-8 text-blue-600 dark:text-blue-400 mx-auto mb-3" />
                <div className="text-4xl font-bold text-blue-600 dark:text-blue-400 mb-2">{stats.avgTime}min</div>
                <div className="text-gray-600 dark:text-gray-300 text-sm font-dm-sans">Tiempo Promedio</div>
              </div>
            </AnimatedSection>
          </div>
        </div>
      </section>

      {/* Filters */}
      <AnimatedSection direction="up" delay={0.4}>
        <section className="bg-white dark:bg-secondary py-8">
          <div className="container mx-auto px-6">
            <div className="flex flex-col md:flex-row gap-4 items-center justify-center">
              <div className="flex items-center gap-3">
                <label className="text-gray-900 dark:text-white font-semibold">Dificultad:</label>
                <select 
                  value={selectedDifficulty}
                  onChange={(e) => setSelectedDifficulty(e.target.value)}
                  className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-purple-500/20 rounded-lg px-4 py-2 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all"
                >
                  <option value="all">Todas</option>
                  <option value="beginner">Principiante</option>
                  <option value="intermediate">Intermedio</option>
                  <option value="advanced">Avanzado</option>
                  <option value="expert">Experto</option>
                  <option value="master">Maestro</option>
                </select>
              </div>

              <div className="flex items-center gap-3">
                <label className="text-gray-900 dark:text-white font-semibold">Categoría:</label>
                <select 
                  value={selectedCategory}
                  onChange={(e) => setSelectedCategory(e.target.value)}
                  className="bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] border border-gray-300 dark:border-purple-500/20 rounded-lg px-4 py-2 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-500 transition-all"
                >
                  <option value="all">Todas</option>
                  <option value="jailbreak">Jailbreak</option>
                  <option value="prompt-leaking">Prompt Leaking</option>
                  <option value="data-extraction">Data Extraction</option>
                  <option value="role-playing">Role Playing</option>
                  <option value="indirect-injection">Indirect Injection</option>
                  <option value="multi-step">Multi-Step</option>
                  <option value="adversarial">Adversarial</option>
                </select>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>

      {/* Challenges Grid */}
      <AnimatedSection direction="up" delay={0.5}>
        <div className="container mx-auto px-6 py-16">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
            {filteredChallenges.map((challenge, idx) => {
              const difficultyColors = {
                beginner: 'bg-green-100 dark:bg-green-500/20 border-green-300 dark:border-green-500/50 text-green-700 dark:text-green-300',
                intermediate: 'bg-yellow-100 dark:bg-yellow-500/20 border-yellow-300 dark:border-yellow-500/50 text-yellow-700 dark:text-yellow-300',
                advanced: 'bg-orange-100 dark:bg-orange-500/20 border-orange-300 dark:border-orange-500/50 text-orange-700 dark:text-orange-300',
                expert: 'bg-red-100 dark:bg-red-500/20 border-red-300 dark:border-red-500/50 text-red-700 dark:text-red-300',
                master: 'bg-purple-100 dark:bg-purple-500/20 border-purple-300 dark:border-purple-500/50 text-purple-700 dark:text-purple-300',
              };

              const Icon = getCategoryIcon(challenge.category);

              return (
                <AnimatedSection key={challenge.id} direction="up" delay={0.6 + idx * 0.05}>
                  <Link
                    href={`/lab/prompt-injection/${challenge.id}`}
                    className="group bg-gray-50 dark:bg-gradient-to-br dark:from-[#1B1663] dark:via-[#120D4F] dark:to-[#1B1663] rounded-2xl p-6 border border-gray-300 dark:border-purple-500/20 hover:border-purple-500 dark:hover:border-purple-400 hover:shadow-xl dark:hover:shadow-purple-500/20 transition-all duration-300 hover:scale-[1.02] block"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="p-3 bg-white dark:bg-gradient-to-br dark:from-purple-600 dark:to-pink-600 rounded-xl group-hover:scale-110 transition-transform">
                          <Icon className="w-6 h-6 text-purple-600 dark:text-white" />
                        </div>
                        <div>
                          <div className="text-sm text-gray-500 dark:text-gray-400 mb-1">Nivel {challenge.level}</div>
                          <h3 className="text-xl font-bold text-gray-900 dark:text-white group-hover:text-purple-600 dark:group-hover:text-purple-300 transition">
                            {challenge.title}
                          </h3>
                        </div>
                      </div>
                      <div className={`px-3 py-1 rounded-full text-xs font-semibold ${difficultyColors[challenge.difficulty]} border`}>
                        {challenge.difficulty.toUpperCase()}
                      </div>
                    </div>

                    <p className="text-gray-600 dark:text-gray-300 mb-4 line-clamp-2">
                      {challenge.description}
                    </p>

                    <div className="flex items-center justify-between text-sm">
                      <div className="flex items-center gap-4 text-gray-500 dark:text-gray-400">
                        <span className="flex items-center gap-1">
                          <Clock className="w-4 h-4" />
                          {challenge.estimatedTime} min
                        </span>
                        <span className="flex items-center gap-1">
                          <Target className="w-4 h-4" />
                          {challenge.points} pts
                        </span>
                      </div>
                      <span className="text-purple-600 dark:text-purple-400 font-semibold group-hover:translate-x-1 transition-transform flex items-center gap-1">
                        Intentar <ArrowRight className="w-4 h-4" />
                      </span>
                    </div>

                    {/* Tags */}
                    <div className="mt-4 flex flex-wrap gap-2">
                      {challenge.tags.slice(0, 3).map(tag => (
                        <span key={tag} className="px-2 py-1 bg-white/50 dark:bg-white/5 rounded-lg text-xs text-gray-600 dark:text-gray-400 border border-gray-200 dark:border-white/10">
                          {tag}
                        </span>
                      ))}
                    </div>
                  </Link>
                </AnimatedSection>
              );
            })}
          </div>
        </div>
      </AnimatedSection>

      {/* Info Section */}
      <AnimatedSection direction="up" delay={0.8}>
        <section className="bg-gradient-to-r from-purple-50 to-pink-50 dark:from-[#1B1663] dark:to-[#120D4F] py-16">
          <div className="container mx-auto px-6">
            <div className="bg-white dark:bg-gradient-to-br dark:from-[#1B1663]/80 dark:via-[#120D4F]/80 dark:to-[#1B1663]/80 rounded-2xl p-8 border border-gray-200 dark:border-purple-500/20 shadow-lg dark:shadow-purple-500/10">
              <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-3">
                <Brain className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                ¿Cómo funciona?
              </h2>
              <div className="grid md:grid-cols-3 gap-8">
                <div className="text-center">
                  <div className="w-16 h-16 bg-gradient-to-br from-purple-600 to-pink-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold mx-auto mb-4">
                    1
                  </div>
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-2 text-lg">Elige un desafío</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Selecciona un nivel acorde a tu experiencia. Empieza por los desafíos de principiante.</p>
                </div>
                <div className="text-center">
                  <div className="w-16 h-16 bg-gradient-to-br from-purple-600 to-pink-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold mx-auto mb-4">
                    2
                  </div>
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-2 text-lg">Ataca la IA</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Usa técnicas de prompt injection para lograr el objetivo. Sé creativo y persistente.</p>
                </div>
                <div className="text-center">
                  <div className="w-16 h-16 bg-gradient-to-br from-purple-600 to-pink-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold mx-auto mb-4">
                    3
                  </div>
                  <h3 className="font-semibold text-gray-900 dark:text-white mb-2 text-lg">Gana recompensas</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-300">Acumula puntos, desbloquea badges y escala en el ranking de red teamers.</p>
                </div>
              </div>
            </div>
          </div>
        </section>
      </AnimatedSection>
    </div>
  );
}

function getCategoryIcon(category: string) {
  const icons = {
    'jailbreak': Unlock,
    'prompt-leaking': Eye,
    'data-extraction': Database,
    'role-playing': Users,
    'indirect-injection': Mail,
    'multi-step': Link2,
    'adversarial': Brain,
  };
  return icons[category as keyof typeof icons] || Target;
}
