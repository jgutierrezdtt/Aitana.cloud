"use client";

import { useState, useEffect } from "react";
import Navigation from "@/components/Navigation";
import Link from "next/link";
import { maturityDomains, calculateDomainMaturity, type AssessmentDomain } from "@/data/maturityAssessment";
import SectorSelector from "@/components/evaluacion/SectorSelector";
import DomainCard from "@/components/evaluacion/DomainCard";
import QuestionCard from "@/components/evaluacion/QuestionCard";
import ResultsDashboard from "@/components/evaluacion/ResultsDashboard";
import { sectorActions, projectedMaturity } from "@/lib/maturityHelpers";

export default function MaturityAssessmentPage() {
  const [currentDomain, setCurrentDomain] = useState(0);
  const [responses, setResponses] = useState<Record<string, boolean>>(() => {
    try {
      if (typeof window !== 'undefined') {
        const saved = localStorage.getItem('ssdlc_responses');
        return saved ? JSON.parse(saved) : {};
      }
      return {};
    } catch (e) {
      return {};
    }
  });
  const [showResults, setShowResults] = useState(false);
  const [sector, setSector] = useState<string>(() => {
    try {
      return (typeof window !== 'undefined' && localStorage.getItem('ssdlc_sector')) || 'general';
    } catch (e) {
      return 'general';
    }
  });
  const [lastSaved, setLastSaved] = useState<Date | null>(null);

  useEffect(() => {
    try {
      localStorage.setItem('ssdlc_sector', sector);
    } catch (e) {
      // ignore
    }
  }, [sector]);

  useEffect(() => {
    try {
      localStorage.setItem('ssdlc_responses', JSON.stringify(responses));
      if (Object.keys(responses).length > 0) {
        setLastSaved(new Date());
      }
    } catch (e) {
      // ignore
    }
  }, [responses]);

  const domain = maturityDomains[currentDomain];

  const handleResponse = (questionId: string, value: boolean) => {
    setResponses(prev => ({ ...prev, [questionId]: value }));
  };

  const getTotalQuestions = (domain: AssessmentDomain) => {
    return domain.practices.reduce((sum, practice) => sum + practice.questions.length, 0);
  };

  const getAnsweredQuestions = (domain: AssessmentDomain) => {
    const domainQuestionIds = domain.practices.flatMap(p => p.questions.map(q => q.id));
    return domainQuestionIds.filter(id => responses[id] !== undefined).length;
  };

  const getProgress = () => {
    const totalQuestions = maturityDomains.reduce((sum, d) => sum + getTotalQuestions(d), 0);
    const answeredQuestions = Object.keys(responses).length;
    return Math.round((answeredQuestions / totalQuestions) * 100);
  };

  const nextDomain = () => {
    if (currentDomain < maturityDomains.length - 1) {
      setCurrentDomain(currentDomain + 1);
    } else {
      setShowResults(true);
    }
  };

  const prevDomain = () => {
    if (currentDomain > 0) {
      setCurrentDomain(currentDomain - 1);
    }
  };

  const handleExportResults = () => {
    const domainScores = maturityDomains.map(d => ({
      domain: d.name,
      score: calculateDomainMaturity(
        Object.fromEntries(
          d.practices.flatMap(p => p.questions.map(q => [q.id, responses[q.id] || false]))
        )
      )
    }));

    const overallScore = Math.round(
      domainScores.reduce((sum, ds) => sum + ds.score, 0) / domainScores.length
    );

    const data = JSON.stringify({ 
      sector,
      responses, 
      domainScores, 
      overallScore,
      exportDate: new Date().toISOString()
    }, null, 2);
    
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `maturity-assessment-${sector}-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
  };

  const handleClearProgress = () => {
    if (confirm('¿Estás seguro de que quieres borrar todo el progreso? Esta acción no se puede deshacer.')) {
      setResponses({});
      setCurrentDomain(0);
      setShowResults(false);
      setLastSaved(null);
      try {
        localStorage.removeItem('ssdlc_responses');
      } catch (e) {
        // ignore
      }
    }
  };

  if (showResults) {
    const domainScores = maturityDomains.map(d => ({
      domain: d,
      score: calculateDomainMaturity(
        Object.fromEntries(
          d.practices.flatMap(p => p.questions.map(q => [q.id, responses[q.id] || false]))
        )
      )
    }));

    const overallScore = Math.round(
      domainScores.reduce((sum, ds) => sum + ds.score, 0) / domainScores.length
    );

    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
        <Navigation />
        <ResultsDashboard
          domainScores={domainScores}
          overallScore={overallScore}
          responses={responses}
          sector={sector}
          sectorActions={sectorActions}
          onReviewAnswers={() => {
            setShowResults(false);
            setCurrentDomain(0);
          }}
          onExportResults={handleExportResults}
          projectedMaturity={projectedMaturity}
        />
      </div>
    );
  }

  const totalQuestionsInDomain = getTotalQuestions(domain);
  const answeredInDomain = getAnsweredQuestions(domain);
  const domainProgress = Math.round((answeredInDomain / totalQuestionsInDomain) * 100);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950">
      {/* Skip to main content link (accessibility) */}
      <a 
        href="#main-content" 
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-blue-600 focus:text-white focus:rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
      >
        Saltar al contenido principal
      </a>
      
      <Navigation />

      <main id="main-content" className="max-w-5xl mx-auto px-6 py-12" role="main">
        {/* Header */}
        <header className="mb-8">
          <nav aria-label="Breadcrumb" className="flex items-center gap-3 mb-4">
            <Link 
              href="/guias" 
              className="text-slate-400 hover:text-white transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:rounded"
            >
              ← Guías
            </Link>
          </nav>
          
          <h1 className="text-4xl font-bold text-white mb-4">
            Evaluación de Madurez SSDLC
          </h1>
          <p className="text-xl text-slate-300 mb-6">
            Evalúa tu programa de seguridad de aplicaciones basado en OWASP SAMM, BSIMM, NIST SSDF y frameworks regulatorios
          </p>

          <SectorSelector sector={sector} onChange={setSector} />

          {/* Auto-save indicator */}
          {lastSaved && (
            <div 
              className="mb-4 flex items-center justify-between bg-green-900/20 border border-green-700/50 rounded-lg px-4 py-2"
              role="status"
              aria-live="polite"
            >
              <div className="flex items-center gap-2">
                <span className="text-green-400" aria-hidden="true">✓</span>
                <span className="text-sm text-green-300">
                  Progreso guardado automáticamente
                </span>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-xs text-green-400">
                  {lastSaved.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' })}
                </span>
                <button
                  onClick={handleClearProgress}
                  className="text-xs text-red-400 hover:text-red-300 underline focus:outline-none focus:ring-2 focus:ring-red-500 focus:rounded"
                  aria-label="Borrar todo el progreso de la evaluación"
                >
                  Borrar progreso
                </button>
              </div>
            </div>
          )}

          {/* Overall Progress */}
          <div 
            className="bg-slate-800/50 border border-slate-700 rounded-xl p-4"
            role="progressbar"
            aria-valuenow={getProgress()}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-label="Progreso global de la evaluación"
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-semibold text-slate-300">Progreso Global</span>
              <span className="text-sm text-slate-400">{getProgress()}% completado</span>
            </div>
            <div className="w-full bg-slate-700 rounded-full h-2">
              <div
                className="bg-gradient-to-r from-blue-500 to-purple-500 h-2 rounded-full transition-all duration-300"
                style={{ width: `${getProgress()}%` }}
              />
            </div>
          </div>
        </header>

        {/* Domain Navigation */}
        <nav 
          className="grid grid-cols-4 gap-3 mb-8"
          role="navigation"
          aria-label="Selección de dominio de evaluación"
        >
          {maturityDomains.map((d, idx) => {
            const totalQ = getTotalQuestions(d);
            const answered = Object.keys(responses).filter(k => 
              d.practices.flatMap(p => p.questions.map(q => q.id)).includes(k)
            ).length;
            const progress = Math.round((answered / totalQ) * 100);

            return (
              <DomainCard
                key={d.id}
                domain={d}
                index={idx}
                isActive={currentDomain === idx}
                progress={progress}
                onClick={() => setCurrentDomain(idx)}
              />
            );
          })}
        </nav>

        {/* Current Domain */}
        <section className={`bg-gradient-to-br ${domain.color} rounded-2xl p-1 mb-8`} aria-labelledby="current-domain-title">
          <div className="bg-slate-900 rounded-xl p-6">
            <div className="flex items-center gap-4 mb-4">
              <div className="text-5xl" aria-hidden="true">{domain.icon}</div>
              <div className="flex-1">
                <h2 id="current-domain-title" className="text-2xl font-bold text-white mb-2">{domain.name}</h2>
                <p className="text-slate-300">{domain.description}</p>
              </div>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Progreso en este dominio</span>
              <span className="text-slate-300">{answeredInDomain} de {totalQuestionsInDomain} preguntas</span>
            </div>
            <div 
              className="w-full bg-slate-700 rounded-full h-2 mt-2"
              role="progressbar"
              aria-valuenow={domainProgress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Progreso en ${domain.name}`}
            >
              <div
                className={`bg-gradient-to-r ${domain.color} h-2 rounded-full transition-all duration-300`}
                style={{ width: `${domainProgress}%` }}
              />
            </div>
          </div>
        </section>

        {/* Questions */}
        <div className="space-y-6 mb-8" role="list" aria-label="Preguntas de evaluación">
          {domain.practices.map((practice) => (
            <article key={practice.id} className="bg-slate-800/50 border border-slate-700 rounded-xl p-6" role="listitem">
              <h3 className="text-xl font-bold text-white mb-2">{practice.name}</h3>
              <p className="text-sm text-slate-400 mb-4">{practice.description}</p>

              <div className="space-y-4" role="list" aria-label={`Preguntas de ${practice.name}`}>
                {practice.questions.map((question) => (
                  <QuestionCard
                    key={question.id}
                    question={question}
                    answer={responses[question.id]}
                    onAnswer={(value) => handleResponse(question.id, value)}
                  />
                ))}
              </div>
            </article>
          ))}
        </div>

        {/* Navigation */}
        <nav className="flex items-center justify-between" role="navigation" aria-label="Navegación entre dominios">
          <button
            onClick={prevDomain}
            disabled={currentDomain === 0}
            className={`px-6 py-3 rounded-xl font-semibold transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 ${
              currentDomain === 0
                ? 'bg-slate-800 text-slate-600 cursor-not-allowed'
                : 'bg-slate-700 hover:bg-slate-600 text-white'
            }`}
            aria-label="Ir al dominio anterior"
          >
            ← Anterior
          </button>

          <div className="text-center">
            <div className="text-sm text-slate-400 mb-1">
              Dominio {currentDomain + 1} de {maturityDomains.length}
            </div>
            <div className="flex gap-2">
              {maturityDomains.map((_, idx) => (
                <div
                  key={idx}
                  className={`w-2 h-2 rounded-full ${
                    idx === currentDomain ? 'bg-blue-500' : 'bg-slate-700'
                  }`}
                />
              ))}
            </div>
          </div>

          <button
            onClick={nextDomain}
            className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-xl font-semibold transition-all shadow-xl focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-950"
            aria-label={currentDomain === maturityDomains.length - 1 ? 'Ver resultados de la evaluación' : 'Ir al siguiente dominio'}
          >
            {currentDomain === maturityDomains.length - 1 ? 'Ver Resultados →' : 'Siguiente →'}
          </button>
        </nav>
      </main>
    </div>
  );
}
