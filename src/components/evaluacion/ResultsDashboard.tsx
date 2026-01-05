"use client";

import Link from "next/link";
import type { AssessmentDomain } from "@/data/maturityAssessment";
import { generateRecommendations } from "@/data/maturityAssessment";
import MaturityChart from "./MaturityChart";
import RoadmapView from "./RoadmapView";
import AIInsightsButton from "./AIInsightsButton";
import { calculateRegulatoryCompliance } from "@/lib/regulatoryHelpers";

interface DomainScore {
  domain: AssessmentDomain;
  score: number;
}

interface ResultsDashboardProps {
  domainScores: DomainScore[];
  overallScore: number;
  responses: Record<string, boolean>;
  sector: string;
  sectorActions: Record<string, { short: string[]; medium: string[]; long: string[] }>;
  onReviewAnswers: () => void;
  onExportResults: () => void;
  projectedMaturity: (base: number) => number[];
}

export default function ResultsDashboard({
  domainScores,
  overallScore,
  responses,
  sector,
  sectorActions,
  onReviewAnswers,
  onExportResults,
  projectedMaturity
}: ResultsDashboardProps) {
  const getMaturityLevel = (score: number): { level: string; color: string; description: string } => {
    if (score === 0) return { level: 'Nivel 0: No implementado', color: 'text-red-500', description: 'Práctica no implementada' };
    if (score === 1) return { level: 'Nivel 1: Inicial', color: 'text-orange-500', description: 'Implementación básica, ad-hoc' };
    if (score === 2) return { level: 'Nivel 2: Gestionado', color: 'text-yellow-500', description: 'Procesos definidos pero no automatizados' };
    if (score === 3) return { level: 'Nivel 3: Definido', color: 'text-blue-500', description: 'Procesos estandarizados y documentados' };
    if (score === 4) return { level: 'Nivel 4: Cuantitativo', color: 'text-purple-500', description: 'Medición y control mediante métricas' };
    return { level: 'Nivel 5: Optimizado', color: 'text-green-500', description: 'Mejora continua y optimización' };
  };

  const overallMaturity = getMaturityLevel(overallScore);

  return (
    <div className="max-w-7xl mx-auto px-6 py-12">
      {/* Header */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold text-white mb-4">Resultados de Evaluación de Madurez SSDLC</h1>
        <p className="text-xl text-slate-300">Análisis completo de tu programa de seguridad de aplicaciones</p>
      </div>

      {/* Overall Score */}
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-2xl p-8 mb-8">
        <div className="text-center mb-6">
          <div className="text-6xl font-bold text-white mb-2">{overallScore}/5</div>
          <div className={`text-2xl font-bold ${overallMaturity.color} mb-2`}>
            {overallMaturity.level}
          </div>
          <div className="text-slate-400">{overallMaturity.description}</div>
        </div>

        <div className="grid grid-cols-5 gap-2 max-w-2xl mx-auto">
          {[0, 1, 2, 3, 4, 5].map(level => (
            <div
              key={level}
              className={`h-3 rounded-full ${
                level <= overallScore ? 'bg-gradient-to-r from-blue-500 to-purple-500' : 'bg-slate-700'
              }`}
            />
          ))}
        </div>
      </div>

      {/* Domain Scores */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
        {domainScores.map(({ domain, score }) => {
          const maturity = getMaturityLevel(score);
          const domainResponses = Object.fromEntries(
            domain.practices.flatMap(p => p.questions.map(q => [q.id, responses[q.id] || false]))
          );
          
          return (
            <div key={domain.id} className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
              <div className="flex items-center gap-3 mb-4">
                <div className="text-4xl">{domain.icon}</div>
                <div className="flex-1">
                  <h3 className="text-lg font-bold text-white">{domain.name}</h3>
                  <p className="text-sm text-slate-400">{domain.description}</p>
                </div>
              </div>

              <div className="flex items-center justify-between mb-2">
                <span className={`text-2xl font-bold ${maturity.color}`}>{score}/5</span>
                <span className="text-sm text-slate-400">{maturity.level}</span>
              </div>

              <div className="grid grid-cols-5 gap-1">
                {[1, 2, 3, 4, 5].map(level => (
                  <div
                    key={level}
                    className={`h-2 rounded-full ${
                      level <= score ? `bg-gradient-to-r ${domain.color}` : 'bg-slate-700'
                    }`}
                  />
                ))}
              </div>

              {/* Top Recommendations */}
              <div className="mt-4 pt-4 border-t border-slate-700">
                <div className="text-xs font-semibold text-slate-400 mb-2">Próximas Prioridades:</div>
                <ul className="space-y-1">
                  {generateRecommendations(domain, domainResponses, sector)
                    .slice(0, 3)
                    .map((rec, idx) => (
                      <li key={idx} className="text-xs text-slate-300 flex items-start gap-2">
                        <span className="text-blue-400 mt-0.5">▹</span>
                        <span>{rec}</span>
                      </li>
                    ))}
                </ul>
              </div>

              {/* AI Insights Button */}
              <div className="mt-4">
                <AIInsightsButton
                  domain={domain.name}
                  responses={domainResponses}
                  sector={sector}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Detailed Analysis */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-8">
        <h2 className="text-2xl font-bold text-white mb-6">Análisis Detallado por Framework</h2>
        
        {/* Sector-specific regulations callout */}
        <div className="bg-blue-900/20 border border-blue-700/50 rounded-lg p-4 mb-6">
          <div className="flex items-start gap-3">
            <div className="text-2xl">📋</div>
            <div className="flex-1">
              <div className="font-semibold text-blue-300 mb-2">
                Normativas Prioritarias para {sector.charAt(0).toUpperCase() + sector.slice(1)}
              </div>
              <div className="text-sm text-slate-300">
                {sector === 'financiero' && 'DORA, NIS2, PCI-DSS, GDPR, ISO 27001'}
                {sector === 'salud' && 'GDPR, HIPAA, IEC 81001, ISO 27001, NIS2'}
                {sector === 'industrial' && 'IEC 62443, ISO 21434, NIS2, CRA, ISO 27001'}
                {sector === 'tecnologia' && 'GDPR, ISO 27001, SOC 2, CRA, EU AI Act'}
                {sector === 'general' && 'ISO 27001, GDPR, NIST 800-53, NIS2, SOC 2'}
              </div>
              <div className="text-xs text-blue-400 mt-2">
                Las recomendaciones priorizan requisitos de estas normativas
              </div>
            </div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
          <div className="bg-slate-900/50 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Cobertura OWASP SAMM</div>
            <div className="text-2xl font-bold text-white">
              {Math.round((Object.values(responses).filter(v => v).length / Object.keys(responses).length) * 100)}%
            </div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Cumplimiento Normativo</div>
            <div className="text-2xl font-bold text-white">
              {domainScores.reduce((sum, ds) => sum + ds.score, 0) > 12 ? 'Alto' : domainScores.reduce((sum, ds) => sum + ds.score, 0) > 8 ? 'Medio' : 'Bajo'}
            </div>
          </div>
          <div className="bg-slate-900/50 rounded-lg p-4">
            <div className="text-sm text-slate-400 mb-1">Mitigación MITRE ATT&CK</div>
            <div className="text-2xl font-bold text-white">
              {(domainScores.find(ds => ds.domain.id === 'design')?.score ?? 0) >= 3 ? 'Efectiva' : 'Parcial'}
            </div>
          </div>
        </div>

        {/* Gap Analysis */}
        <div className="mb-6">
          <h3 className="text-lg font-bold text-white mb-4">Análisis de Brechas (Gap Analysis)</h3>
          <div className="space-y-3">
            {domainScores.filter(ds => ds.score < 3).map(({ domain, score }) => (
              <div key={domain.id} className="bg-slate-900/50 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-2xl">{domain.icon}</span>
                    <span className="font-semibold text-white">{domain.name}</span>
                  </div>
                  <span className="text-orange-500 text-sm font-semibold">Gap Identificado</span>
                </div>
                <p className="text-sm text-slate-400 mb-3">
                  Nivel actual: {score}/5 → Objetivo recomendado: Nivel 3 (Definido)
                </p>
                <div className="text-xs text-slate-300">
                  <span className="font-semibold">Impacto:</span> {
                    domain.id === 'governance' ? 'Alto riesgo de incumplimiento normativo y falta de dirección estratégica' :
                    domain.id === 'design' ? 'Vulnerabilidades arquitectónicas no detectadas tempranamente' :
                    domain.id === 'devsecops' ? 'Detección tardía de vulnerabilidades y falta de automatización' :
                    'Respuesta reactiva a incidentes y falta de visibilidad'
                  }
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Projected Maturity Charts */}
        <div className="mb-6">
          <h3 className="text-lg font-bold text-white mb-4">Proyección de Madurez por Dominio</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {domainScores.map(({ domain, score }) => (
              <MaturityChart
                key={domain.id}
                icon={domain.icon}
                name={domain.name}
                currentScore={score}
                projectedScores={projectedMaturity(score)}
                color={domain.color}
                shortActions={sectorActions[sector]?.short || []}
              />
            ))}
          </div>
        </div>

        {/* Roadmap */}
        <RoadmapView 
          sector={sector} 
          sectorActions={sectorActions[sector] || { short: [], medium: [], long: [] }} 
        />
      </div>

      {/* Regulatory Compliance Section */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-xl p-6 mb-8">
        <h2 className="text-2xl font-bold text-white mb-6">Cumplimiento Normativo Estimado</h2>
        <p className="text-sm text-slate-400 mb-4">
          Basado en tus respuestas, estimamos tu nivel de cumplimiento con las normativas clave de tu sector
        </p>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {calculateRegulatoryCompliance(responses, sector).map((item) => (
            <div key={item.regulation} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-white">{item.regulation}</span>
                  {item.critical && (
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">
                      Crítica
                    </span>
                  )}
                </div>
                <span className={`text-lg font-bold ${
                  item.coverage >= 80 ? 'text-green-500' :
                  item.coverage >= 60 ? 'text-yellow-500' :
                  item.coverage >= 40 ? 'text-orange-500' :
                  'text-red-500'
                }`}>
                  {item.coverage}%
                </span>
              </div>
              
              <div className="w-full bg-slate-700 rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all ${
                    item.coverage >= 80 ? 'bg-green-500' :
                    item.coverage >= 60 ? 'bg-yellow-500' :
                    item.coverage >= 40 ? 'bg-orange-500' :
                    'bg-red-500'
                  }`}
                  style={{ width: `${Math.min(100, Math.max(0, item.coverage))}%` }}
                />
              </div>
              
              <div className="mt-2 text-xs text-slate-400">
                {item.coverage >= 80 ? 'Cumplimiento alto' :
                 item.coverage >= 60 ? 'Cumplimiento aceptable' :
                 item.coverage >= 40 ? 'Requiere mejoras' :
                 'Cumplimiento bajo - acción urgente'}
              </div>
            </div>
          ))}
        </div>
        
        <div className="mt-6 p-4 bg-amber-900/20 border border-amber-700/50 rounded-lg">
          <div className="flex items-start gap-3">
            <span className="text-2xl">⚠️</span>
            <div className="flex-1">
              <div className="font-semibold text-amber-300 mb-1">Nota Importante</div>
              <div className="text-sm text-slate-300">
                Esta es una estimación aproximada basada en tus respuestas. Para certificación oficial,
                se requiere una auditoría formal por parte de un organismo acreditado.
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-4 justify-center">
        <button
          onClick={onReviewAnswers}
          className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white rounded-xl font-semibold transition-all"
        >
          Revisar Respuestas
        </button>
        <button
          onClick={onExportResults}
          className="px-6 py-3 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-500 hover:to-purple-500 text-white rounded-xl font-semibold transition-all"
        >
          Exportar Resultados
        </button>
        <Link
          href="/matriz-normativas"
          className="px-6 py-3 bg-green-600 hover:bg-green-500 text-white rounded-xl font-semibold transition-all"
        >
          Ver Matriz de Normativas
        </Link>
      </div>
    </div>
  );
}
