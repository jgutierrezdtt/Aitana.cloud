"use client";

import type { AssessmentDomain } from "@/data/maturityAssessment";

interface DomainCardProps {
  domain: AssessmentDomain;
  index: number;
  isActive: boolean;
  progress: number;
  onClick: () => void;
}

export default function DomainCard({ domain, index, isActive, progress, onClick }: DomainCardProps) {
  return (
    <button
      onClick={onClick}
      className={`p-4 rounded-xl border transition-all focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 focus:ring-offset-slate-950 ${
        isActive
          ? `bg-gradient-to-br ${domain.color} border-white/20 shadow-xl scale-105`
          : 'bg-slate-800/50 border-slate-700 hover:border-slate-600 hover:scale-102'
      }`}
      aria-label={`${domain.name}: ${progress}% completado${isActive ? ', dominio actual' : ''}`}
      aria-pressed={isActive}
      aria-current={isActive ? 'step' : undefined}
      tabIndex={0}
    >
      <div className="text-3xl mb-2" aria-hidden="true">{domain.icon}</div>
      <div className={`text-sm font-semibold ${isActive ? 'text-white' : 'text-slate-300'}`}>
        {domain.name}
      </div>
      <div className="text-xs text-slate-400 mt-1" aria-label={`Progreso: ${progress}%`}>
        {progress}%
      </div>
    </button>
  );
}
