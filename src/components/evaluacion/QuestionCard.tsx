"use client";

import Link from "next/link";
import type { AssessmentQuestion } from "@/data/maturityAssessment";

interface QuestionCardProps {
  question: AssessmentQuestion;
  answer?: boolean;
  onAnswer: (value: boolean) => void;
}

export default function QuestionCard({ question, answer, onAnswer }: QuestionCardProps) {
  const isAnswered = answer !== undefined;

  return (
    <div
      className={`bg-slate-900/50 rounded-lg p-5 border transition-all ${
        isAnswered 
          ? answer 
            ? 'border-green-500/50 bg-green-500/5' 
            : 'border-red-500/50 bg-red-500/5'
          : 'border-slate-700'
      }`}
      role="group"
      aria-labelledby={`question-${question.id}`}
    >
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="px-2 py-0.5 bg-blue-500/20 text-blue-400 text-xs rounded font-semibold">
              Nivel {question.level}
            </span>
            {question.mitigates.length > 0 && (
              <span className="px-2 py-0.5 bg-purple-500/20 text-purple-400 text-xs rounded">
                MITRE ATT&CK
              </span>
            )}
          </div>
          <p id={`question-${question.id}`} className="text-white font-semibold mb-2">
            {question.question}
          </p>
          <p className="text-sm text-slate-400 mb-3">{question.description}</p>

          {/* Evidence */}
          <details className="text-xs text-slate-500 mb-3">
            <summary className="cursor-pointer hover:text-slate-400 focus:outline-none focus:text-slate-300">
              Evidencias esperadas
            </summary>
            <ul className="mt-2 ml-4 space-y-1" role="list">
              {question.evidence.map((ev, idx) => (
                <li key={idx}>• {ev}</li>
              ))}
            </ul>
          </details>

          {/* Frameworks */}
          <div className="flex flex-wrap gap-1 mb-2" role="list" aria-label="Frameworks relacionados">
            {question.frameworks.map((fw, idx) => (
              <span key={idx} className="px-2 py-0.5 bg-slate-700/50 text-slate-400 text-xs rounded">
                {fw.split(' ')[0]}
              </span>
            ))}
          </div>

          {/* Regulations */}
          {question.regulations.length > 0 && (
            <div className="flex flex-wrap gap-1" role="list" aria-label="Normativas aplicables">
              {question.regulations.map((reg, idx) => (
                <Link
                  key={idx}
                  href={`/normativas/${reg}`}
                  className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded hover:bg-green-500/30 transition-colors focus:outline-none focus:ring-2 focus:ring-green-500"
                  aria-label={`Ver normativa ${reg.toUpperCase()}`}
                >
                  {reg.toUpperCase()}
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="flex gap-2" role="group" aria-label={`Respuesta para: ${question.question}`}>
          <button
            onClick={() => onAnswer(true)}
            className={`px-4 py-2 rounded-lg font-semibold transition-all focus:outline-none focus:ring-2 focus:ring-green-500 ${
              answer === true
                ? 'bg-green-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
            aria-label="Sí"
            aria-pressed={answer === true}
          >
            ✓ Sí
          </button>
          <button
            onClick={() => onAnswer(false)}
            className={`px-4 py-2 rounded-lg font-semibold transition-all focus:outline-none focus:ring-2 focus:ring-red-500 ${
              answer === false
                ? 'bg-red-600 text-white'
                : 'bg-slate-700 text-slate-300 hover:bg-slate-600'
            }`}
            aria-label="No"
            aria-pressed={answer === false}
          >
            ✗ No
          </button>
        </div>
      </div>

      {/* Mitigations */}
      {question.mitigates.length > 0 && (
        <div className="mt-3 pt-3 border-t border-slate-700">
          <div className="text-xs text-slate-400 mb-1">Mitiga:</div>
          <div className="text-xs text-purple-400">
            {question.mitigates.join(' | ')}
          </div>
        </div>
      )}
    </div>
  );
}
