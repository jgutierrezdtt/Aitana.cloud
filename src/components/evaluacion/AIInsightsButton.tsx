'use client';

import { useState } from 'react';
import { useAIAnalysis } from '@/hooks/useAIAnalysis';
import { Sparkles, AlertCircle, Loader2 } from 'lucide-react';

interface AIInsightsButtonProps {
  domain: string;
  responses: Record<string, boolean>;
  sector: string;
}

export default function AIInsightsButton({ 
  domain, 
  responses, 
  sector 
}: AIInsightsButtonProps) {
  const { analyzeResponses, loading, error } = useAIAnalysis();
  const [insights, setInsights] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState(false);

  const handleAnalyze = async () => {
    if (insights && !isExpanded) {
      setIsExpanded(true);
      return;
    }

    const result = await analyzeResponses(domain, responses, sector);
    if (result) {
      setInsights(result);
      setIsExpanded(true);
    }
  };

  return (
    <div className="space-y-4">
      {/* Botón principal */}
      <button
        onClick={handleAnalyze}
        disabled={loading}
        className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-white rounded-lg hover:from-purple-700 hover:to-pink-700 transition-all disabled:opacity-50 disabled:cursor-not-allowed shadow-lg hover:shadow-xl"
        aria-label="Analizar con IA"
      >
        {loading ? (
          <>
            <Loader2 className="w-5 h-5 animate-spin" aria-hidden="true" />
            <span>Analizando con IA...</span>
          </>
        ) : (
          <>
            <Sparkles className="w-5 h-5" aria-hidden="true" />
            <span>{insights ? 'Ver Análisis de IA' : '🤖 Análisis Inteligente'}</span>
          </>
        )}
      </button>

      {/* Error */}
      {error && (
        <div 
          className="p-4 bg-red-500/10 border border-red-500 rounded-lg flex items-start gap-3"
          role="alert"
        >
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" aria-hidden="true" />
          <div>
            <p className="font-semibold text-red-400">Error en el análisis</p>
            <p className="text-sm text-red-300 mt-1">{error}</p>
            <p className="text-xs text-slate-400 mt-2">
              💡 Asegúrate de tener configurado OLLAMA_BASE_URL (local) o TOGETHER_API_KEY (producción)
            </p>
          </div>
        </div>
      )}

      {/* Insights */}
      {insights && isExpanded && (
        <div className="p-6 bg-gradient-to-br from-purple-500/10 to-pink-500/10 border border-purple-500/30 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-purple-400 flex items-center gap-2">
              <Sparkles className="w-5 h-5" aria-hidden="true" />
              Insights de IA
            </h3>
            <button
              onClick={() => setIsExpanded(false)}
              className="text-sm text-slate-400 hover:text-white transition-colors"
              aria-label="Cerrar insights"
            >
              Cerrar
            </button>
          </div>
          
          <div className="prose prose-invert prose-sm max-w-none">
            <div className="whitespace-pre-wrap text-slate-200 leading-relaxed">
              {insights}
            </div>
          </div>

          <div className="pt-3 border-t border-purple-500/20 flex items-center gap-2 text-xs text-slate-500">
            <span>Generado con IA</span>
            <span>•</span>
            <span>Verifica las recomendaciones con tu equipo</span>
          </div>
        </div>
      )}
    </div>
  );
}
