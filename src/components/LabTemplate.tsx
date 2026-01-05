"use client";

import { useState } from "react";
import ApiPageWrapper from "@/components/ApiPageWrapper";

interface LabTemplateProps {
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  color: string;
  apiEndpoint: string;
  examples?: { name: string; description: string; url: string }[];
  vulnerabilityInfo: string;
}

export default function LabTemplate({
  title,
  description,
  severity,
  color,
  apiEndpoint,
  examples = [],
  vulnerabilityInfo
}: LabTemplateProps) {
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [customUrl, setCustomUrl] = useState(apiEndpoint);

  const testEndpoint = async (url: string) => {
    setLoading(true);
    try {
      const res = await fetch(url);
      const data = await res.json();
      setResponse({ status: res.status, data });
    } catch (error: any) {
      setResponse({ error: error.message });
    }
    setLoading(false);
  };

  return (
    <ApiPageWrapper
      title={title}
      description={description}
      severity={severity}
      color={color}
    >
      <div className="space-y-6">
        {/* Custom URL Test */}
        <div>
          <label className="block text-blue-200 font-medium mb-2">
            Endpoint de la API:
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={customUrl}
              onChange={(e) => setCustomUrl(e.target.value)}
              className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-300/50 focus:outline-none focus:border-blue-400 transition-colors font-mono text-sm"
            />
            <button
              onClick={() => testEndpoint(customUrl)}
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-blue-500 to-cyan-500 hover:from-blue-600 hover:to-cyan-600 text-white rounded-xl font-medium transition-all duration-200 shadow-lg disabled:opacity-50"
            >
              {loading ? "Probando..." : "Probar"}
            </button>
          </div>
        </div>

        {/* Examples */}
        {examples.length > 0 && (
          <div>
            <h3 className="text-blue-200 font-medium mb-3">Ejemplos de explotación:</h3>
            <div className="grid grid-cols-1 gap-3">
              {examples.map((example, index) => (
                <div
                  key={index}
                  className="p-4 bg-white/5 border border-white/10 rounded-xl"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="text-blue-300 font-medium mb-1">{example.name}</div>
                      <p className="text-blue-200/60 text-sm mb-2">{example.description}</p>
                      <code className="text-xs text-green-400 font-mono break-all bg-slate-900/50 px-2 py-1 rounded">
                        {example.url}
                      </code>
                    </div>
                    <button
                      onClick={() => testEndpoint(example.url)}
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium transition-colors flex-shrink-0"
                    >
                      Ejecutar
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Response */}
        {response && (
          <div>
            <h3 className="text-blue-200 font-medium mb-3">Respuesta de la API:</h3>
            <div className="bg-slate-900/50 border border-white/10 rounded-xl p-6 overflow-auto">
              {response.status && (
                <div className="mb-3 text-blue-300 font-mono text-sm">
                  Status: <span className={response.status < 400 ? "text-green-400" : "text-red-400"}>{response.status}</span>
                </div>
              )}
              <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                {JSON.stringify(response.data || response, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* Vulnerability Info */}
        <div className={`${
          severity === 'critical' ? 'bg-red-500/10 border-red-400/30' :
          severity === 'high' ? 'bg-orange-500/10 border-orange-400/30' :
          'bg-yellow-500/10 border-yellow-400/30'
        } border rounded-xl p-4`}>
          <div className="flex items-start gap-3">
            <svg className={`w-6 h-6 ${
              severity === 'critical' ? 'text-red-400' :
              severity === 'high' ? 'text-orange-400' :
              'text-yellow-400'
            } flex-shrink-0 mt-0.5`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h4 className={`${
                severity === 'critical' ? 'text-red-300' :
                severity === 'high' ? 'text-orange-300' :
                'text-yellow-300'
              } font-medium mb-1`}>
                Vulnerabilidad {severity === 'critical' ? 'Crítica' : severity === 'high' ? 'Alta' : 'Media'}
              </h4>
              <p className={`${
                severity === 'critical' ? 'text-red-200/70' :
                severity === 'high' ? 'text-orange-200/70' :
                'text-yellow-200/70'
              } text-sm whitespace-pre-wrap`}>
                {vulnerabilityInfo}
              </p>
            </div>
          </div>
        </div>

        {/* Documentation Link */}
        <div className="flex justify-center pt-4">
          <a
            href="/api/openapi"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-6 py-3 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-blue-400/50 text-blue-300 rounded-xl transition-all"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Ver Documentación Completa de la API
          </a>
        </div>
      </div>
    </ApiPageWrapper>
  );
}
