"use client";

import { useState } from "react";
import ApiPageWrapper from "@/components/ApiPageWrapper";

export default function XSSLab() {
  const [input, setInput] = useState("");
  const [reflect, setReflect] = useState(true);
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleTest = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/lab/xss?input=${encodeURIComponent(input)}&reflect=${reflect}`);
      const data = await response.json();
      setResults(data);
    } catch (error) {
      setResults({ error: "Error al ejecutar el test" });
    }
    setLoading(false);
  };

  const examples = [
    { name: "Alert básico", value: "<script>alert('XSS')</script>" },
    { name: "Img onerror", value: "<img src=x onerror=alert('XSS')>" },
    { name: "SVG onload", value: "<svg onload=alert('XSS')>" },
    { name: "Input autofocus", value: "<input autofocus onfocus=alert('XSS')>" },
  ];

  return (
    <ApiPageWrapper
      title="Cross-Site Scripting (XSS) Lab"
      description="Demuestra ataques XSS y ejecución de scripts maliciosos. Aprende cómo los atacantes pueden inyectar código JavaScript."
      severity="high"
      color="from-orange-500 to-red-500"
    >
      <div className="space-y-6">
        {/* Input */}
        <div>
          <label className="block text-blue-200 font-medium mb-2">
            Payload XSS:
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ingresa tu payload XSS..."
              className="flex-1 px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-300/50 focus:outline-none focus:border-orange-400 transition-colors"
              onKeyPress={(e) => e.key === 'Enter' && handleTest()}
            />
            <button
              onClick={handleTest}
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-orange-500 to-red-500 hover:from-orange-600 hover:to-red-600 text-white rounded-xl font-medium transition-all duration-200 shadow-lg disabled:opacity-50"
            >
              {loading ? "Probando..." : "Probar"}
            </button>
          </div>
        </div>

        {/* Options */}
        <div>
          <label className="flex items-center gap-2 text-blue-200 cursor-pointer">
            <input
              type="checkbox"
              checked={reflect}
              onChange={(e) => setReflect(e.target.checked)}
              className="w-4 h-4 rounded border-white/20 bg-white/10 text-orange-500 focus:ring-orange-500 focus:ring-offset-0"
            />
            <span>Reflejar entrada en la respuesta (XSS Reflejado)</span>
          </label>
        </div>

        {/* Examples */}
        <div>
          <h3 className="text-blue-200 font-medium mb-3">Ejemplos de payloads XSS:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {examples.map((example, index) => (
              <button
                key={index}
                onClick={() => setInput(example.value)}
                className="text-left p-4 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-orange-400/50 rounded-xl transition-all"
              >
                <div className="text-orange-300 font-medium text-sm mb-1">{example.name}</div>
                <code className="text-xs text-blue-200/60 font-mono break-all">{example.value}</code>
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        {results && (
          <div>
            <h3 className="text-blue-200 font-medium mb-3">Resultados:</h3>
            <div className="bg-slate-900/50 border border-white/10 rounded-xl p-6 overflow-auto">
              <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
            
            {results.reflected && (
              <div className="mt-4 p-4 bg-orange-500/10 border border-orange-400/30 rounded-xl">
                <div className="text-orange-300 font-medium mb-2">Contenido reflejado:</div>
                <div className="bg-slate-900/50 p-3 rounded-lg">
                  <div dangerouslySetInnerHTML={{ __html: results.reflected }} />
                </div>
              </div>
            )}
          </div>
        )}

        {/* Warning */}
        <div className="bg-orange-500/10 border border-orange-400/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <svg className="w-6 h-6 text-orange-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h4 className="text-orange-300 font-medium mb-1">Vulnerabilidad Alta</h4>
              <p className="text-orange-200/70 text-sm">
                Este endpoint es vulnerable a XSS. La entrada del usuario se refleja en la respuesta sin sanitización, permitiendo la ejecución de scripts arbitrarios.
              </p>
            </div>
          </div>
        </div>
      </div>
    </ApiPageWrapper>
  );
}
