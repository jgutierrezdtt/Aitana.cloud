"use client";

import { useState } from "react";
import ApiPageWrapper from "@/components/ApiPageWrapper";

export default function SQLInjectionLab() {
  const [searchTerm, setSearchTerm] = useState("");
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleSearch = async () => {
    setLoading(true);
    try {
      const response = await fetch(`/api/lab/sqli?search=${encodeURIComponent(searchTerm)}`);
      const data = await response.json();
      setResults(data);
    } catch (error) {
      setResults({ error: "Error al ejecutar la consulta" });
    }
    setLoading(false);
  };

  const examples = [
    { name: "Búsqueda normal", value: "admin" },
    { name: "SQL Injection básico", value: "' OR '1'='1" },
    { name: "Comentario SQL", value: "admin'--" },
    { name: "UNION SELECT", value: "' UNION SELECT email, password, role FROM User--" },
  ];

  return (
    <ApiPageWrapper
      title="SQL Injection Lab"
      description="Explora vulnerabilidades de inyección SQL en consultas de base de datos. Esta API permite manipular queries SQL directamente."
      severity="critical"
      color="from-red-500 to-pink-600"
    >
      <div className="space-y-6">
        {/* Search Input */}
        <div>
          <label className="block text-gray-700 dark:text-blue-200 font-medium mb-2">
            Término de búsqueda:
          </label>
          <div className="flex gap-2">
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Ingresa tu búsqueda..."
              className="flex-1 px-4 py-3 bg-gray-50 dark:bg-white/10 border border-gray-300 dark:border-white/20 rounded-xl text-gray-900 dark:text-white placeholder-gray-400 dark:placeholder-blue-300/50 focus:outline-none focus:border-blue-500 dark:focus:border-blue-400 transition-colors"
              onKeyPress={(e) => e.key === 'Enter' && handleSearch()}
            />
            <button
              onClick={handleSearch}
              disabled={loading}
              className="px-6 py-3 bg-gradient-to-r from-red-500 to-pink-600 hover:from-red-600 hover:to-pink-700 text-white rounded-xl font-medium transition-all duration-200 shadow-lg disabled:opacity-50"
            >
              {loading ? "Buscando..." : "Buscar"}
            </button>
          </div>
        </div>

        {/* Examples */}
        <div>
          <h3 className="text-gray-700 dark:text-blue-200 font-medium mb-3">Ejemplos de payloads:</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {examples.map((example, index) => (
              <button
                key={index}
                onClick={() => setSearchTerm(example.value)}
                className="text-left p-4 bg-gray-100 dark:bg-white/5 hover:bg-gray-200 dark:hover:bg-white/10 border border-gray-200 dark:border-white/10 hover:border-blue-400 dark:hover:border-blue-400/50 rounded-xl transition-all"
              >
                <div className="text-gray-900 dark:text-blue-300 font-medium text-sm mb-1">{example.name}</div>
                <code className="text-xs text-gray-600 dark:text-blue-200/60 font-mono">{example.value}</code>
              </button>
            ))}
          </div>
        </div>

        {/* Results */}
        {results && (
          <div>
            <h3 className="text-gray-700 dark:text-blue-200 font-medium mb-3">Resultados:</h3>
            <div className="bg-gray-100 dark:bg-slate-900/50 border border-gray-300 dark:border-white/10 rounded-xl p-6 overflow-auto">
              <pre className="text-gray-800 dark:text-green-400 text-sm font-mono whitespace-pre-wrap">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
          </div>
        )}

        {/* Warning */}
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-400/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <svg className="w-6 h-6 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h4 className="text-red-700 dark:text-red-300 font-medium mb-1">Vulnerabilidad Crítica</h4>
              <p className="text-red-600 dark:text-red-200/70 text-sm">
                Este endpoint es vulnerable a SQL Injection. La entrada del usuario se concatena directamente en la query SQL sin sanitización.
              </p>
            </div>
          </div>
        </div>
      </div>
    </ApiPageWrapper>
  );
}
