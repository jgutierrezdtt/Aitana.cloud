"use client";

import { useState } from "react";
import ApiPageWrapper from "@/components/ApiPageWrapper";

export default function BrokenAuthLab() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [response, setResponse] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password })
      });
      const data = await res.json();
      setResponse({ status: res.status, data });
    } catch (error: any) {
      setResponse({ error: error.message });
    }
    setLoading(false);
  };

  const credentials = [
    { email: "admin@vulnerable-app.com", password: "admin123", role: "Admin" },
    { email: "user@example.com", password: "password123", role: "User" },
    { email: "test@test.com", password: "test", role: "User" }
  ];

  return (
    <ApiPageWrapper
      title="Broken Authentication"
      description="Sistemas de autenticación débiles y vulnerables que permiten acceso no autorizado"
      severity="critical"
      color="from-rose-500 to-red-600"
    >
      <div className="space-y-6">
        {/* Login Form */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-blue-200 font-medium mb-2">Email:</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="email@example.com"
              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-300/50 focus:outline-none focus:border-rose-400 transition-colors"
            />
          </div>
          <div>
            <label className="block text-blue-200 font-medium mb-2">Password:</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-xl text-white placeholder-blue-300/50 focus:outline-none focus:border-rose-400 transition-colors"
            />
          </div>
        </div>

        <button
          onClick={handleLogin}
          disabled={loading}
          className="w-full px-6 py-3 bg-gradient-to-r from-rose-500 to-red-600 hover:from-rose-600 hover:to-red-700 text-white rounded-xl font-medium transition-all duration-200 shadow-lg disabled:opacity-50"
        >
          {loading ? "Iniciando sesión..." : "Iniciar Sesión"}
        </button>

        {/* Default Credentials */}
        <div>
          <h3 className="text-blue-200 font-medium mb-3">Credenciales por defecto (vulnerabilidad):</h3>
          <div className="grid grid-cols-1 gap-3">
            {credentials.map((cred, index) => (
              <button
                key={index}
                onClick={() => { setEmail(cred.email); setPassword(cred.password); }}
                className="text-left p-4 bg-white/5 hover:bg-white/10 border border-white/10 hover:border-rose-400/50 rounded-xl transition-all"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-rose-300 font-medium text-sm mb-1">{cred.role}</div>
                    <code className="text-xs text-blue-200/60 font-mono">{cred.email} / {cred.password}</code>
                  </div>
                  <span className="text-blue-400 text-sm">Click para usar</span>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Response */}
        {response && (
          <div>
            <h3 className="text-blue-200 font-medium mb-3">Respuesta:</h3>
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

        {/* Vulnerabilities */}
        <div className="bg-red-500/10 border border-red-400/30 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <svg className="w-6 h-6 text-red-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <div>
              <h4 className="text-red-300 font-medium mb-2">Vulnerabilidades Críticas de Autenticación:</h4>
              <ul className="text-red-200/70 text-sm space-y-1 list-disc list-inside">
                <li>Contraseñas almacenadas en texto plano en la base de datos</li>
                <li>Credenciales por defecto conocidas (admin/admin123)</li>
                <li>JWT con secreto débil y expuesto en variables de entorno</li>
                <li>Sin límite de intentos de login (permite fuerza bruta)</li>
                <li>Tokens almacenados en localStorage (vulnerable a XSS)</li>
                <li>Sin verificación de email o autenticación de dos factores</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </ApiPageWrapper>
  );
}
