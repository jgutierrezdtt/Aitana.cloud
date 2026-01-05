'use client';

import { useState, useEffect } from 'react';
import { useParams, useRouter } from 'next/navigation';
import Link from 'next/link';
import { getChallengeById } from '@/data/prompt-injection-challenges';
import { Challenge } from '@/types/prompt-injection';

export default function ChallengePage() {
  const params = useParams();
  const router = useRouter();
  const challengeId = params.id as string;

  const [challenge, setChallenge] = useState<Challenge | null>(null);
  const [userPrompt, setUserPrompt] = useState('');
  const [response, setResponse] = useState('');
  const [loading, setLoading] = useState(false);
  const [attackSuccess, setAttackSuccess] = useState<boolean | null>(null);
  const [secretExtracted, setSecretExtracted] = useState(false);
  const [pointsEarned, setPointsEarned] = useState(0);
  const [showHints, setShowHints] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [startTime, setStartTime] = useState(Date.now());

  useEffect(() => {
    const ch = getChallengeById(challengeId);
    if (ch) {
      setChallenge(ch);
    } else {
      router.push('/lab/prompt-injection');
    }
  }, [challengeId, router]);

  const handleSubmit = async () => {
    if (!userPrompt.trim() || !challenge) return;

    setLoading(true);
    setAttempts(prev => prev + 1);

    try {
      const res = await fetch('/api/ai/vulnerable-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          challengeId: challenge.id,
          userPrompt,
        }),
      });

      const data = await res.json();

      setResponse(data.response);
      setAttackSuccess(data.attackSuccess);
      setSecretExtracted(data.secretExtracted);
      setPointsEarned(data.pointsEarned);

      // Save to localStorage (simple progress tracking)
      if (data.attackSuccess || data.secretExtracted) {
        const completed = JSON.parse(localStorage.getItem('completedChallenges') || '[]');
        if (!completed.includes(challenge.id)) {
          completed.push(challenge.id);
          localStorage.setItem('completedChallenges', JSON.stringify(completed));
        }

        const totalPoints = parseInt(localStorage.getItem('totalPoints') || '0');
        localStorage.setItem('totalPoints', String(totalPoints + data.pointsEarned));
      }

    } catch (error) {
      console.error('Error:', error);
      setResponse('Error al comunicarse con la IA. Verifica tu configuración.');
      setAttackSuccess(false);
    } finally {
      setLoading(false);
    }
  };

  if (!challenge) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-white text-xl">Cargando desafío...</div>
      </div>
    );
  }

  const difficultyColors = {
    beginner: 'text-green-400',
    intermediate: 'text-yellow-400',
    advanced: 'text-orange-400',
    expert: 'text-red-400',
    master: 'text-purple-400',
  };

  const elapsedMinutes = Math.floor((Date.now() - startTime) / 60000);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-purple-900 to-indigo-900">
      {/* Navigation */}
      <nav className="bg-black/30 backdrop-blur-md border-b border-white/10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <Link href="/lab/prompt-injection" className="flex items-center gap-3 text-white hover:opacity-80 transition">
            <span className="text-2xl">←</span>
            <span className="font-semibold">Volver a desafíos</span>
          </Link>
          <div className="flex items-center gap-4 text-white/80 text-sm">
            <span>Nivel {challenge.level}</span>
            <span>•</span>
            <span>Intentos: {attempts}</span>
            <span>•</span>
            <span>Tiempo: {elapsedMinutes} min</span>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto px-6 py-12">
        <div className="grid md:grid-cols-3 gap-8">
          {/* Left Panel - Challenge Info */}
          <div className="md:col-span-1 space-y-6">
            {/* Challenge Header */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
              <div className="text-5xl mb-4">{getCategoryIcon(challenge.category)}</div>
              <h1 className="text-3xl font-black text-white mb-2">
                {challenge.title}
              </h1>
              <div className={`text-lg font-semibold mb-4 ${difficultyColors[challenge.difficulty]}`}>
                {challenge.difficulty.toUpperCase()}
              </div>
              <p className="text-gray-300 mb-4">
                {challenge.description}
              </p>
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="flex items-center gap-1">
                  ⏱️ {challenge.estimatedTime} min
                </span>
                <span className="flex items-center gap-1">
                  🎯 {challenge.points} pts
                </span>
              </div>
            </div>

            {/* Objective */}
            <div className="bg-blue-500/20 backdrop-blur-md rounded-2xl p-6 border border-blue-500/50">
              <h2 className="text-xl font-bold text-white mb-3 flex items-center gap-2">
                <span>🎯</span>
                Objetivo
              </h2>
              <p className="text-gray-200">
                {challenge.objective}
              </p>
            </div>

            {/* Hints */}
            <div className="bg-yellow-500/20 backdrop-blur-md rounded-2xl p-6 border border-yellow-500/50">
              <button
                onClick={() => setShowHints(!showHints)}
                className="w-full flex items-center justify-between text-xl font-bold text-white mb-3"
              >
                <span className="flex items-center gap-2">
                  <span>💡</span>
                  Pistas ({challenge.hints.length})
                </span>
                <span className="text-2xl">{showHints ? '▼' : '▶'}</span>
              </button>
              {showHints && (
                <ul className="space-y-2">
                  {challenge.hints.map((hint, idx) => (
                    <li key={idx} className="text-gray-200 text-sm flex items-start gap-2">
                      <span className="text-yellow-400 font-bold">{idx + 1}.</span>
                      <span>{hint}</span>
                    </li>
                  ))}
                </ul>
              )}
              {!showHints && (
                <p className="text-gray-300 text-sm">
                  Haz clic para revelar pistas si te atascas
                </p>
              )}
            </div>

            {/* Tags */}
            <div className="bg-white/5 backdrop-blur-md rounded-2xl p-6 border border-white/10">
              <h3 className="text-white font-semibold mb-3">Tags</h3>
              <div className="flex flex-wrap gap-2">
                {challenge.tags.map(tag => (
                  <span key={tag} className="px-3 py-1 bg-purple-500/20 border border-purple-500/50 rounded-full text-purple-300 text-xs">
                    {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Right Panel - Attack Interface */}
          <div className="md:col-span-2 space-y-6">
            {/* Input Area */}
            <div className="bg-white/10 backdrop-blur-md rounded-2xl p-6 border border-white/20">
              <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <span>⚔️</span>
                Tu Ataque de Prompt
              </h2>
              <textarea
                value={userPrompt}
                onChange={(e) => setUserPrompt(e.target.value)}
                placeholder="Escribe tu prompt de ataque aquí... Sé creativo y piensa como un red teamer."
                className="w-full h-48 bg-black/30 border border-white/20 rounded-xl p-4 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-purple-500 font-mono text-sm resize-none"
                disabled={loading}
              />
              <div className="mt-4 flex items-center justify-between">
                <div className="text-sm text-gray-400">
                  {userPrompt.length} caracteres
                </div>
                <button
                  onClick={handleSubmit}
                  disabled={loading || !userPrompt.trim()}
                  className="px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-bold rounded-xl disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300 hover:scale-105 shadow-lg"
                >
                  {loading ? '⚡ Atacando...' : '🚀 Lanzar Ataque'}
                </button>
              </div>
            </div>

            {/* Response Area */}
            {response && (
              <div className={`backdrop-blur-md rounded-2xl p-6 border-2 ${
                attackSuccess 
                  ? 'bg-green-500/20 border-green-500/50' 
                  : attackSuccess === false
                  ? 'bg-red-500/20 border-red-500/50'
                  : 'bg-white/10 border-white/20'
              }`}>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-2xl font-bold text-white flex items-center gap-2">
                    <span>🤖</span>
                    Respuesta de la IA
                  </h2>
                  {attackSuccess !== null && (
                    <div className={`px-4 py-2 rounded-full font-bold ${
                      attackSuccess 
                        ? 'bg-green-500 text-white' 
                        : 'bg-red-500 text-white'
                    }`}>
                      {attackSuccess ? '✅ ATAQUE EXITOSO' : '❌ BLOQUEADO'}
                    </div>
                  )}
                </div>

                <div className="bg-black/30 rounded-xl p-4 mb-4">
                  <pre className="text-gray-200 whitespace-pre-wrap font-mono text-sm">
                    {response}
                  </pre>
                </div>

                {secretExtracted && (
                  <div className="bg-yellow-500/20 border border-yellow-500/50 rounded-xl p-4 mb-4">
                    <div className="flex items-center gap-2 text-yellow-300 font-bold mb-2">
                      <span className="text-2xl">🏆</span>
                      ¡Dato secreto extraído!
                    </div>
                    <p className="text-gray-200 text-sm">
                      Has logrado extraer información confidencial: <code className="bg-black/30 px-2 py-1 rounded">{challenge.secretData}</code>
                    </p>
                  </div>
                )}

                {pointsEarned > 0 && (
                  <div className="flex items-center justify-between bg-purple-500/20 border border-purple-500/50 rounded-xl p-4">
                    <div>
                      <div className="text-purple-300 font-bold text-lg">Puntos Ganados</div>
                      <div className="text-gray-300 text-sm">¡Sigue así! Completa más desafíos para desbloquear badges.</div>
                    </div>
                    <div className="text-5xl font-black text-purple-300">
                      +{pointsEarned}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Educational Note */}
            <div className="bg-blue-500/10 backdrop-blur-md rounded-2xl p-6 border border-blue-500/30">
              <h3 className="text-white font-bold mb-3 flex items-center gap-2">
                <span>📚</span>
                Nota Educativa
              </h3>
              <p className="text-gray-300 text-sm mb-3">
                Este laboratorio utiliza IAs <strong>intencionalmente vulnerables</strong> para fines educativos. 
                En producción, los sistemas deben implementar:
              </p>
              <ul className="text-gray-400 text-sm space-y-1 list-disc list-inside">
                <li>Filtros de contenido robustos</li>
                <li>Validación de inputs y outputs</li>
                <li>Límites de rate y detección de anomalías</li>
                <li>System prompts seguros y probados</li>
                <li>Logging y monitoreo de ataques</li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function getCategoryIcon(category: string): string {
  const icons: Record<string, string> = {
    'jailbreak': '🔓',
    'prompt-leaking': '🕵️',
    'data-extraction': '💎',
    'role-playing': '🎭',
    'indirect-injection': '📧',
    'multi-step': '🔗',
    'adversarial': '🧠',
  };
  return icons[category] || '🎯';
}
