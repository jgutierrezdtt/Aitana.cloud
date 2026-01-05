/**
 * Types for Prompt Injection Lab
 * Educational platform for AI security testing
 */

export type DifficultyLevel = 'beginner' | 'intermediate' | 'advanced' | 'expert' | 'master';

export type AttackCategory = 
  | 'jailbreak'           // Bypass safety filters
  | 'prompt-leaking'      // Extract system prompts
  | 'data-extraction'     // Steal confidential data
  | 'indirect-injection'  // Attacks via external data
  | 'role-playing'        // Manipulation via personas
  | 'multi-step'          // Chain attacks
  | 'adversarial';        // Advanced adversarial prompts

export interface Challenge {
  id: string;
  level: number;
  title: string;
  description: string;
  difficulty: DifficultyLevel;
  category: AttackCategory;
  objective: string;
  hints: string[];
  points: number;
  
  // Success criteria
  successPatterns: string[];  // Regex patterns for success detection
  forbiddenPatterns: string[]; // Should NOT appear in response
  
  // Vulnerable AI configuration
  systemPrompt: string;
  secretData?: string;        // Hidden data to extract
  
  // Metadata
  estimatedTime: number;      // minutes
  attempts?: number;          // max attempts before hint
  tags: string[];
}

export interface ChallengeAttempt {
  challengeId: string;
  userPrompt: string;
  aiResponse: string;
  success: boolean;
  timestamp: Date;
  executionTime: number;      // ms
}

export interface UserProgress {
  userId?: string;            // Optional for anonymous users
  completedChallenges: string[];
  totalPoints: number;
  badges: Badge[];
  attempts: ChallengeAttempt[];
  currentStreak: number;      // consecutive days
  bestCategory: AttackCategory;
}

export interface Badge {
  id: string;
  name: string;
  description: string;
  icon: string;
  category: AttackCategory | 'special';
  requirement: string;
  earnedAt?: Date;
  rarity: 'common' | 'rare' | 'epic' | 'legendary';
}

export interface LeaderboardEntry {
  rank: number;
  username: string;
  points: number;
  completedChallenges: number;
  badges: number;
  favCategory: AttackCategory;
  lastActive: Date;
}

export interface AIResponse {
  content: string;
  blocked: boolean;           // If safety filter triggered
  metadata: {
    provider: string;
    model: string;
    tokensUsed: number;
    latency: number;
  };
}

export interface VulnerabilityReport {
  challengeId: string;
  vulnerabilityType: AttackCategory;
  exploitUsed: string;
  impact: 'low' | 'medium' | 'high' | 'critical';
  mitigation: string[];
  owaspMapping?: string;      // OWASP LLM Top 10 reference
}
