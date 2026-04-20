export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface AnalysisDetails {
  urlStructure: string;
  domainReputation: string;
  socialEngineeringTricks: string;
  forensicDeepDive?: string;
  visualPrediction?: string;
}

export interface WebSource {
  title: string;
  uri: string;
}

export interface AgentReport {
  activeProbing: {
    performed: boolean;
    credentialsUsed: string;
    outcome: string;
    behaviorRisk: 'HIGH' | 'MEDIUM' | 'LOW';
  };
  visualForensics: {
    analyzed: boolean;
    brandImpersonation: string;
    hostingMismatch: string;
  };
}

export interface AnalysisResult {
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  verdictTitle: string;
  reasoning: string[];
  technicalDetails: AnalysisDetails;
  mitigationAdvice?: string[];
  agentReport: AgentReport;
  webSources: WebSource[];
  timestamp: number;
}

export interface ScanHistoryItem extends AnalysisResult {
  id: string;
}
