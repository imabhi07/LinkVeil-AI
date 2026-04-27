export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface AnalysisDetails {
  urlStructure: string;
  domainReputation: string;
  socialEngineeringTricks: string;
  forensicDeepDive?: string;
  visualPrediction?: string;
}

export interface AgentReport {
  activeProbing: {
    performed: boolean;
    credentialsUsed: string;
    outcome: string;
    behaviorRisk: 'HIGH' | 'MEDIUM' | 'LOW' | 'Unknown';
    reachable?: boolean;
    loginFormFound?: boolean;
    fieldsFilled?: boolean;
    acceptedFakeCredentials?: boolean;
    postSubmitRedirect?: string;
    pageTitle?: string;
    finalUrl?: string;
    screenshotPath?: string;
    redirectChain?: string[];
    formFields?: Record<string, any>;
    contentSnippet?: string;
  };
}

export interface AnalysisResult {
  url: string;
  riskScore: number;
  riskLevel: RiskLevel;
  verdictTitle: string;
  recommendation?: string;
  reasoning: string[];
  technicalDetails: AnalysisDetails;
  mitigationAdvice?: string[];
  agentReport: AgentReport;
  timestamp: number;
  
  // New Forensic Artifacts
  whois_info?: Record<string, any>;
  threat_intel?: Record<string, any>;
  visual_forensics?: Record<string, any>;
  fusion_trace?: Record<string, any>;
  probe_artifacts?: Record<string, any>;
}

export interface BackendScanResponse {
  url: string;
  risk_score: number;
  risk_level: string;
  recommendation?: string;
  explanation: string;
  brand_impersonation: boolean;
  brand_name: string | null;
  verdictTitle: string;
  technicalDetails: Record<string, any>;
  mitigationAdvice: string[];
  agentReport: Record<string, any>;
  whois_info?: Record<string, any>;
  threat_intel?: Record<string, any>;
  visual_forensics?: Record<string, any>;
  fusion_trace?: Record<string, any>;
  probe_artifacts?: Record<string, any>;
}

export interface ScanHistoryItem extends AnalysisResult {
  id: string;
}
