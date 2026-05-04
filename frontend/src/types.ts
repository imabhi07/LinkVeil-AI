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
  type: 'url';
}

export interface EmailScanHistoryItem {
  id: string;
  type: 'email';
  timestamp: number;
  result: EmailScanResponse;
}

export type HistoryItem = ScanHistoryItem | EmailScanHistoryItem;
export interface EmailScanRequest {
  from_name?: string;
  from_email?: string;
  reply_to?: string;
  subject?: string;
  body?: string;
  raw_email?: string;
}

export interface EmailScanResponse {
  email_risk_score: number;
  email_risk_level: string;
  reasons: string[];
  suspicious_indicators: Record<string, boolean>;
  extracted_urls: string[];
  link_results: BackendScanResponse[];
  parsed_email?: {
    from_name?: string;
    from_email?: string;
    reply_to?: string;
    subject?: string;
    body?: string;
  };
  auth_results?: {
    spf: string;
    dkim: string;
    dmarc: string;
  };
  triage_stats?: Record<string, number>;
  skipped_urls?: Array<{ url: string; type: string; reason: string }>;
  scanned_count: number;
  total_extracted: number;
  heuristic_score: number;
  link_score: number;
  forensic_errors: Array<{ url: string; stage: string; message: string }>;
  deep_dive_target?: string;
  unwrap_events?: Array<{
    found_url: string;
    destination_url: string;
    status: string;
    reason: string;
  }>;
}
