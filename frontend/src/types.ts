export type RiskLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'INCONCLUSIVE' | 'UNKNOWN';

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
  forensic_errors?: Array<{ stage: string; message: string }>;
  degraded_engines?: string[];
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
  forensic_errors?: Array<{ stage: string; message: string }>;
  degraded_engines?: string[];
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
  schema_version: string;
  scan_id: string;
  scanned_at: string;
  scan_type: string;
  input_type: 'manual' | 'paste' | 'eml';

  // Scoring
  email_risk_score: number;
  link_risk_score: number;
  final_risk_score: number;
  verdict_label: 'safe' | 'suspicious' | 'malicious' | 'inconclusive';
  final_verdict_source: 'email' | 'link' | 'tie';

  analysis_quality: 'high' | 'medium' | 'low';
  confidence: { level: 'high' | 'medium' | 'low'; reasons: string[] };

  score_identity: number;
  score_linguistic: number;

  // Score Breakdown
  score_breakdown?: {
    email: Array<{ signal: string; points: number; reason: string }>;
    link: Array<{ url: string; points: number; reason: string }>;
  };

  // Failures / Partial Results
  forensic_errors: Array<{
    engine: string;
    message: string;
    retryable: boolean;
  }>;

  // Link Triage Explainability
  triage_stats: {
    total_found: number;
    analyzed: number;
    ignored: number;
    filtered: number;
    wrappers_unwrapped?: number;
    pii_scrubbed?: number;
    ignored_breakdown?: Record<string, number>;
    filtered_breakdown?: Record<string, number>;
  };

  // Identity
  identity: {
    subject: string;
    from: { name: string; email: string; domain: string };
    reply_to: { email: string; domain: string } | null;
    return_path: { email: string; domain: string } | null;
    mismatches: Array<string>;
    mailing_list_detected: boolean;
    mailing_list_signals?: string[];
  };

  // Authentication
  auth: {
    spf: string;
    dkim: string;
    dmarc: string;
    alignment: {
      dkim_aligned: boolean | null;
      spf_aligned: boolean | null;
      mode: string;
      notes?: string[];
    };
    provider_spam_signals: Array<{ header: string; value: string; parsed_score?: number }>;
    provider_flagged_spam: boolean;
  };

  // HTML Forensics
  html_findings: {
    link_mismatches: Array<{
      visible_text: string;
      href: string;
      visible_domain?: string;
      href_domain?: string;
      reason: string;
    }>;
    hidden_html: Array<{
      technique: string;
      snippet: string;
    }>;
    form_tags_found: boolean;
    zero_width_chars_found: boolean;
  };

  // Social Engineering
  social_engineering: {
    matches: Array<{
      category: string;
      keyword: string;
      snippet: string;
      confidence?: string;
    }>;
    cta_count: number;
  };

  // Evidence (PII-safe)
  evidence: {
    quoted_snippets: Array<{
      id: string;
      text: string;
      source: string;
      tags?: string[];
    }>;
  };

  // Attachments
  attachments: Array<{
    filename: string;
    mime_type: string;
    size_bytes: number;
    sha256: string;
    risk: 'low' | 'medium' | 'high';
    reasons: string[];
  }>;

  // Legacy compatibility / Link details (Optional)
  link_results: BackendScanResponse[];
  extracted_urls: string[];
  reasons: string[];
  deep_dive_target?: string;
  unwrap_events?: Array<{ found_url: string; destination_url: string; status: string; reason: string }>;
}
