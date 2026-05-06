import type { AnalysisResult, RiskLevel, BackendScanResponse, AgentReport } from '../types';

/**
 * Map the backend's ScanResponse → prototype's AnalysisResult
 */
export function mapToAnalysisResult(raw: BackendScanResponse): AnalysisResult {
  let riskLevel: RiskLevel;
  let verdictTitle: string;
  
  switch (raw.risk_level?.toLowerCase()) {
    case 'high':
    case 'malicious':
      riskLevel = 'MALICIOUS';
      verdictTitle = 'Malicious Site Detected';
      break;
    case 'medium':
    case 'suspicious':
      riskLevel = 'SUSPICIOUS';
      verdictTitle = 'Suspicious Activity Found';
      break;
    case 'low':
    case 'safe':
      riskLevel = 'SAFE';
      verdictTitle = 'Verified Safe';
      break;
    default:
      riskLevel = 'UNKNOWN';
      verdictTitle = 'Analysis Inconclusive';
  }
  
  if (raw.verdictTitle) {
    if (riskLevel === 'MALICIOUS' && raw.verdictTitle.toUpperCase().includes('SUSPICIOUS')) {
      verdictTitle = raw.verdictTitle.replace(/suspicious/i, 'MALICIOUS');
    } else if (riskLevel === 'SUSPICIOUS' && raw.verdictTitle.toUpperCase().includes('MALICIOUS')) {
      verdictTitle = raw.verdictTitle.replace(/malicious/i, 'SUSPICIOUS');
    } else {
      verdictTitle = raw.verdictTitle;
    }
  }

  const reasoning = raw.explanation
    ? raw.explanation.split(/\n+/).filter((s: string) => s.trim().length > 0)
    : ['No detailed findings available.'];

  // Map backend agent report
  const rawAgentData = raw.agentReport || {};
  const activeProbing = rawAgentData.activeProbing || rawAgentData; 
  
  const mappedAgentReport: AgentReport = {
    activeProbing: {
      ...activeProbing, // Spread all properties from backend
      performed: !!activeProbing?.performed,
      credentialsUsed: activeProbing?.credentialsUsed || 'test_admin@linkveil.local / ●●●●●●●●',
      outcome: activeProbing?.outcome || 'No outcome reported by agent.',
      behaviorRisk: (activeProbing?.behaviorRisk || 'Unknown') as any,
      screenshotPath: activeProbing?.screenshotPath
    }
  };

  let urlStructure = raw.url;
  try {
    const u = new URL(raw.url.includes('://') ? raw.url : `http://${raw.url}`);
    urlStructure = `Protocol: ${u.protocol} | Host: ${u.hostname} | Path: ${u.pathname}`;
  } catch { /* use raw url */ }

  const techSource = raw.technicalDetails || {};
  
  const technicalDetails = {
    urlStructure: techSource.urlDeepDive || urlStructure,
    domainReputation: (() => {
      const whoisText = raw.whois_info?.domain_age_days != null
        ? `\n\nWHOIS EVIDENCE:\n• Age: ${raw.whois_info.domain_age_days} days\n• Registrar: ${raw.whois_info.registrar || 'Unknown'}${raw.whois_info.is_new_domain ? '\n• ⚠️ WARNING: RECENTLY REGISTERED' : ''}${raw.whois_info.has_privacy ? '\n• Privacy Protection: ENABLED' : ''}`
        : "";
      
      if (techSource.domainForensics) {
        return techSource.domainForensics + whoisText;
      }
      return whoisText.trim() || (riskLevel === 'SAFE' ? 'Domain registration appears legitimate.' : 'Domain reputation check inconclusive.');
    })(),
    socialEngineeringTricks: techSource.socialEngineering || (raw.brand_impersonation
      ? `Impersonates ${raw.brand_name} branding to trick users into submitting credentials.`
      : 'No social engineering patterns detected.'),
    visualPrediction: raw.visual_forensics?.brand_match 
      ? `Visual logo match detected for ${raw.visual_forensics.brand_match} (score: ${raw.visual_forensics.score})`
      : 'No visual logo matches detected.'
  };

  return {
    url: raw.url,
    riskScore: Math.round(raw.risk_score),
    riskLevel,
    verdictTitle,
    recommendation: raw.recommendation,
    reasoning,
    technicalDetails,
    agentReport: mappedAgentReport,
    timestamp: Date.now(),
    whois_info: raw.whois_info,
    threat_intel: raw.threat_intel,
    visual_forensics: raw.visual_forensics,
    fusion_trace: raw.fusion_trace,
    mitigationAdvice: raw.mitigationAdvice,
    probe_artifacts: raw.probe_artifacts,
    forensic_errors: raw.forensic_errors || [],
    degraded_engines: raw.degraded_engines || []
  };
}
