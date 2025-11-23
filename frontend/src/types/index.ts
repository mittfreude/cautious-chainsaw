export interface ThreatInterpretation {
  logsource: {
    category?: string
    product?: string
    service?: string
  }
  attack_behavior: string
  relevant_fields: string[]
  mitre_attack: string[]
  assumptions: string[]
}

export interface GeneratedRule {
  interpretation: ThreatInterpretation
  sigma_rule: string
  reviewed_rule?: string
}

export interface LogTestResult {
  log: string
  matches: boolean
}
