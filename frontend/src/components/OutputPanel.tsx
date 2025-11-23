'use client'

import { useState } from 'react'
import { GeneratedRule, LogTestResult } from '@/types'
import { testLogs } from '@/lib/api'

interface OutputPanelProps {
  generatedRule: GeneratedRule | null
  isLoading: boolean
}

export default function OutputPanel({ generatedRule, isLoading }: OutputPanelProps) {
  const [testInput, setTestInput] = useState('')
  const [testResults, setTestResults] = useState<LogTestResult[]>([])
  const [isTesting, setIsTesting] = useState(false)

  const handleDownload = () => {
    if (!generatedRule) return

    const ruleToDownload = generatedRule.reviewed_rule || generatedRule.sigma_rule
    const blob = new Blob([ruleToDownload], { type: 'text/yaml' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'sigma_rule.yml'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const handleTestLogs = async () => {
    if (!generatedRule || !testInput.trim()) return

    setIsTesting(true)
    try {
      const ruleToTest = generatedRule.reviewed_rule || generatedRule.sigma_rule
      const results = await testLogs({
        sigma_rule: ruleToTest,
        log_lines: testInput.trim().split('\n').filter(line => line.trim()),
      })
      setTestResults(results)
    } catch (err) {
      console.error('Failed to test logs:', err)
    } finally {
      setIsTesting(false)
    }
  }

  if (isLoading) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6 flex items-center justify-center h-96">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600 text-lg">Generating your Sigma rule...</p>
        </div>
      </div>
    )
  }

  if (!generatedRule) {
    return (
      <div className="bg-white rounded-lg shadow-md p-6 flex items-center justify-center h-96">
        <div className="text-center text-gray-500">
          <p className="text-xl mb-2">👈 Start by entering a threat description or example logs</p>
          <p className="text-sm">Your generated Sigma rule will appear here</p>
        </div>
      </div>
    )
  }

  const { interpretation } = generatedRule
  const displayRule = generatedRule.reviewed_rule || generatedRule.sigma_rule

  return (
    <div className="space-y-6">
      {/* Threat Interpretation */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-bold mb-4 text-gray-800">🎯 Threat Interpretation</h2>

        <div className="space-y-4">
          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Log Source</h3>
            <div className="bg-gray-50 p-3 rounded">
              {interpretation.logsource.category && (
                <p className="text-sm"><strong>Category:</strong> {interpretation.logsource.category}</p>
              )}
              {interpretation.logsource.product && (
                <p className="text-sm"><strong>Product:</strong> {interpretation.logsource.product}</p>
              )}
              {interpretation.logsource.service && (
                <p className="text-sm"><strong>Service:</strong> {interpretation.logsource.service}</p>
              )}
            </div>
          </div>

          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Attack Behavior</h3>
            <p className="text-sm text-gray-600 bg-gray-50 p-3 rounded">{interpretation.attack_behavior}</p>
          </div>

          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Relevant Fields</h3>
            <div className="flex flex-wrap gap-2">
              {interpretation.relevant_fields.map((field, idx) => (
                <span key={idx} className="px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                  {field}
                </span>
              ))}
            </div>
          </div>

          <div>
            <h3 className="font-semibold text-gray-700 mb-2">MITRE ATT&CK</h3>
            <div className="flex flex-wrap gap-2">
              {interpretation.mitre_attack.map((technique, idx) => (
                <span key={idx} className="px-3 py-1 bg-red-100 text-red-800 rounded-full text-sm">
                  {technique}
                </span>
              ))}
            </div>
          </div>

          <div>
            <h3 className="font-semibold text-gray-700 mb-2">Assumptions & Limitations</h3>
            <ul className="list-disc list-inside space-y-1 text-sm text-gray-600">
              {interpretation.assumptions.map((assumption, idx) => (
                <li key={idx}>{assumption}</li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* Generated Sigma Rule */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-2xl font-bold text-gray-800">
            {generatedRule.reviewed_rule ? '✨ Reviewed Sigma Rule' : '📜 Generated Sigma Rule'}
          </h2>
          <button
            onClick={handleDownload}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition-colors font-semibold"
          >
            ⬇️ Download .yml
          </button>
        </div>

        <pre className="bg-gray-900 text-green-400 p-4 rounded-lg overflow-x-auto text-sm font-mono">
          {displayRule}
        </pre>
      </div>

      {/* Log Testing */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h2 className="text-2xl font-bold mb-4 text-gray-800">🧪 Quick Log Sanity Check</h2>

        <textarea
          value={testInput}
          onChange={(e) => setTestInput(e.target.value)}
          placeholder="Paste test log lines here (one per line)..."
          className="w-full h-32 p-3 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm mb-3"
        />

        <button
          onClick={handleTestLogs}
          disabled={isTesting || !testInput.trim()}
          className={`w-full py-2 px-4 rounded-lg font-semibold text-white transition-colors ${
            isTesting || !testInput.trim()
              ? 'bg-gray-400 cursor-not-allowed'
              : 'bg-purple-600 hover:bg-purple-700'
          }`}
        >
          {isTesting ? '⏳ Testing...' : '🔬 Test Logs'}
        </button>

        {testResults.length > 0 && (
          <div className="mt-4 space-y-2">
            {testResults.map((result, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border ${
                  result.matches
                    ? 'bg-green-50 border-green-200'
                    : 'bg-gray-50 border-gray-200'
                }`}
              >
                <div className="flex items-start gap-2">
                  <span className="text-lg">{result.matches ? '✅' : '⚪'}</span>
                  <code className="text-sm flex-1">{result.log}</code>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
