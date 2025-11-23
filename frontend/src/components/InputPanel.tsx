'use client'

import { useState } from 'react'
import { generateRule, reviewRule } from '@/lib/api'
import { GeneratedRule } from '@/types'

interface InputPanelProps {
  inputMode: 'threat' | 'logs'
  modelName: string
  temperature: number
  setGeneratedRule: (rule: GeneratedRule | null) => void
  isLoading: boolean
  setIsLoading: (loading: boolean) => void
  generatedRule: GeneratedRule | null
}

export default function InputPanel({
  inputMode,
  modelName,
  temperature,
  setGeneratedRule,
  isLoading,
  setIsLoading,
  generatedRule,
}: InputPanelProps) {
  const [input, setInput] = useState('')
  const [error, setError] = useState<string | null>(null)

  const placeholderText = inputMode === 'threat'
    ? `Example: "Detect when a user creates a new scheduled task via schtasks.exe to establish persistence. The task name often contains suspicious keywords like 'update', 'chrome', or random strings."`
    : `Example log lines:
2024-01-15 14:23:45 EventID=4698 TaskName=\\Microsoft\\Windows\\UpdateTask CommandLine="powershell.exe -enc <base64>"
2024-01-15 14:24:12 EventID=4698 TaskName=\\ChromeUpdate CommandLine="cmd.exe /c whoami"`

  const handleGenerate = async () => {
    if (!input.trim()) {
      setError('Please enter a threat description or example logs')
      return
    }

    setError(null)
    setIsLoading(true)

    try {
      const result = await generateRule({
        input: input.trim(),
        input_mode: inputMode,
        model_name: modelName,
        temperature,
      })
      setGeneratedRule(result)
    } catch (err: any) {
      setError(err.message || 'Failed to generate rule. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  const handleReview = async () => {
    if (!generatedRule) return

    setError(null)
    setIsLoading(true)

    try {
      const result = await reviewRule({
        sigma_rule: generatedRule.sigma_rule,
        model_name: modelName,
        temperature,
      })
      setGeneratedRule({
        ...generatedRule,
        reviewed_rule: result.reviewed_rule,
      })
    } catch (err: any) {
      setError(err.message || 'Failed to review rule. Please try again.')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="bg-white rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-bold mb-4 text-gray-800">
        {inputMode === 'threat' ? '📝 Threat Description' : '📋 Example Logs'}
      </h2>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder={placeholderText}
        className="w-full h-64 p-4 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
        disabled={isLoading}
      />

      {error && (
        <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
          <p className="text-red-800 text-sm">❌ {error}</p>
        </div>
      )}

      <div className="mt-4 flex gap-3">
        <button
          onClick={handleGenerate}
          disabled={isLoading}
          className={`flex-1 py-3 px-6 rounded-lg font-semibold text-white transition-colors ${
            isLoading
              ? 'bg-gray-400 cursor-not-allowed'
              : 'bg-blue-600 hover:bg-blue-700 active:bg-blue-800'
          }`}
        >
          {isLoading ? '⏳ Generating...' : '🚀 Generate Sigma Rule'}
        </button>

        {generatedRule && !generatedRule.reviewed_rule && (
          <button
            onClick={handleReview}
            disabled={isLoading}
            className={`py-3 px-6 rounded-lg font-semibold transition-colors ${
              isLoading
                ? 'bg-gray-400 text-white cursor-not-allowed'
                : 'bg-green-600 text-white hover:bg-green-700 active:bg-green-800'
            }`}
          >
            {isLoading ? '⏳ Reviewing...' : '🔍 Review & Improve Rule'}
          </button>
        )}
      </div>
    </div>
  )
}
