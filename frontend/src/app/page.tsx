'use client'

import { useState } from 'react'
import Header from '@/components/Header'
import Sidebar from '@/components/Sidebar'
import InputPanel from '@/components/InputPanel'
import OutputPanel from '@/components/OutputPanel'
import { GeneratedRule, ThreatInterpretation } from '@/types'

export default function Home() {
  const [inputMode, setInputMode] = useState<'threat' | 'logs'>('threat')
  const [modelName, setModelName] = useState('gpt-4o-mini')
  const [temperature, setTemperature] = useState(0.3)
  const [generatedRule, setGeneratedRule] = useState<GeneratedRule | null>(null)
  const [isLoading, setIsLoading] = useState(false)

  return (
    <main className="min-h-screen bg-gray-50">
      <Header />
      <div className="flex">
        <Sidebar
          inputMode={inputMode}
          setInputMode={setInputMode}
          modelName={modelName}
          setModelName={setModelName}
          temperature={temperature}
          setTemperature={setTemperature}
        />
        <div className="flex-1 p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <InputPanel
              inputMode={inputMode}
              modelName={modelName}
              temperature={temperature}
              setGeneratedRule={setGeneratedRule}
              isLoading={isLoading}
              setIsLoading={setIsLoading}
              generatedRule={generatedRule}
            />
            <OutputPanel
              generatedRule={generatedRule}
              isLoading={isLoading}
            />
          </div>
        </div>
      </div>
    </main>
  )
}
