interface SidebarProps {
  inputMode: 'threat' | 'logs'
  setInputMode: (mode: 'threat' | 'logs') => void
  modelName: string
  setModelName: (model: string) => void
  temperature: number
  setTemperature: (temp: number) => void
}

export default function Sidebar({
  inputMode,
  setInputMode,
  modelName,
  setModelName,
  temperature,
  setTemperature,
}: SidebarProps) {
  return (
    <aside className="w-80 bg-white border-r border-gray-200 p-6 shadow-sm">
      <div className="space-y-6">
        {/* Input Mode Selection */}
        <div>
          <h3 className="text-lg font-semibold mb-3 text-gray-800">Input Mode</h3>
          <div className="space-y-2">
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="radio"
                name="inputMode"
                value="threat"
                checked={inputMode === 'threat'}
                onChange={(e) => setInputMode(e.target.value as 'threat' | 'logs')}
                className="w-4 h-4 text-blue-600"
              />
              <span className="text-gray-700">Threat description</span>
            </label>
            <label className="flex items-center space-x-2 cursor-pointer">
              <input
                type="radio"
                name="inputMode"
                value="logs"
                checked={inputMode === 'logs'}
                onChange={(e) => setInputMode(e.target.value as 'threat' | 'logs')}
                className="w-4 h-4 text-blue-600"
              />
              <span className="text-gray-700">Example logs</span>
            </label>
          </div>
        </div>

        {/* Model Configuration */}
        <div>
          <h3 className="text-lg font-semibold mb-3 text-gray-800">Model Configuration</h3>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Model
            </label>
            <select
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="gpt-4o-mini">gpt-4o-mini (fast, cost-effective)</option>
              <option value="gpt-4o">gpt-4o (more capable)</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Temperature: {temperature.toFixed(1)}
            </label>
            <input
              type="range"
              min="0"
              max="1"
              step="0.1"
              value={temperature}
              onChange={(e) => setTemperature(parseFloat(e.target.value))}
              className="w-full h-2 bg-gray-200 rounded-lg appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-xs text-gray-500 mt-1">
              <span>Precise (0.0)</span>
              <span>Creative (1.0)</span>
            </div>
          </div>
        </div>

        {/* About Section */}
        <div className="pt-6 border-t border-gray-200">
          <h3 className="text-lg font-semibold mb-3 text-gray-800">About</h3>
          <p className="text-sm text-gray-600 leading-relaxed">
            SigmaForge uses AI to generate Sigma detection rules from threat descriptions
            or example log lines. Sigma is a generic signature format for SIEM systems.
          </p>
          <div className="mt-4 p-3 bg-blue-50 rounded-lg">
            <p className="text-xs text-blue-800">
              💡 <strong>Tip:</strong> Start with a clear threat description or 2-3 example log lines.
            </p>
          </div>
        </div>
      </div>
    </aside>
  )
}
