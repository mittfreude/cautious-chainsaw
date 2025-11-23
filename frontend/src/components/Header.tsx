export default function Header() {
  return (
    <header className="bg-gradient-to-r from-blue-600 to-blue-800 text-white p-6 shadow-lg">
      <div className="container mx-auto">
        <h1 className="text-4xl font-bold flex items-center gap-3">
          <span>🛡️</span>
          <span>SigmaForge</span>
        </h1>
        <p className="text-blue-100 mt-2 text-lg">
          LLM-assisted Sigma Detection Rule Generator
        </p>
      </div>
    </header>
  )
}
