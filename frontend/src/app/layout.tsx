import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'SigmaForge - LLM-assisted Sigma Detection Rule Generator',
  description: 'Generate Sigma detection rules using AI',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}
