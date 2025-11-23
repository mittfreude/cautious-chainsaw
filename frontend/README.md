# SigmaForge Frontend (Next.js)

Modern React-based frontend for SigmaForge, built with Next.js and TypeScript.

## 🚀 Quick Start

### Prerequisites

- Node.js 18.x or higher
- npm or yarn
- Running SigmaForge FastAPI backend on port 8000

### Installation

1. Install dependencies:
```bash
cd frontend
npm install
```

2. Configure environment variables:
```bash
cp .env.local.example .env.local
```

Edit `.env.local` to set your API URL (default: `http://localhost:8000`).

3. Start the development server:
```bash
npm run dev
```

The application will be available at http://localhost:3000

## 📦 Build for Production

```bash
npm run build
npm start
```

## 🏗️ Project Structure

```
frontend/
├── src/
│   ├── app/                  # Next.js app directory
│   │   ├── layout.tsx        # Root layout
│   │   ├── page.tsx          # Home page
│   │   └── globals.css       # Global styles
│   ├── components/           # React components
│   │   ├── Header.tsx        # App header
│   │   ├── Sidebar.tsx       # Configuration sidebar
│   │   ├── InputPanel.tsx    # Input form
│   │   └── OutputPanel.tsx   # Results display
│   ├── lib/                  # Utilities
│   │   └── api.ts            # API client
│   └── types/                # TypeScript types
│       └── index.ts          # Type definitions
├── public/                   # Static assets
├── package.json              # Dependencies
├── tsconfig.json             # TypeScript config
├── tailwind.config.js        # Tailwind CSS config
└── next.config.js            # Next.js config
```

## 🎨 Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **HTTP Client**: Axios
- **State Management**: React hooks (useState)

## 🔌 API Integration

The frontend communicates with the FastAPI backend through three main endpoints:

- `POST /api/generate` - Generate Sigma rules
- `POST /api/review` - Review and improve rules
- `POST /api/test-logs` - Test log matching

API client is located in `src/lib/api.ts`.

## 🎯 Features

- 🎨 Modern, responsive UI
- 🚀 Fast page loads with Next.js
- 📱 Mobile-friendly design
- 🎭 Dark mode support (system preference)
- ♿ Accessible components
- 🔄 Real-time feedback
- 📥 Download generated rules as .yml files
- 🧪 Quick log testing functionality

## 📝 Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NEXT_PUBLIC_API_URL` | Backend API URL | `http://localhost:8000` |

## 🛠️ Development

### Code Style

This project uses TypeScript strict mode and follows React best practices.

### Available Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm start` - Start production server
- `npm run lint` - Run ESLint

## 🐛 Troubleshooting

### API Connection Issues

If the frontend can't connect to the backend:

1. Ensure the backend is running on the correct port
2. Check CORS settings in `backend/main.py`
3. Verify `.env.local` has the correct `NEXT_PUBLIC_API_URL`

### Build Errors

Clear Next.js cache:
```bash
rm -rf .next
npm run build
```

## 📄 License

Same as the main SigmaForge project.
