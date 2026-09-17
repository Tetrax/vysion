## Frontend (React/Vite scaffold)

This folder is ready for a lightweight React/Vite UI. Suggested structure:
- `src/pages/Upload.tsx` – upload FortiGate `.conf`, show basic metadata.
- `src/pages/AuditOptions.tsx` – configure WAN selection, UTM licence, MPLS.
- `src/pages/Results.tsx` – display audit summary and links to reports.
- `src/components/` – shared UI (buttons, forms, progress).

### Quickstart (to initialize)
```bash
npm create vite@latest frontend -- --template react-ts
cd frontend
npm install
npm run dev
```

Update `.env` with `VITE_API_BASE=http://localhost:8000`.







