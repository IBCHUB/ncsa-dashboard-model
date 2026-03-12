import type { Metadata } from 'next';
import '@/styles/globals.css';
import Sidebar from '@/components/layout/Sidebar';

export const metadata: Metadata = {
  title: 'TCTI - Thailand Cyber Threat Intelligence',
  description: 'ระบบเชื่อมโยงข่าวกรองทางไซเบอร์ของประเทศไทย',
  keywords: ['cyber security', 'threat intelligence', 'IOC', 'Thailand'],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="th">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap"
          rel="stylesheet"
        />
        <script src="https://mcp.figma.com/mcp/html-to-design/capture.js" async />
      </head>
      <body>
        <div className="app-layout">
          <Sidebar />
          <main className="main-content">
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
