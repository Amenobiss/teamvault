import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata = {
  title: "TeamVault",
  description: "Gestión segura de Claves CTCD Jaen",
  manifest: "/manifest.json",
  icons: {
    apple: "/teamvault_icon-192.png",
    icon: [
      { url: "/teamvault_icon-192.png", sizes: "192x192", type: "image/png" },
      { url: "/teamvault_icon-512.png", sizes: "512x512", type: "image/png" },
    ],
    shortcut: "/teamvault_icon-192.png",
  },
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "TeamVault",
  },
};

export default function RootLayout({ children }) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        <link rel="manifest" href="/manifest.json?v=1.4.4" />
        <link rel="icon" type="image/png" sizes="192x192" href="/teamvault_icon-192.png" />
        <link rel="icon" type="image/png" sizes="512x512" href="/teamvault_icon-512.png" />
        <link rel="shortcut icon" href="/teamvault_icon-192.png" />
        <link rel="apple-touch-icon" href="/teamvault_icon-192.png" />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}