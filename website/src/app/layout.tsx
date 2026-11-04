import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Script from "next/script";
import ServiceWorker from "@/components/common/ServiceWorker";
import SiteShell from "@/components/docs/SiteShell";
import { getLevels, REPO_URL } from "@/lib/content";
import { themeInitScript } from "@/lib/theme";
import Providers from "@/providers/Providers";
import type { NavLevel } from "@/types/nav";
import "./globals.css";

const geistSans = Geist({
    variable: "--font-geist-sans",
    subsets: ["latin"],
});

const geistMono = Geist_Mono({
    variable: "--font-geist-mono",
    subsets: ["latin"],
});

const SITE_NAME = "Auth Mastery";
const DESCRIPTION =
    "Learn backend authentication and authorization step by step, in plain English: passwords, sessions, cookies, JWT, OAuth, MFA and enterprise SSO, with diagrams and runnable Node.js code.";

export const metadata: Metadata = {
    metadataBase: new URL(process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000"),
    title: {
        default: "Auth Mastery: backend authentication, level by level",
        template: "%s · Auth Mastery",
    },
    description: DESCRIPTION,
    applicationName: SITE_NAME,
    keywords: [
        "authentication",
        "authorization",
        "backend authentication tutorial",
        "Node.js authentication",
        "session based auth",
        "cookies",
        "JWT",
        "refresh tokens",
        "OAuth 2.0",
        "OpenID Connect",
        "MFA",
        "passkeys",
        "SSO",
        "RBAC",
        "web security",
    ],
    authors: [{ name: "Ashutosh Kumar", url: REPO_URL }],
    creator: "Ashutosh Kumar",
    category: "education",
    alternates: { canonical: "/" },
    openGraph: {
        type: "website",
        siteName: SITE_NAME,
        locale: "en_US",
        url: "/",
        title: "Auth Mastery: backend authentication, level by level",
        description: DESCRIPTION,
    },
    // Title, description and image fall back to the og: tags, so each page only sets those once
    twitter: { card: "summary_large_image" },
    robots: {
        index: true,
        follow: true,
        googleBot: { index: true, follow: true, "max-image-preview": "large", "max-snippet": -1 },
    },
    appleWebApp: {
        capable: true,
        statusBarStyle: "default",
        title: SITE_NAME,
    },
    formatDetection: { telephone: false },
};

export const viewport: Viewport = {
    width: "device-width",
    initialScale: 1,
    themeColor: [
        { media: "(prefers-color-scheme: light)", color: "#ffffff" },
        { media: "(prefers-color-scheme: dark)", color: "#16171d" },
    ],
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    const nav: NavLevel[] = getLevels().map((level) => ({
        number: level.number,
        title: level.title,
        href: level.href,
        topics: level.topics.map((t) => ({
            number: t.number,
            title: t.title,
            href: t.href,
            done: t.hasNotes,
        })),
    }));

    return (
        // The theme script sets data-theme before React loads, so the attribute differs from the server HTML
        <html
            lang="en"
            suppressHydrationWarning
            data-scroll-behavior="smooth"
            className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
        >
            <body className="min-h-full bg-bg text-fg">
                <Script id="theme-init" strategy="beforeInteractive">
                    {themeInitScript}
                </Script>
                <ServiceWorker />
                <Providers>
                    <SiteShell nav={nav} repoUrl={REPO_URL}>
                        {children}
                    </SiteShell>
                </Providers>
            </body>
        </html>
    );
}
