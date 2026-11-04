"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import ThemeSelect from "@/components/common/ThemeSelect";
import type { NavLevel } from "@/types/nav";
import Search from "./Search";
import Sidebar from "./Sidebar";

export default function SiteShell({
    nav,
    repoUrl,
    children,
}: {
    nav: NavLevel[];
    repoUrl: string;
    children: React.ReactNode;
}) {
    const pathname = usePathname();
    const [menuOpen, setMenuOpen] = useState(false);
    const [lastPath, setLastPath] = useState(pathname);

    // Close the mobile menu after navigating to another page
    if (pathname !== lastPath) {
        setLastPath(pathname);
        setMenuOpen(false);
    }

    useEffect(() => {
        if (!menuOpen) return;
        const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenuOpen(false);
        window.addEventListener("keydown", onKey);
        // Stop the page behind the open menu from scrolling
        document.body.style.overflow = "hidden";
        return () => {
            window.removeEventListener("keydown", onKey);
            document.body.style.overflow = "";
        };
    }, [menuOpen]);

    return (
        <>
            <a
                href="#main"
                className="sr-only z-50 rounded bg-accent px-3 py-2 text-accent-fg focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
            >
                Skip to content
            </a>

            <header className="sticky top-0 z-30 h-16 border-b border-border bg-header/90 backdrop-blur">
                <div className="mx-auto flex h-full max-w-[1600px] items-center gap-2 px-3 sm:gap-3 sm:px-6">
                    <button
                        type="button"
                        onClick={() => setMenuOpen((o) => !o)}
                        aria-label={menuOpen ? "Close menu" : "Open menu"}
                        aria-expanded={menuOpen}
                        aria-controls="sidebar"
                        className="grid h-10 w-10 place-items-center rounded-lg border border-border text-lg text-fg lg:hidden"
                    >
                        {menuOpen ? "✕" : "☰"}
                    </button>
                    <Link href="/" className="text-lg font-extrabold tracking-tight whitespace-nowrap min-[360px]:text-xl sm:text-2xl">
                        <span className="text-fg">Auth</span>
                        <span className="text-accent">Mastery</span>
                    </Link>
                    <div className="ml-auto flex items-center gap-2 sm:gap-3">
                        <div className="hidden sm:block sm:w-64 md:w-80">
                            <Search />
                        </div>
                        <ThemeSelect />
                        <a
                            href={repoUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label="Contribute on GitHub (opens in a new tab)"
                            title="Contribute on GitHub"
                            className="grid h-10 w-10 shrink-0 place-items-center rounded-lg border border-border text-fg transition-colors hover:border-accent hover:text-accent"
                        >
                            <svg aria-hidden viewBox="0 0 16 16" width="20" height="20" fill="currentColor">
                                <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z" />
                            </svg>
                        </a>
                    </div>
                </div>
            </header>

            <div className="mx-auto flex max-w-[1600px]">
                <aside
                    id="sidebar"
                    className={`${menuOpen ? "block" : "hidden"} fixed top-16 bottom-0 left-0 z-20 w-80 max-w-[85vw] overflow-y-auto border-r border-border bg-sidebar lg:sticky lg:block lg:h-[calc(100vh-4rem)] lg:w-72 lg:max-w-none lg:shrink-0`}
                >
                    {/* On phones the search box lives in the menu */}
                    <div className="px-4 pt-4 sm:hidden">
                        <Search />
                    </div>
                    <Sidebar nav={nav} />
                </aside>
                {menuOpen && (
                    <button
                        type="button"
                        aria-label="Close menu"
                        onClick={() => setMenuOpen(false)}
                        className="fixed inset-0 top-16 z-10 bg-black/40 lg:hidden"
                    />
                )}
                <main id="main" className="min-w-0 flex-1">
                    {children}
                </main>
            </div>
        </>
    );
}
