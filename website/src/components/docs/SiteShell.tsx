"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import ThemeSelect from "@/components/common/ThemeSelect";
import type { NavLevel } from "@/types/nav";
import Search, { CommandPalette, isTypingIn } from "./Search";
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
    // Desktop only: the sidebar is always visible, but can be folded away
    const [collapsed, setCollapsed] = useState(false);
    const [paletteOpen, setPaletteOpen] = useState(false);
    const [lastPath, setLastPath] = useState(pathname);

    // Close the mobile menu after navigating to another page
    if (pathname !== lastPath) {
        setLastPath(pathname);
        setMenuOpen(false);
    }

    // Shift + / ("?") toggles the sidebar: the drawer on phones, collapse on desktop
    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            const isShiftSlash =
                e.key === "?" || (e.shiftKey && e.code === "Slash");
            if (
                !isShiftSlash ||
                e.ctrlKey ||
                e.metaKey ||
                e.altKey ||
                isTypingIn(e.target)
            )
                return;
            e.preventDefault();
            if (window.matchMedia("(min-width: 1024px)").matches)
                setCollapsed((c) => !c);
            else setMenuOpen((o) => !o);
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, []);

    useEffect(() => {
        if (!menuOpen) return;
        const onKey = (e: KeyboardEvent) =>
            e.key === "Escape" && setMenuOpen(false);
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
                className="bg-accent text-accent-fg sr-only z-50 rounded px-3 py-2 focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
            >
                Skip to content
            </a>

            <header className="border-border bg-header/90 sticky top-0 z-30 h-16 border-b backdrop-blur">
                <div className="mx-auto flex h-full max-w-[1600px] items-center gap-2 px-3 sm:gap-3 sm:px-6">
                    <button
                        type="button"
                        onClick={() => setMenuOpen((o) => !o)}
                        aria-label={menuOpen ? "Close menu" : "Open menu"}
                        aria-expanded={menuOpen}
                        aria-controls="sidebar"
                        title="Toggle menu (Shift + /)"
                        className="border-border text-fg hover:border-accent hover:text-accent relative grid h-10 w-10 shrink-0 place-items-center rounded-lg border transition-colors lg:hidden"
                    >
                        <span aria-hidden className="relative block h-3.5 w-5">
                            {[
                                menuOpen
                                    ? "top-1/2 -translate-y-1/2 rotate-45"
                                    : "top-0",
                                menuOpen
                                    ? "top-1/2 -translate-y-1/2 scale-x-0 opacity-0"
                                    : "top-1/2 -translate-y-1/2",
                                menuOpen
                                    ? "top-1/2 -translate-y-1/2 -rotate-45"
                                    : "bottom-0",
                            ].map((pos, i) => (
                                <span
                                    key={i}
                                    className={`absolute left-0 h-0.5 w-full rounded-full bg-current transition-all duration-300 ease-out motion-reduce:transition-none ${pos}`}
                                />
                            ))}
                        </span>
                    </button>
                    <button
                        type="button"
                        onClick={() => setCollapsed((c) => !c)}
                        aria-label={
                            collapsed ? "Expand sidebar" : "Collapse sidebar"
                        }
                        aria-expanded={!collapsed}
                        aria-controls="sidebar"
                        title={`${collapsed ? "Expand" : "Collapse"} sidebar (Shift + /)`}
                        className="border-border text-fg hover:border-accent hover:text-accent hidden h-10 w-10 shrink-0 place-items-center rounded-lg border transition-colors lg:grid"
                    >
                        <svg
                            aria-hidden
                            viewBox="0 0 24 24"
                            width="20"
                            height="20"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="2"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                        >
                            <rect x="3" y="4" width="18" height="16" rx="2" />
                            <path d="M9 4v16" />
                            <path
                                d="M14 10l2 2-2 2"
                                className={`origin-[15px_12px] transition-transform duration-300 ease-out motion-reduce:transition-none ${collapsed ? "" : "rotate-180"}`}
                            />
                        </svg>
                    </button>
                    <Link
                        href="/"
                        className="text-lg font-extrabold tracking-tight whitespace-nowrap min-[360px]:text-xl sm:text-2xl"
                    >
                        <span className="text-fg">Auth</span>
                        <span className="text-accent">Mastery</span>
                    </Link>
                    <div className="ml-auto flex items-center gap-2 sm:gap-3">
                        <div className="hidden sm:block sm:w-64 md:w-80">
                            <Search onOpen={() => setPaletteOpen(true)} />
                        </div>
                        <ThemeSelect />
                        <a
                            href={repoUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label="Contribute on GitHub (opens in a new tab)"
                            title="Contribute on GitHub"
                            className="border-border text-fg hover:border-accent hover:text-accent grid h-10 w-10 shrink-0 place-items-center rounded-lg border transition-colors"
                        >
                            <svg
                                aria-hidden
                                viewBox="0 0 16 16"
                                width="20"
                                height="20"
                                fill="currentColor"
                            >
                                <path d="M8 0c4.42 0 8 3.58 8 8a8.013 8.013 0 0 1-5.45 7.59c-.4.08-.55-.17-.55-.38 0-.27.01-1.13.01-2.2 0-.75-.25-1.23-.54-1.48 1.78-.2 3.65-.88 3.65-3.95 0-.88-.31-1.59-.82-2.15.08-.2.36-1.02-.08-2.12 0 0-.67-.22-2.2.82-.64-.18-1.32-.27-2-.27-.68 0-1.36.09-2 .27-1.53-1.03-2.2-.82-2.2-.82-.44 1.1-.16 1.92-.08 2.12-.51.56-.82 1.28-.82 2.15 0 3.06 1.86 3.75 3.64 3.95-.23.2-.44.55-.51 1.07-.46.21-1.61.55-2.33-.66-.15-.24-.6-.83-1.23-.82-.67.01-.27.38.01.53.34.19.73.9.82 1.13.16.45.68 1.31 2.69.94 0 .67.01 1.3.01 1.49 0 .21-.15.45-.55.38A7.995 7.995 0 0 1 0 8c0-4.42 3.58-8 8-8Z" />
                            </svg>
                        </a>
                    </div>
                </div>
            </header>

            <div className="mx-auto flex max-w-[1600px]">
                {/* Phones: slides in as a drawer. Desktop: width folds 18rem -> 0 while the content stays 18rem wide, so it slides out instead of squashing */}
                <aside
                    id="sidebar"
                    className={`border-border bg-sidebar fixed top-16 bottom-0 left-0 z-20 w-80 max-w-[85vw] [scrollbar-width:none] overflow-x-hidden overflow-y-auto border-r shadow-xl transition-[translate,width,visibility] duration-300 ease-out motion-reduce:transition-none lg:sticky lg:h-[calc(100vh-4rem)] lg:max-w-none lg:shrink-0 lg:translate-x-0 lg:shadow-none [&::-webkit-scrollbar]:hidden ${
                        menuOpen
                            ? "max-lg:visible max-lg:translate-x-0"
                            : "max-lg:invisible max-lg:-translate-x-full"
                    } ${collapsed ? "lg:invisible lg:w-0 lg:border-r-0" : "lg:visible lg:w-72"}`}
                >
                    <div
                        className={`w-full transition-[opacity,translate] duration-300 ease-out motion-reduce:transition-none lg:w-72 ${
                            collapsed ? "lg:-translate-x-6 lg:opacity-0" : ""
                        }`}
                    >
                        {/* On phones the search box lives in the menu */}
                        <div className="px-4 pt-4 sm:hidden">
                            <Search onOpen={() => setPaletteOpen(true)} />
                        </div>
                        <Sidebar nav={nav} />
                    </div>
                </aside>
                <button
                    type="button"
                    aria-label="Close menu"
                    tabIndex={menuOpen ? 0 : -1}
                    aria-hidden={!menuOpen}
                    onClick={() => setMenuOpen(false)}
                    className={`fixed inset-0 top-16 z-10 bg-black/40 backdrop-blur-[2px] transition-opacity duration-300 ease-out motion-reduce:transition-none lg:hidden ${
                        menuOpen
                            ? "opacity-100"
                            : "pointer-events-none opacity-0"
                    }`}
                />
                <main id="main" className="min-w-0 flex-1">
                    {children}
                </main>
            </div>
            <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
        </>
    );
}
