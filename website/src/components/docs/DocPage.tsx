"use client";

import { useSyncExternalStore } from "react";
import type { Heading } from "@/lib/markdown";
import Toc from "./Toc";

// Whether the desktop "On this page" panel is hidden; remembered across pages.
const KEY = "toc-hidden";
let fallback = false; // used when localStorage is blocked
function readHidden() {
    try {
        return localStorage.getItem(KEY) === "1";
    } catch {
        return fallback;
    }
}
function setHidden(hidden: boolean) {
    fallback = hidden;
    try {
        localStorage.setItem(KEY, hidden ? "1" : "0");
    } catch {
        // storage blocked: the fallback keeps it for this page view
    }
    window.dispatchEvent(new Event(KEY));
}
function subscribeHidden(onChange: () => void) {
    window.addEventListener(KEY, onChange);
    window.addEventListener("storage", onChange);
    return () => {
        window.removeEventListener(KEY, onChange);
        window.removeEventListener("storage", onChange);
    };
}

/** Page body: a content column that fills the space, plus "On this page" (sticky panel on wide screens, dropdown otherwise). */
export default function DocPage({ toc, children }: { toc: Heading[]; children: React.ReactNode }) {
    const hidden = useSyncExternalStore(subscribeHidden, readHidden, () => false);
    const hasToc = toc.length > 0;

    return (
        <div className="flex gap-8 px-4 py-8 sm:px-8 sm:py-10 lg:px-10 2xl:gap-12">
            <article className="min-w-0 flex-1">
                {hasToc && (
                    <details className="mb-8 rounded-lg border border-border xl:hidden">
                        <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-fg">On this page</summary>
                        <div className="max-h-[60vh] overflow-y-auto border-t border-border p-3">
                            <Toc headings={toc} />
                        </div>
                    </details>
                )}
                {children}
            </article>
            {hasToc &&
                (hidden ? (
                    <button
                        type="button"
                        onClick={() => setHidden(false)}
                        aria-label="Show On this page"
                        title="Show On this page"
                        className="sticky top-24 hidden h-9 w-9 shrink-0 place-items-center self-start rounded-lg border border-border text-muted hover:border-accent hover:text-accent xl:grid"
                    >
                        ☰
                    </button>
                ) : (
                    <aside className="sticky top-24 hidden max-h-[calc(100vh-7rem)] w-60 shrink-0 self-start overflow-y-auto xl:block 2xl:w-64">
                        <div className="mb-2 flex items-center justify-between gap-2">
                            <p className="text-sm font-semibold text-fg">On this page</p>
                            <button
                                type="button"
                                onClick={() => setHidden(true)}
                                aria-label="Hide On this page"
                                title="Hide On this page"
                                className="grid h-7 w-7 place-items-center rounded-md text-muted hover:bg-surface hover:text-fg"
                            >
                                ✕
                            </button>
                        </div>
                        <Toc headings={toc} />
                    </aside>
                ))}
        </div>
    );
}
