"use client";

import { useSyncExternalStore } from "react";

function subscribe(onChange: () => void) {
    const observer = new MutationObserver(onChange);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => observer.disconnect();
}

/** The theme actually on the page ("light" | "dark"), or null during server rendering. */
export function useResolvedTheme() {
    return useSyncExternalStore(
        subscribe,
        () => (document.documentElement.dataset.theme === "dark" ? "dark" : "light"),
        () => null,
    );
}
