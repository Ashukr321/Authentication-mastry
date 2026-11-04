"use client";

import { useSyncExternalStore } from "react";
import { readThemePref, saveThemePref, subscribeThemePref, type ThemePref } from "@/lib/theme";

const OPTIONS: { value: ThemePref; label: string }[] = [
    { value: "auto", label: "💻 Auto" },
    { value: "light", label: "☀️ Light" },
    { value: "dark", label: "🌙 Dark" },
];

export default function ThemeSelect() {
    const pref = useSyncExternalStore(subscribeThemePref, readThemePref, () => "auto" as const);

    return (
        <label className="relative">
            <span className="sr-only">Color theme</span>
            <select
                value={pref}
                onChange={(e) => saveThemePref(e.target.value as ThemePref)}
                className="h-10 cursor-pointer appearance-none rounded-lg border border-border bg-surface py-0 pr-7 pl-2 text-sm sm:pr-9 sm:pl-3 font-medium text-fg hover:border-accent focus:border-accent focus:outline-none"
            >
                {OPTIONS.map((o) => (
                    <option key={o.value} value={o.value}>
                        {o.label}
                    </option>
                ))}
            </select>
            <span aria-hidden className="pointer-events-none absolute top-1/2 right-2.5 -translate-y-1/2 sm:right-3 text-xs text-muted">
                ▼
            </span>
        </label>
    );
}
