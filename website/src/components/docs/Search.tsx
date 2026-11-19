"use client";

import { Command } from "cmdk";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { SearchItem } from "@/types/nav";

export const isTypingIn = (el: EventTarget | null) =>
    el instanceof HTMLElement &&
    (el.isContentEditable ||
        ["INPUT", "TEXTAREA", "SELECT"].includes(el.tagName));

/** The search box in the header / mobile menu: a button that opens the command palette. */
export default function Search({ onOpen }: { onOpen: () => void }) {
    return (
        <button
            type="button"
            onClick={onOpen}
            aria-label="Search topics (Ctrl + K)"
            className="group border-border bg-surface text-muted hover:border-accent flex h-10 w-full max-w-xs items-center gap-2 rounded-lg border px-3 text-sm transition-colors"
        >
            <span aria-hidden>⌕</span>
            <span className="flex-1 text-left">Search topics…</span>
            <kbd className="border-border group-hover:text-accent rounded border px-1.5 font-mono text-xs">
                Ctrl K
            </kbd>
        </button>
    );
}

/** Ctrl/⌘ + K (or "/") command palette over every topic and section in /search-index.json. */
export function CommandPalette({
    open,
    onOpenChange,
}: {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}) {
    const router = useRouter();
    const [items, setItems] = useState<SearchItem[] | null>(null);

    useEffect(() => {
        const onKey = (e: KeyboardEvent) => {
            if (e.key.toLowerCase() === "k" && (e.ctrlKey || e.metaKey)) {
                e.preventDefault();
                onOpenChange(!open);
            } else if (e.key === "/" && !open && !isTypingIn(e.target)) {
                e.preventDefault();
                onOpenChange(true);
            }
        };
        window.addEventListener("keydown", onKey);
        return () => window.removeEventListener("keydown", onKey);
    }, [open, onOpenChange]);

    // The index is only downloaded the first time someone opens the palette
    useEffect(() => {
        if (!open || items) return;
        fetch("/search-index.json")
            .then((r) => r.json())
            .then(setItems)
            .catch(() => setItems([]));
    }, [open, items]);

    const go = (href: string) => {
        onOpenChange(false);
        router.push(href);
    };

    return (
        <Command.Dialog
            open={open}
            onOpenChange={onOpenChange}
            label="Search topics"
            overlayClassName="cmdk-overlay fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
            contentClassName="cmdk-content fixed top-[12vh] left-1/2 z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-2xl border border-border bg-surface shadow-2xl"
        >
            <div className="border-border flex items-center gap-2 border-b px-4">
                <span aria-hidden className="text-muted text-lg">
                    ⌕
                </span>
                <Command.Input
                    autoFocus
                    placeholder="Search topics and sections…"
                    className="text-fg placeholder:text-muted h-14 flex-1 bg-transparent text-base focus:outline-none"
                />
                <kbd className="border-border text-muted rounded border px-1.5 font-mono text-xs">
                    Esc
                </kbd>
            </div>

            <Command.List className="[&_[cmdk-group-heading]]:text-muted max-h-[min(60vh,420px)] overflow-y-auto overscroll-contain p-2 [&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:py-2 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-semibold [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:uppercase">
                {items === null ? (
                    <Command.Loading>
                        <div className="text-muted px-3 py-6 text-center text-sm">
                            Loading…
                        </div>
                    </Command.Loading>
                ) : (
                    <>
                        <Command.Empty className="text-muted px-3 py-6 text-center text-sm">
                            No results found.
                        </Command.Empty>
                        <Command.Group heading="Topics & sections">
                            {items.map((r) => (
                                <Command.Item
                                    key={r.href}
                                    // value must be unique; title + context is what people search by
                                    value={`${r.title} ${r.context} ${r.href}`}
                                    onSelect={() => go(r.href)}
                                    className="data-[selected=true]:bg-accent-soft flex cursor-pointer items-center gap-3 rounded-lg px-3 py-2 transition-colors"
                                >
                                    <div className="min-w-0 flex-1">
                                        <div className="text-fg truncate text-sm font-medium">
                                            {r.title}
                                        </div>
                                        <div className="text-muted truncate text-xs">
                                            {r.context}
                                        </div>
                                    </div>
                                    {r.soon && (
                                        <span className="bg-hover text-muted shrink-0 rounded px-1.5 text-[10px] tracking-wide uppercase">
                                            soon
                                        </span>
                                    )}
                                </Command.Item>
                            ))}
                        </Command.Group>
                    </>
                )}
            </Command.List>

            <div className="border-border text-muted hidden items-center gap-4 border-t px-4 py-2 text-xs sm:flex">
                <span>
                    <kbd className="font-mono">↑↓</kbd> navigate
                </span>
                <span>
                    <kbd className="font-mono">↵</kbd> open
                </span>
                <span>
                    <kbd className="font-mono">Ctrl K</kbd> toggle
                </span>
            </div>
        </Command.Dialog>
    );
}
