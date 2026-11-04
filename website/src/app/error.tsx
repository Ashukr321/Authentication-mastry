"use client";

import Link from "next/link";

export default function ErrorPage() {
    return (
        <div className="px-5 py-24 text-center">
            <p className="font-mono text-sm tracking-widest text-red-500 uppercase">Error</p>
            <h1 className="mt-3 text-3xl font-bold">Something went wrong</h1>
            <p className="mt-2 text-muted">Please try again or return to the home page.</p>
            <Link
                href="/"
                className="mt-6 inline-flex rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-accent-fg hover:opacity-90"
            >
                Back to home
            </Link>
        </div>
    );
}
