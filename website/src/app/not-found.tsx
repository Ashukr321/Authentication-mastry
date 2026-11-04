import Link from "next/link";

export default function NotFound() {
    return (
        <div className="px-5 py-24 text-center">
            <p className="font-mono text-sm tracking-widest text-accent uppercase">404</p>
            <h1 className="mt-3 text-3xl font-bold">Page not found</h1>
            <p className="mt-2 text-muted">This page doesn&apos;t exist. Maybe the topic moved?</p>
            <Link
                href="/"
                className="mt-6 inline-flex rounded-lg bg-accent px-4 py-2.5 text-sm font-semibold text-accent-fg hover:opacity-90"
            >
                Back to home
            </Link>
        </div>
    );
}
