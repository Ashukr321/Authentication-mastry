"use client";

import { useEffect } from "react";

/** Registers public/sw.js in production builds (in dev it would serve stale hot-reloaded files). */
export default function ServiceWorker() {
    useEffect(() => {
        if (process.env.NODE_ENV !== "production" || !("serviceWorker" in navigator)) return;
        navigator.serviceWorker.register("/sw.js", { scope: "/" }).catch(() => {});
    }, []);
    return null;
}
