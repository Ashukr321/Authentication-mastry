export type ThemePref = "auto" | "light" | "dark";

const KEY = "theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

// Runs in <head> before the page paints, so there is no flash of the wrong theme.
export const themeInitScript = `(function(){try{var p=localStorage.getItem("${KEY}")||"auto";var d=p==="dark"||(p==="auto"&&matchMedia("${DARK_QUERY}").matches);document.documentElement.dataset.theme=d?"dark":"light"}catch(e){}})()`;

export function readThemePref(): ThemePref {
    try {
        const saved = localStorage.getItem(KEY);
        return saved === "light" || saved === "dark" ? saved : "auto";
    } catch {
        return "auto"; // storage blocked (private mode etc.)
    }
}

/** Sets html[data-theme] to "light" or "dark", resolving "auto" from the OS setting. */
export function applyTheme(pref: ThemePref) {
    const dark = pref === "dark" || (pref === "auto" && matchMedia(DARK_QUERY).matches);
    document.documentElement.dataset.theme = dark ? "dark" : "light";
}

export function saveThemePref(pref: ThemePref) {
    try {
        localStorage.setItem(KEY, pref);
    } catch {
        // storage blocked: the choice still applies to this page view
    }
    applyTheme(pref);
    window.dispatchEvent(new Event("themepref"));
}

/** Follows OS light/dark changes while the preference is "auto". */
export function subscribeThemePref(onChange: () => void) {
    const media = matchMedia(DARK_QUERY);
    const onMedia = () => {
        if (readThemePref() === "auto") applyTheme("auto");
    };
    media.addEventListener("change", onMedia);
    window.addEventListener("themepref", onChange);
    window.addEventListener("storage", onChange);
    return () => {
        media.removeEventListener("change", onMedia);
        window.removeEventListener("themepref", onChange);
        window.removeEventListener("storage", onChange);
    };
}
