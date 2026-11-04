// Shared script for every topic's diagrams.html page: draws the Mermaid diagrams.
// Classic script (not an ES module) so the page also works when opened by double-clicking (file://).

// The website embeds this page with ?theme=light|dark so the diagrams follow its theme switch
const forced = new URLSearchParams(location.search).get("theme");
if (forced === "light" || forced === "dark") document.documentElement.dataset.theme = forced;

// Inside the website's iframe, hide this page's own header (the website already shows one)
if (window.self !== window.top) document.documentElement.classList.add("embedded");

const dark = forced ? forced === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
mermaid.initialize({ startOnLoad: true, theme: dark ? "dark" : "default", securityLevel: "strict" });
