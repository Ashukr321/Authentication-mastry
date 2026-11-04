// Shared script for every topic's diagrams.html page: draws the Mermaid diagrams.
// Classic script (not an ES module) so the page also works when opened by double-clicking (file://).
const dark = window.matchMedia("(prefers-color-scheme: dark)").matches;
mermaid.initialize({ startOnLoad: true, theme: dark ? "dark" : "default", securityLevel: "strict" });
