# Mindmap - Vanilla JavaScript

Lightweight, backend-free mindmap app using HTML + CSS and vanilla JavaScript (SVG rendering).

Files (kept separate for easy editing):
- `index.html` — UI and SVG canvas
- `styles.css` — styling and theme variables
- `app.js` — application logic (nodes, links, pan/zoom, drag, inline edit, search, save/export/import)

Offline usage
- The app runs fully offline with no external network requests or CDN dependencies. All resources are local and the map is persisted to `localStorage` in your browser.
- To run: open `index.html` in your browser (double-click the file or use your browser's Open File). For best behavior you can also serve the folder with a simple static server (for example, `npx http-server .` or VS Code Live Server), but a network server is not required.

Quick tips
- Drag nodes to reposition them.
- Double-click or click the pencil control to open the inline editor and edit a node's label; press Enter to save.
- Use the toolbar to add nodes, change node style/palette, zoom, search, export/import JSON or save to `localStorage`.

Behavior notes
- The editor is inline (not a prompt) and saves immediately on Enter or blur.
- Autosave can be toggled in the toolbar; explicit Save and Export remain available.

Next suggestions I can implement if you want:
- Pixel-perfect text wrapping by measuring text widths
- Per-edge style overrides (allow each link to have its own style)
- Keyboard shortcuts and undo/redo
- Single-file distributable build (inline CSS/JS) while keeping the separated-source development files
