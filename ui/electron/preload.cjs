const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ember", {
  pick:             () => ipcRenderer.invoke("ember:pick"),
  setBinary:        (p) => ipcRenderer.invoke("ember:setBinary", p),
  binary:           () => ipcRenderer.invoke("ember:binary"),
  run:              (args) => ipcRenderer.invoke("ember:run", args),

  loadAnnotations:  (bp) => ipcRenderer.invoke("ember:loadAnnotations", bp),
  saveAnnotations:  (bp, data) => ipcRenderer.invoke("ember:saveAnnotations", bp, data),
  // Prompts a save dialog and writes a patched copy of the current
  // binary to the chosen path. Returns the chosen path, or null if the
  // user cancelled.
  savePatchedAs:    () => ipcRenderer.invoke("ember:savePatchedAs"),

  recents:          () => ipcRenderer.invoke("ember:recents"),
  openRecent:       (bp) => ipcRenderer.invoke("ember:openRecent", bp),

  // AI / OpenRouter proxy. The API key is held in the main process and
  // never crosses the IPC boundary to the renderer — only the resulting
  // tokens do, streamed via `ai:chunk` events keyed on a request id.
  ai: {
    getConfig:    ()        => ipcRenderer.invoke("ember:ai:getConfig"),
    setConfig:    (c)       => ipcRenderer.invoke("ember:ai:setConfig", c),
    listModels:   (provider) => ipcRenderer.invoke("ember:ai:listModels", provider),
    detectCli:    (kind)    => ipcRenderer.invoke("ember:ai:detectCli", kind),
    // Returns a request id; the caller subscribes to onChunk/onDone/onError
    // with the same id to receive the streamed response.
    chat:         (req)     => ipcRenderer.invoke("ember:ai:chat", req),
    cancel:       (id)      => ipcRenderer.invoke("ember:ai:cancel", id),
    onChunk:      (cb)      => {
      const h = (_e, id, delta) => cb(id, delta);
      ipcRenderer.on("ember:ai:chunk", h);
      return () => ipcRenderer.removeListener("ember:ai:chunk", h);
    },
    onDone:       (cb)      => {
      const h = (_e, id, info) => cb(id, info);
      ipcRenderer.on("ember:ai:done", h);
      return () => ipcRenderer.removeListener("ember:ai:done", h);
    },
    onError:      (cb)      => {
      const h = (_e, id, msg) => cb(id, msg);
      ipcRenderer.on("ember:ai:error", h);
      return () => ipcRenderer.removeListener("ember:ai:error", h);
    },
    // Agentic tool events. `onTool` fires when the model invokes one
    // of Ember's binary-navigation tools; `onToolDone` fires once the
    // call returns (or fails). The chat panel renders these as a
    // status row so the user can see the model's reasoning trail.
    onTool:       (cb)      => {
      const h = (_e, id, info) => cb(id, info);
      ipcRenderer.on("ember:ai:tool", h);
      return () => ipcRenderer.removeListener("ember:ai:tool", h);
    },
    onToolDone:   (cb)      => {
      const h = (_e, id, info) => cb(id, info);
      ipcRenderer.on("ember:ai:toolDone", h);
      return () => ipcRenderer.removeListener("ember:ai:toolDone", h);
    },
  },
});
