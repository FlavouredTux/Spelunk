const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("ember", {
  pick:             () => ipcRenderer.invoke("ember:pick"),
  setBinary:        (p) => ipcRenderer.invoke("ember:setBinary", p),
  binary:           () => ipcRenderer.invoke("ember:binary"),
  run:              (args) => ipcRenderer.invoke("ember:run", args),

  loadAnnotations:  (bp) => ipcRenderer.invoke("ember:loadAnnotations", bp),
  saveAnnotations:  (bp, data) => ipcRenderer.invoke("ember:saveAnnotations", bp, data),

  recents:          () => ipcRenderer.invoke("ember:recents"),
  openRecent:       (bp) => ipcRenderer.invoke("ember:openRecent", bp),
});
