const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('normalApi', {
  summary: () => ipcRenderer.invoke('normal:summary'),
  complete: result => ipcRenderer.invoke('normal:complete', result)
});
