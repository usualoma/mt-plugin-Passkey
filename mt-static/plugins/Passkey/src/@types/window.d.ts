interface JQuery {
  mtModal: {
    open: (url: string, opts: { large: boolean }) => void;
  };
}

interface Window {
  CMSScriptURI: string;
  jQuery: typeof jQuery;
}
