declare module "pdfmake/build/pdfmake" {
  import type { TDocumentDefinitions } from "pdfmake/interfaces";

  type PdfDocumentGenerator = {
    download(defaultFileName?: string): void;
    getBlob(callback: (blob: Blob) => void): void;
    open(): void;
    print(): void;
  };

  type PdfMakeBrowser = {
    vfs?: Record<string, string>;
    createPdf(documentDefinitions: TDocumentDefinitions): PdfDocumentGenerator;
  };

  const pdfMake: PdfMakeBrowser;
  export default pdfMake;
}

declare module "pdfmake/build/vfs_fonts" {
  type PdfMakeVirtualFileSystem =
    | Record<string, string>
    | {
        pdfMake?: {
          vfs: Record<string, string>;
        };
        vfs?: Record<string, string>;
      };

  const vfsFonts: PdfMakeVirtualFileSystem;
  export default vfsFonts;
}
