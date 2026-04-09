import Jimp from "jimp";
// Use CommonJS require with loose typing to avoid missing type declarations
// eslint-disable-next-line @typescript-eslint/no-var-requires
const QrCodeReader: any = require("qrcode-reader");

export interface QrScanResult {
  found: boolean;
  data?: string;
}

export const scanQrCode = async (imagePath: string): Promise<QrScanResult> => {
  try {
    const image = await (Jimp as any).read(imagePath);

    const qr = new (QrCodeReader as any)();

    return await new Promise<QrScanResult>((resolve) => {
      qr.callback = (err: Error | null, value: { result: string } | null) => {
        if (err || !value) {
          return resolve({ found: false });
        }

        resolve({
          found: true,
          data: value.result,
        });
      };

      qr.decode(image.bitmap);
    });
  } catch {
    return { found: false };
  }
};

