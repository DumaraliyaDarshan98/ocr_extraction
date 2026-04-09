import sharp from "sharp";

export const getImageMetadata = async (imagePath: string) => {
  try {
    const metadata = await sharp(imagePath).metadata();
    return metadata;
  } catch {
    return null;
  }
};

