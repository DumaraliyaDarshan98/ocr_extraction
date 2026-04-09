import fs from "fs";
import path from "path";
import OpenAI from "openai";
import { GoogleGenerativeAI } from "@google/generative-ai";
import "dotenv/config";
import { parseJsonFromModelText } from "../utils/jsonExtract.util";

export interface AiAnalysisResult {
  documentType: string;
  faceDetected: boolean;
  qrDetected: boolean;
  possibleTampering: boolean;
  layoutConsistent: boolean;
  authenticityScore: number;
}

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || "");

function getMimeType(filePath: string, fallbackMimeType?: string): string {
  if (fallbackMimeType && fallbackMimeType.trim() !== "") {
    return fallbackMimeType;
  }
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".pdf") {
    return "application/pdf";
  }
  if (ext === ".png") {
    return "image/png";
  }
  if (ext === ".webp") {
    return "image/webp";
  }
  if (ext === ".gif") {
    return "image/gif";
  }
  return "image/jpeg";
}

const buildPrompt = () => `
You are a document forensics assistant.
Analyze this identity document image.

Output rules (mandatory):
- Respond with a single JSON object only. No markdown, no code fences, no commentary before or after.
- Use double quotes for all JSON keys and string values.
- The JSON must match exactly this shape and key names:
{
  "documentType": string,
  "faceDetected": boolean,
  "qrDetected": boolean,
  "possibleTampering": boolean,
  "layoutConsistent": boolean,
  "authenticityScore": number
}
- authenticityScore is 0-100 (integer or decimal).
`;

// OpenAI-based analysis
export const analyzeDocumentWithOpenAI = async (
  filePath: string
): Promise<AiAnalysisResult | null> => {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    return null;
  }

  const absolutePath = path.resolve(filePath);
  const imageBuffer = await fs.promises.readFile(absolutePath);
  const base64Image = imageBuffer.toString("base64");

  const prompt = buildPrompt();

  const response = await openai.chat.completions.create(
    {
      model: "gpt-4.1-mini",
      messages: [
        {
          role: "system",
          content:
            "You are a helpful AI that analyzes identity document images.",
        },
        {
          role: "user",
          content: [
            { type: "text", text: prompt },
            {
              type: "image_url",
              image_url: {
                url: `data:image/jpeg;base64,${base64Image}`,
              },
            },
          ] as any,
        },
      ],
      max_tokens: 300,
    } as any
  );

  const raw = response.choices[0]?.message?.content ?? "";

  try {
    const parsed = parseJsonFromModelText(raw) as AiAnalysisResult;
    return parsed;
  } catch (error) {
    console.error("Error parsing OpenAI analysis response:", error);
    return null;
  }
};

// Gemini-based analysis
export const analyzeDocumentWithGemini = async (
  filePath: string,
  mimeTypeHint?: string
): Promise<AiAnalysisResult | null> => {
  try {
    if (!process.env.GEMINI_API_KEY) {
      return null;
    }

    const absolutePath = path.resolve(filePath);
    const imageBuffer = await fs.promises.readFile(absolutePath);
    const base64Image = imageBuffer.toString("base64");
    const mimeType = getMimeType(absolutePath, mimeTypeHint);

    // const model = genAI.getGenerativeModel({
    //   model: process.env.GEMINI_MODEL || "gemini-2.5-flash",
    // });

    const model = genAI.getGenerativeModel({
      model: "gemini-1.5-flash",
    });
  
    const prompt = buildPrompt();

    const result = await model.generateContent([
      prompt,
      {
        inlineData: {
          mimeType,
          data: base64Image,
        },
      },
    ]);

    const text = result.response.text();

    return parseJsonFromModelText(text) as AiAnalysisResult;
  } catch (error) {
    console.error("Gemini analysis error:", error);
    return null;
  }
};

// Public entry point: choose provider based on env
export const analyzeDocumentAI = async (
  filePath: string,
  mimeTypeHint?: string
): Promise<AiAnalysisResult | null> => {
  const useOpenAI = (process.env.USE_OPENAI || "").toLowerCase() === "true";

  if (useOpenAI) {
    const openAiResult = await analyzeDocumentWithOpenAI(filePath);
    if (openAiResult) return openAiResult;
  }

  return analyzeDocumentWithGemini(filePath, mimeTypeHint);
};

