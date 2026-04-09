declare module "cors";
declare module "qrcode-reader";
declare module "@google/generative-ai";

declare namespace NodeJS {
  interface ProcessEnv {
    OPENAI_API_KEY?: string;
    GEMINI_API_KEY?: string;
    USE_OPENAI?: string; // "true" or "false"
    /** Override default gemini-2.5-flash */
    GEMINI_MODEL?: string;
    /** Absolute or cwd-relative path to trigger JSON file or trigger folder */
    TRIGGER_CONFIG_PATH?: string;
    NAME_MATCH_THRESHOLD?: string;
    MIN_AGE?: string;
    FIELD_CONFIDENCE_THRESHOLD?: string;
    FACE_MATCH_THRESHOLD?: string;
    FACE_DISTANCE_MAX?: string;
    FACE_MATCH_ENABLED?: string;
    NAME_FIELD_KEYS?: string;
    DOB_FIELD_KEYS?: string;
  }
}

