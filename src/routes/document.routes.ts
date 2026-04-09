import express from "express";
import multer from "multer";
import {
  extractDocumentSimple,
  validateExtractedData,
  verifyDocument,
} from "../controllers/document.controller";

const router = express.Router();

const upload = multer({
  dest: "src/uploads/",
  fileFilter: (_req, file, cb) => {
    const mime = String(file.mimetype ?? "").toLowerCase();
    if (file.fieldname === "selfie") {
      cb(null, mime.startsWith("image/"));
      return;
    }
    const isImage = mime.startsWith("image/");
    const isPdf = mime === "application/pdf";
    cb(null, isImage || isPdf);
  },
});
const uploadKyc = upload.fields([
  { name: "file", maxCount: 1 },
  { name: "selfie", maxCount: 1 },
]);
const uploadSingleDocument = upload.single("file");

router.post("/verify", uploadKyc, verifyDocument);
router.post("/validate", validateExtractedData);
router.post("/extract-simple", uploadSingleDocument, extractDocumentSimple);

export default router;