import express from "express";
import cors from "cors";
import documentRoutes from "./routes/document.routes";

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/document", documentRoutes);

export default app;