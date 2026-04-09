import app from "./app";

const PORT = 5000;

const server = app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});

server.on("error", (err: NodeJS.ErrnoException) => {
  if (err && err.code === "EADDRINUSE") {
    console.error(
      `Port ${PORT} is already in use. Stop the existing server and try again.`
    );
    process.exit(1);
  }
  console.error("Server error:", err);
  process.exit(1);
});