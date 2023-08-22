const express = require("express");
const path = require("path");
const cors = require("cors");
const app = express();

app.use(cors());
app.use(express.static(path.join(__dirname, "../../build")));
app.get("/*", (req, res) => {
  res.sendFile(path.join(__dirname, "../../build/index.html"));
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});

module.exports = app;
