const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const app = express();
app.use(bodyParser.json());

// =============================
// Hardcoded secret key
// =============================
const SECRET_KEY = "mySuperSecretKey123";

// =============================
// Dummy users (with roles)
// =============================
const users = [
  { id: 1, username: "adminUser", password: "admin123", role: "Admin" },
  { id: 2, username: "modUser", password: "mod123", role: "Moderator" },
  { id: 3, username: "normalUser", password: "user123", role: "User" },
];

// =============================
// POST /login - issue JWT token
// =============================
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "Invalid username or password" });
  }

  // Generate JWT token
  const token = jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    SECRET_KEY,
    { expiresIn: "1h" }
  );

  res.json({ token });
});

// =============================
// Middleware: Verify Token
// =============================
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ message: "Token missing" });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
}

// =============================
// Middleware: Role Authorization
// =============================
function authorizeRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }
    next();
  };
}

// =============================
// Protected Routes
// =============================

// Admin-only route
app.get(
  "/admin-dashboard",
  verifyToken,
  authorizeRoles("Admin"),
  (req, res) => {
    res.json({
      message: "Welcome to the Admin dashboard.",
      user: req.user,
    });
  }
);

// Moderator-only route
app.get(
  "/moderator-panel",
  verifyToken,
  authorizeRoles("Moderator"),
  (req, res) => {
    res.json({
      message: "Welcome to the Moderator panel.",
      user: req.user,
    });
  }
);

// General user route (accessible to everyone)
app.get("/user-profile", verifyToken, (req, res) => {
  res.json({
    message: `Welcome to your profile, ${req.user.username}`,
    user: req.user,
  });
});

// =============================
// Start Server
// =============================
app.listen(3000, () => {
  console.log("✅ Server running at http://localhost:3000");
});
