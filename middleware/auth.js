import jwt from "jsonwebtoken";

export const verifyToken = async (req, res, next) => {
  try {
    let token = req.header("Authorization");

    if (!token) {
      return res.status(403).send("No token. Access Denied");
    }
    console.log("----- verifyToken 1 ----");
    if (token.startsWith("Bearer ")) {
      console.log("----- verifyToken 2 ----");
      token = token.slice(7, token.length).trimLeft();
    }

    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
};
