import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

/* Register User */
/* We receive the user details from the front end. Encrypt the password and save the details in the MongoDB */
export const register = async (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      password,
      picturePath,
      friends,
      location,
      occupation,
    } = req.body; // From request body.

    //Bcrypt will generate a random string, called salt for added security, and will use it to encrypt the password.
    const salt = await bcrypt.genSalt();
    const passwordHash = await bcrypt.hash(password, salt);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: passwordHash, //encrypted password.
      picturePath,
      friends,
      location,
      occupation,
      viewedProfile: Math.floor(Math.random() * 1000), //Create a random count as it's not important for this project.
      impressions: Math.floor(Math.random() * 1000), //Create a random count as it's not important for this project.
    });
    const savedUser = await newUser.save(); // Save it to the DB
    res.status(201).json(savedUser);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

/* Logging In */
/* We are getting the email and password from the front end. With email, we fetch a unique record from DB. Compare the password from the 
front end and the DB. If they match, assign a JWT token with a secret String and set it in the response. Delete the password for security so that it 
won't be send to front end back and forth. */
export const login = async (req, res) => {
  try {
    //Get the email and password from req
    const { email, password } = req.body;
    //Find the unique record from MongoDB with the email received from request.
    const user = await User.findOne({ email: email });

    if (!user) return res.status(400).json({ msg: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

    //User matches. Create a token and assign to the response. Delete the password.
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    delete user.password;
    res.status(200).json({ token, user });
  } catch (err) {
    console.log("---auth.js error --", err);
    res.status(500).json({ error: err.message });
  }
};
