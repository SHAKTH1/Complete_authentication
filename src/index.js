const express = require("express");
const bcrypt = require("bcryptjs");
const path = require("path");
const app = express();
const LogInCollection = require("./mongo");
const port = process.env.PORT || 4000;

// Firebase initialization
const { initializeApp } = require("firebase/app");
const { getAuth, sendPasswordResetEmail } = require("firebase/auth");


const firebaseConfig = {
  apiKey: "AIzaSyBx2yySRlobcD4bMmHUVY1EZo3jzDH4hYc",
  authDomain: "passwordauth-8a9ed.firebaseapp.com",
  projectId: "passwordauth-8a9ed",
  storageBucket: "passwordauth-8a9ed.appspot.com",
  messagingSenderId: "557339329004",
  appId: "1:557339329004:web:a4f82332b81d1ceacc40c9",
  measurementId: "G-4ZMRMHHQEN"
};

const firebaseApp = initializeApp(firebaseConfig);
const auth = getAuth(firebaseApp);
let analytics;
try {
    // Check if analytics is supported
    if (typeof window !== 'undefined') {
        // Analytics is supported in the client-side browser environment
        analytics = getAnalytics(firebaseApp);
    }
} catch (error) {
    // Handle error if analytics is not supported
    console.error("Firebase Analytics is not supported in this environment:", error);
}


const static_path = path.join(__dirname, "../tempelates").replace(/\\/g, '/');
const tempelatePath = path.join(__dirname, "../tempelates/").replace(/\\/g, '/');

app.set("view engine", "hbs");
app.set("views", tempelatePath);
app.use(express.static(static_path));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

app.get('/signup', (req, res) => {
    res.render('signup');
});

app.get('/', (req, res) => {
    res.render('login');
});

app.get('/home', (req, res) => {
    res.render('home'); 
});

app.get('/forgotpass', (req, res) => {
    res.render('forgotpass');
});

app.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  try {
    // Check if the user exists in MongoDB
    const user = await LogInCollection.findOne({ email });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    // Send password reset email only if the user exists in MongoDB
    await sendPasswordResetEmail(auth, email);
    console.log("Password reset email sent successfully to:", email);
    res.status(200).json({ message: "Password reset link sent successfully" }); // Send success message to client
  } catch (error) {
    console.error("Error sending reset link:", error.message);
    res.status(500).json({ error: "Internal server error" }); // Send error message to client
  }
});


app.post('/signup', async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        if (!name || !email || !phone || !password) {
            return res.status(400).send("All fields are required.");
        }

        const existingUser = await LogInCollection.findOne({ name });

        if (existingUser) {
            return res.send("User already exists.");
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new LogInCollection({
            name,
            email,
            phone,
            password: hashedPassword
        });
        await newUser.save();

        res.status(201).render("home", {
            naming: name
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("An error occurred during signup.");
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await LogInCollection.findOne({ email });

        if (!user) {
            return res.status(404).send("User not found.");
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).send("Invalid password.");
        }

        res.status(201).render("home", {
            naming: user.name
        });
    } catch (error) {
        console.error(error);
        res.status(500).send("An error occurred during login.");
    }
});

app.post('/signout', (req, res) => {
    // Perform any sign-out actions here (e.g., clearing session, etc.)
    res.redirect('/');
});

app.listen(port, () => {
    console.log('port connected');
});