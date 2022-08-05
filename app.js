require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Models
const User = require('./models/User');

const app = express();

// Config JSON response
app.use(express.json());

// Private route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // Check if user exists
    const user = await User.findById(id, '-password')

    if (!user) {
        return res.status(404).json({ message: `User not found!` })
    }

    res.status(200).json({ user })
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({ message: `Access denied! `})
    }

    try {
        const secret = process.env.SECRET;

        jwt.verify(token, secret)

        next();
        
    } catch (error) {
        res.status(400).json({ message: `Invalid token!` })
    }
}

// Public route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Welcome to our API!' }); 
});

//Register User
app.post('/auth/register', async (req, res) => {

    const { name, email, password, confirmPassword } = req.body;

    //validations
    if (!name) {
        return res.status(422).json({ message: 'Name is required!' })
    }

    if (!email) {
        return res.status(422).json({ message: 'Email is required!' })
    }

    if (!password) {
        return res.status(422).json({ message: 'Password is required!' })
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ message: `Passwords don't match!` })
    }

    // Check if user exists
    const userExists = await User.findOne({ email: email })

    if (userExists) {
        return res.status(422).json({ message: `User already exists!` })
    }

    // Create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt)

    // Create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json(`User created successfully`)
    } catch(error) {
        console.log(err);

        res.status(500).json({ 
            message: `Server error, please try again later.` 
        })
    }
})

// Login user
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;

    // Validations
    if (!email) {
        return res.status(422).json({ message: 'Email is required!' })
    }

    if (!password) {
        return res.status(422).json({ message: 'Password is required!' })
    }

    // Check if user exists
    const user = await User.findOne({ email: email })
    if (!user) {
        return res.status(404).json({ message: `User not found!` })
    }

    //Check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({ message: `Invalid password!` })
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({ message: `Authentication was successful`, token})

    } catch(err) {
        console.log(err);

        res.status(500).json({ 
            message: `Server error, please try again later.` 
        })
    }
 
})

//Credentials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.6rzpvu9.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000);
        console.log(`Connected with database.`)
    })
    .catch((err) => console.log(err)
)