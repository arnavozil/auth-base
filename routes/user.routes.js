const { Router } = require('express');
const router = Router();
const User = require('../model/user.model');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const auth = require('../middleware/auth');


const register = async (req, res) => {
    try{
        let { firstName, lastName, email, password } = req.body;
        
        // validating input
        if(!(firstName && lastName && email && password)) return res.status(400).send('All fields are required.');
        email = email.toLowerCase();

        // checking existing user
        const existingUser = await User.findOne({ email });
        if(existingUser) return res.status(409).send('Seems like you are already registered, please login to continue.');

        // hashing the password
        const passHash = await bcrypt.hash(password, 10);

        // creating user in database
        const user = await User.create({
            firstName, lastName, email,
            password: passHash
        });

        // creating token
        const token = jwt.sign(
            {userId: user._id, email},
            process.env.SECRET_KEY
        );

        // saving token
        user.token = token;
        
        // sending user refresh key
        const refreshKey = jwt.sign(
            { token },
            process.env.REFRESH_SECRET_KEY
        );
        res.cookie('refresh', refreshKey, {
            httpOnly: true,
            sameSite: 'none'
        });

        // sending new user
        return res.status(200).json(user);
    }catch(err){
        // next(err);
    };
};

const login = async (req, res) => {
    try{
        // get input
		let { email, password } = req.body;

		// validating input
        if(!(email && password)) return res.status(400).send('All fields are required.');
        email = email.toLowerCase();

        // checking existing user
        const existingUser = await User.findOne({ email });
		if(!existingUser) return res.status(400).send('No account found by that email');

		// matching password
		const isPassSame = await bcrypt.compare(password, existingUser.password);
		if(!isPassSame) return res.status(400).send('Invalid password');

		// generating token
		const token = jwt.sign(
			{ userId: existingUser.id, email },
			process.env.SECRET_KEY,
		);
		existingUser.token = token;

        // sending user refresh key
        const refreshKey = jwt.sign(
            { token },
            process.env.REFRESH_SECRET_KEY
        );
        res.cookie('refresh', refreshKey, {
            httpOnly: true,
            sameSite: 'none'
        });
        
		return res.status(200).json(existingUser);
    }catch (err){
        
    };
};

const refresh = (req, res) => {

    try{
        // extracting cookie from request
        const { refresh } = req.cookies;
        if(!refresh) return res.status(404).send('No refresh token found, please authenticate yourself.');

        const decoded = jwt.verify(refresh, process.env.REFRESH_SECRET_KEY);
        if(!decoded.token) return res.status(401).send('Invalid refresh token');

        res.status(200).json({ token: decoded.token });
    }catch(err){

    }
};

const getUser = async (req, res) => {
    try{
        const userData = req.user;
        const user = await User.findById(userData.userId);
        res.status(200).json(user);
    }catch(err){

    }
};

router.post('/login', login);
router.post('/register', register);
router.get('/refresh', refresh);
router.get('/get', auth, getUser);

module.exports = router;
