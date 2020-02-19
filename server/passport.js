const passport  = require('passport');
const jwtStrategy = require('passport-jwt').Strategy;
const { ExtractJwt } = require('passport-jwt');
const LocalStrategy = require('passport-local').Strategy;
const GooglePlusTokenStrategy = require('passport-google-plus-token');
const { JWT_SECRET } = require('./configuration');
const User = require('./models/user');

// JSON WEB TOKENS STRATEGY
passport.use(new jwtStrategy({
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: JWT_SECRET
}, async (payload, done) => {
    try {
        // Find the user specified in token
        const user = await User.findById(payload.sub);

        // If user doesn't exists, handle it
        if (!user) {
            return done(null, false);
        }

        // Otherwise, return the user
        done(null, user);
    } catch (error) {
        done(error, false);
    }
}));

// GOOGLE OAUTH STRATEGY
passport.use('googleToken', new GooglePlusTokenStrategy({
    clientID: '278195508427-q24vocl6bjvolnnh7dus7cqu0725ueih.apps.googleusercontent.com',
    clientSecret: '6R6EjFbNWRYOgAF1SiT0V-yU'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        console.log('accessToken', accessToken);
        console.log('refreshToken', refreshToken);
        console.log('profile', profile);

        // Check whether this current user exists in our DB
        const existingUser = await User. findOne({ "google.id": profile.id });
        if (existingUser) {
            console.log('User already exists in our DB');
            return done(null, existingUser);
        }

        console.log('User doesn\'t exists, we\'re creating a new one');

        // If new account
        const newUser = new User({
            method: 'google',
            google: {
                id: profile.id,
                email: profile.emails[0].value
            }
        });

        await newUser.save();
        done(null, newUser);
    } catch (error) {
        done(error, false, error.message);
    }
}));

// LOCAL STRATEGY
passport.use(new LocalStrategy({
    usernameField: 'email'
}, async (email, password, done) => {
    try {
        console.log('email', email);
        // Find the user given the email
        const user = await User.findOne({ "local.email": email });

        // If not, handle it
        if(!user) {
            return done(null, false);
        }

        // Check if the password is correct
        const isMatch = await user.isValidPassword(password);
        
        console.log('isMatch', isMatch);

        // If not, handle it
        if (!isMatch) {
            return done(null, false);
        }

        // Otherwise, return the user
        done(null, user);
    } catch (error) {
        done(error, false);
    }
}));