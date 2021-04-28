//jshint esversion:6
require('dotenv').config()   // for .env

const express = require("express");
const bodyParser = require("body-parser");
const passport=require('passport');
const plm=require('passport-local-mongoose');
const session=require('express-session');
const bcrypt=require('bcrypt-nodejs');
const flash = require('connect-flash')
const mongoose = require("mongoose");
const nodemailer = require('nodemailer');
const ejs = require("ejs");

const app = express();
app.use(express.static('public'));

app.set('view engine','ejs')

app.use(bodyParser.urlencoded({extended: true}));

// -----------------------------------------------------------------------------------------
app.use(session({
    secret:process.env.SECRET,
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
// =========================================================================================

mongoose.connect("mongodb://localhost:27017/test" , {useNewUrlParser: true, useUnifiedTopology: true});
// mongoose.connect('mongodb://172.18.0.1:60000', {useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false, mongos: true});
mongoose.set('useCreateIndex', true);

const UserSchema = new mongoose.Schema({
    name : String,
    email : String,
    college : String,
    phone : String,
    branch : String,
    dob : Date,
    password : String,
    otp: Number,
    otpexpire: Date
});

const ElectionSchema = new mongoose.Schema({
    collegename : String,
    electionname : String,
    electionuni : String,
    semester : String,
    starttime : String,
    endtime : String,
});

const ResultSchema = new mongoose.Schema({
    electionID : String,
    rollno : String,
    name : String,
    count : Number
})

const VoterSchema = new mongoose.Schema({
    email : String,
    electionID : String
})

const DummyUserSchema = new mongoose.Schema({
    name : String,
    email : String,
    phone : String,
    branch : String,
    dob : Date,
    otp: Number,
    otpexpire: Date,
    college : String
})

const AdminSchema = new mongoose.Schema({
    email : String,
    password : String
})

// -----------------------------------------------------------------------------------------
UserSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;
  
    if (!user.isModified('password')) return next();
  
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
        if (err) return next(err);
    
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});
  
UserSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) 
            return cb(err);
        cb(null, isMatch);
    });
};
UserSchema.plugin(plm);

AdminSchema.pre('save', function(next) {
    var user = this;
    var SALT_FACTOR = 5;
  
    if (!user.isModified('password')) return next();
  
    bcrypt.genSalt(SALT_FACTOR, function(err, salt) {
        if (err) return next(err);
    
        bcrypt.hash(user.password, salt, null, function(err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});
  
AdminSchema.methods.comparePassword = function(candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if (err) 
            return cb(err);
        cb(null, isMatch);
    });
};
AdminSchema.plugin(plm)

// =========================================================================================

const User = mongoose.model("User", UserSchema);

const Election = mongoose.model("Election", ElectionSchema);

const Result = mongoose.model("Result", ResultSchema);

const Voter = mongoose.model("Voter", VoterSchema);

const DummyUser = mongoose.model("DummyUser", DummyUserSchema);

const Admin = mongoose.model("Admin", AdminSchema);

// -----------------------------------------------------------------------------------------
passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user);
});
  
passport.deserializeUser(function(user, done) {
    if(user!=null){
        done(null,user);
    }
});

// =========================================================================================

app.get("/adminlogin", (req,res)=>{
    res.render("adminlogin");
});

app.get('/forgot', (req, res)=>{
    res.render('forgot', {msg: ''});
})

let transporter = nodemailer.createTransport({
    host: 'smtp@gmail.com',
    port: 465,
    secure: true,
    service: 'gmail',
    auth:{
        user: process.env.EMAIL,
        pass: process.env.PASSWORD
    }
})

app.get('/logout',function(req,res)
{
    req.logout();
    res.status(200).clearCookie('connect.sid', { path: '/'});
    req.session.destroy(function (err) {
        res.redirect('/login');
    });
});

app.get("/signup", function(req,res){
    res.render("signup", {msg: ""});
});

app.get("/login", function(req,res){
    res.render("login",{msg:""});
});

app.post("/signup", function(req,res){
    const v1 = req.body.name;
    const v2 = req.body.email;
    const v3 = req.body.phone;
    const v4 = req.body.branch;
    const v5 = req.body.dob;

    // Email Check
    const fix = "@nit";
    var MSG = "";
    console.log(v2.length);
    console.log(v2.slice(9,13));
    if(v2.slice(9,13) !== fix)
    {
        MSG = "enter valid mail";
    }

    // PhoneNumber Check
    if(v3.length !== 10)
    {
        MSG = "enter valid phone number";    
    }

    
    let f = 1;
    for(let i=0;i<10;i++)
    {
        if(v3[i] !== '0' && v3[i] !== '1' && v3[i] !== '2' && v3[i] !== '3' && v3[i] !== '4' && v3[i] !== '5' && v3[i] !== '6' && v3[i] !== '7' && v3[i] !== '8' && v3[i] !== '9')
        {
            f = 0;
        }
    }
    if(f === 0)
    {
        MSG = "enter valid phone number";
    }
    
    if(v4 !== "CSE" && v4 !== "ECE" && v4 !== "EEE")
    {
        MSG = "branch should be CSE | ECE | EEE";
    }
    // console.log(MSG);

    // Check for the Date of Birth.

    const user = new DummyUser({
        name : v1,
        email : v2,
        phone : v3,
        college : req.body.college,
        branch : v4,
        dob : v5
    });
    v2 === User.findOne({email : v2}, function(err, foundUser)
    {
        if(err)
        {
            console.log("Error");
        }
        else
        {
            // TODO : need to tell user that Email Already Exists.
            if(foundUser !== null)
            {
                MSG = "Email Already Exists.";
                res.render("login", {msg : "Account Already Exists"});
            }
            else
            {
                if(MSG === "")
                {
                    // User.insertMany(user);
                    // profile redirect
                    let otp = Math.random();
                    otp = otp * 1000000;
                    otp = parseInt(otp);
                    // console.log(otp);
                    user.otp = otp;
                    user.otpexpire = Date.now() + 3600000;
                    DummyUser.deleteMany({email : v2}, (err, foundDummy)=>{
                        if(!err)
                        {}
                        else
                        console.log(err);
                    })
                    user.save();
                    var mailOptions = {
                        to: req.body.email,
                        subject: 'OTP for your registration',
                        html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                    };

                    transporter.sendMail(mailOptions, (err, info)=>{
                        if(err){
                            console.log(err)
                        }else{
                            res.render('otp', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                        }
                    })
                }
                else
                {
                    res.render("signup", {msg : MSG});
                }
            }
        }
    });
});

app.post('/verifyotp', (req,res)=>{
    DummyUser.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
        if(err){
          console.log(err)
        }else{
          if(!foundUser){
            res.render('otp', {email: req.body.email, msg: 'otp expired click resend otp'})
          }else{
              console.log(foundUser.otp);
              console.log(req.body.otp);
            if(foundUser.otp == req.body.otp){
              res.render('createpassword', {msg:'Successfully Verified', email: req.body.email})
            }else{
              res.render('otp', {email: req.body.email, msg: 'incorrect otp'})
            }
          }
        }
    })
})

app.post('/createpassword', (req,res)=>{
    DummyUser.findOne({email : req.body.email}, (err,foundUser)=>{
        if(!err)
        {
            var user = new User({
                name : foundUser.name,
                email : foundUser.email,
                college : foundUser.college,
                phone : foundUser.phone,
                dob : foundUser.dob,
                branch : foundUser.branch,
                password : req.body.password
            })
            user.save();
            res.redirect('login');
        }
    })
})

var LocalStrategy=require('passport-local').Strategy;
const { Int32 } = require("bson");
passport.use('user-local',new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
    },function(email, password, done) {
    User.findOne({ email: email }, function(err, user) {
        if (err) return done(err);
        if (!user) return done(null, false, { message: 'Incorrect Email.' });
        user.comparePassword(password, function(err, isMatch) {
            if (isMatch) 
            {
                return done(null, user);
            } 
            else 
            {
                return done(null, false, { message: 'Incorrect password.' });
            }
        });
    });
}))


passport.use('admin-local',new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },function(email, password, done) {
    Admin.findOne({ email: email }, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'Incorrect Email.' });
      user.comparePassword(password, function(err, isMatch) {
        if (isMatch) {
          return done(null, user);
        } else {
          return done(null, false, { message: 'Incorrect password.' });
        }
      });
    });
}));

app.get('/adminlogout', (req,res)=>{
    req.logout();
    res.redirect('/adminlogin');
})

app.post("/adminlogin", (req, res, next)=>{
    passport.authenticate("admin-local", function(err, user, info)
    {
        if(err)
        { 
            return next(err);
        }
        if(!user)
        {
            return res.render("adminlogin", {msg : info.message});
        }
        req.logIn(user, function(err)
        {
            if(err)
            { 
                return next(err); 
            }
            return res.render("admin");
        });
    })(req, res, next)
})

app.post("/admin", (req,res)=>{
    var tmp = new Election({
        collegename : req.body.college,
        electionname : req.body.electionname,
        semester : req.body.semester,
        electionuni : req.body.college + "_" + req.body.electionname,
        starttime : req.body.starttime,
        endtime : req.body.endtime
    })
    tmp.save();
    res.render("informer1", {message : "Successfully Added to the Database."});
})

app.get('/admin',function(req,res)
{
    // console.log(req);
 
    // popupS.alert({
    //     content: 'Hello World!'
    // });
    if(req.isAuthenticated())
    {
        res.render('admin');
    }
    else
    {
        console.log("Admin is Not Authenticated");
        res.render(informer1, {message : "Please Log In"});
    }
});

app.post("/login", function(req, res, next)
{
    passport.authenticate("user-local", function(err, user, info)
    {
        if(err)
        { 
            return next(err);
        }
        if(!user)
        {
            return res.render("login", {msg : info.message});
        }
        req.logIn(user, function(err)
        {
            if(err)
            { 
                return next(err); 
            }
            return res.redirect("/portal");
        });
    })(req, res, next)
});

app.get("/Reset_Password", function(req,res){
    res.sendFile(__dirname + "/Reset_Password.html");
});

app.post("/Reset_Password", function(req,res){
    console.log(req.body.email);
    var f = 0;
    User.findOne({email : req.body.email}, function(err,resp){
        if(!err)
        {
            console.log(resp);
            if(resp === null)
            {
                res.send("<h1> Failure 10 </h1>");
            }
            if(resp.password === req.body.oldpass)
            {
                User.updateOne({email : req.body.email}, {$set :{"password" : req.body.newpass}}, function(err,respond){
                    if (err) throw err;
                    console.log("1 document updated");
                    res.redirect("/login");
                });
                f = 1;
                // resp.password = req.body.newpass;
            }
            else
            {
                res.send("<h1> Failure 11 </h1>");
                f = 1;
            }
        }
        else
        {
            console.log("err");
            f = 1;
        }
    });
});

app.get('/portal',function(req,res)
{
    // console.log(req);
 
    // popupS.alert({
    //     content: 'Hello World!'
    // });
    if(req.isAuthenticated())
    {
        var Branch = req.user.college + "_" + req.user.email[0] + req.user.email[1] + "_" + req.user.branch;
        console.log(Branch);
        Election.find({electionuni : Branch}, (err, foundElections)=>{
            if(!err)
            {
                // console.log("Hi");
                console.log(foundElections);
                res.render('portal',{electionObject : foundElections, details : req.user});
            }
        })
    }
    else
    {
        console.log("User is Not Authenticated");
    }
});

app.post('/vote', (req,res)=>{
    Election.findOne({_id : req.body.id}, (err, electionObject)=>{
        if(!err)
        {
            var st_d = new Date(electionObject.starttime);
            var en_d = new Date(electionObject.endtime);
            var date = Date.now();
            var branch = electionObject.collegename + " " + req.user.branch + " " +"Semester " + electionObject.semester;
            if(st_d <= date && date <= en_d)
            {
                Result.find({electionID : req.body.id}, (err, foundelection)=>{
                    if(!err)
                    {
                        console.log(foundelection);
                        if(foundelection.length != 0)
                        {
                            res.render('vote', {Candidates : foundelection, Heading : branch});
                        }
                        else
                        {
                            res.render('informer', {message : "Election Abonded beacuse of lack of candidates."});
                        }
                    }
                })
            }
            else
            {
                res.redirect('/portal');
            }
        }
    })
})

app.post('/register', (req,res)=>{
    var electionid = req.body.id;
    const email = req.user.email.slice(0,9);
    const Name = req.user.name;
    var result = new Result({
        electionID : electionid,
        rollno : email,
        name : Name,
        count : 0
    })
    Result.findOne({electionID : electionid, rollno : email}, (err, foundres)=>{
        if(!err)
        {
            if(foundres)
            {
                res.render('informer', {message : "You are already Registered as a Leader for this Election."});
            }
            else
            {
                Election.findOne({_id : electionid}, (err, electionObject)=>{
                    if(!err)
                    {
                        var st_d = new Date(electionObject.starttime);
                        var date = Date.now();
                        if(st_d > date)
                        {
                            result.save();
                            res.render('informer', {message : "Successfully Registered."});
                        }
                        else
                        {
                            res.render('informer', {message : "Ooops! Time Up."});
                        }
                    }
                })
            }
        }
    })
})

app.post('/vote/voted', (req,res)=>{
    Voter.findOne({email : req.user.email , electionID : req.body.id}, (err, foundUser)=>{
        if(!err)
        {
            if(!foundUser)
            {
                const NewVoter = new Voter({
                    electionID : req.body.id,
                    email : req.user.email
                })
                NewVoter.save();
                Result.updateOne({electionID : req.body.id,rollno : req.body.Voted},{ $inc: { "count": 1 }}, (err, found)=>{
                    res.render('informer', {message : "Thank You! Your vote has been recorded."});
                });
            }
            else
            {
                res.render('informer', {message : "You already Casted your Vote."});
            }
        }
    })
})


app.post('/results', (req,res)=>{
    Result.find({electionID : req.body.id}, (err, foundResults)=>{
        if(!err)
        {
            if(foundResults.length != 0)
            {
                Election.find({_id : req.body.id}, (err, foundElections)=>{
                    if(!err)
                    {
                        console.log(foundElections);
                        res.render('results', {Candidates : foundResults, Heading : foundElections});
                    }
                })
            }
            else
            {
                res.render('informer', {message : "Election Abonded because of lack of Candidates."});
            }
        }
    })
})


app.get('/resetpassword', (req, res)=>{
    res.render('resetpassword');
})

app.post('/resetpassword', (req, res)=>{
    if(req.user.email == null)
    {
        res.send("Please come after some time...")
    }
    User.findOne({email : req.user.email}, (err, resp)=>{
        if(err)
        {
            console.log(err);
        }
        else
        {
            resp.password = req.body.newpass;
            resp.save();
            req.logout();
            res.redirect('login');
        }
    });
})


app.get('/forgot1stepemail', (req, res)=>{
    res.render('forgot1stepemail');
})

app.post('/forgot1stepemail', (req, res)=>{
    User.findOne({email : req.body.email}, (err, user)=>{
        if(!err)
        {
            if(user)
            {
                let otp = Math.random();
                otp = otp * 1000000;
                otp = parseInt(otp);
                // console.log(otp);
                user.otp = otp;
                user.otpexpire = Date.now() + 3600000;
                user.save();
                var mailOptions = {
                    to: req.body.email,
                    subject: 'OTP for your registration',
                    html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                };

                transporter.sendMail(mailOptions, (err, info)=>{
                    if(err){
                        console.log(err)
                    }else{
                        res.render('otpfor', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                    }
                })
            }
        }
    })
})

app.post('/resendotp', (req,res)=>{
    User.findOne({email : req.body.email}, (err, user)=>{
        if(!err)
        {
            if(user)
            {
                let otp = Math.random();
                otp = otp * 1000000;
                otp = parseInt(otp);
                // console.log(otp);
                user.otp = otp;
                user.otpexpire = Date.now() + 3600000;
                user.save();
                var mailOptions = {
                    to: req.body.email,
                    subject: 'OTP for your registration',
                    html: '<h3>OTP for verification is </h3>' + '<h1>'+ otp +'</h1>'
                };

                transporter.sendMail(mailOptions, (err, info)=>{
                    if(err){
                        console.log(err)
                    }else{
                        res.render('otpfor', {msg:'otp sent sucessfully to '+ req.body.email, email: req.body.email})
                    }
                })
            }
        }
    })
})

app.post('/verifyotpfor', (req,res)=>{
    User.findOne({email: req.body.email, otpexpire: {$gt: Date.now()}}, function(err, foundUser){
        if(err){
          console.log(err)
        }else{
          if(!foundUser){
            res.render('otp', {email: req.body.email, msg: 'otp expired click resend otp'})
          }else{
              console.log(foundUser.otp);
              console.log(req.body.otp);
            if(foundUser.otp == req.body.otp)
            {
              res.render('createpassword', {msg:'Successfully Verified', email: req.body.email})
            }
            else
            {
              res.render('otpfor', {email: req.body.email, msg: 'incorrect otp'})
            }
          }
        }
    })
})


app.get('/home', (req,res)=>{
    res.render('index');
})


// app.get('/informer', (req,res)=>{
//     res.render('informer');
// })

let port = process.env.PORT;
if (port == null || port == "") {
    port = 3000;
}
app.listen(port, function() {
    console.log("Server started on port 3000");
});
