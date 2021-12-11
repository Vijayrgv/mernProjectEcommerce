const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");


const userSchema = new mongoose.Schema({
   
    name:{
        type:String,
        required:[true,"Enter Your Name"],
        maxlength:[30,"Name cannot exceed 30 character"],
        minlength:[4,"Name should have more than 4 character"]
    },
    email:{
        type:String,
        required:[true,"Please Enter Your Email"],
        unique:true,
        validate:[validator.isEmail,"Please Enter a valid Email"]
    },
    password:{
        type:String,
        required:[true,"Please Enter Your Password"],
        minlength:[8,"Password Should be greater than 8 character"],
        select:false,
    },
    avatar:{
        public_id:{
            type:String,
            required:true,
        },
        url:{
            type:String,
            required:true,
            default:"https://res.cloudinary.com/rgv23/image/upload/v1636963782/avatars/cw0wmmyqqpuwetop6s2j.jpg"
        },
    },
    role:{
        type:String,
        default:"user",
    },
    createdAt:{
        type:Date,
        default:Date.now
    },
    resetPasswordToken:String,
    resetPasswordExpire: Date,
});

userSchema.pre("save",async function(next){

    if(!this.isModified("password")){
        next();
    }

    this.password = await bcrypt.hash(this.password,10)
})

// JQT Token

userSchema.methods.getJWTToken = function(){
    return  jwt.sign({id:this._id},process.env.JWT_SECRET,{
        expiresIn: process.env.JWT_EXPIRE,
    })
}

// Compare Password

userSchema.methods.comparePassword = async function (enteredPassword){
    return await bcrypt.compare(enteredPassword,this.password);
}


// Generating password reset token

userSchema.methods.getResetPasswordToken = function(){

    //Generating token
    const resetToken = crypto.randomBytes(20).toString("hex");

    //Hashing and add to userSchema

    this.resetPasswordToken = crypto.createHash("sha256")
    .update(resetToken)
    .digest("hex");

    this.resetPasswordExpire = Date.now() + 15 *60*1000;

    return resetToken;
}


module.exports = mongoose.model("User",userSchema);