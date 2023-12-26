const express = require('express');
const mongoose = require('mongoose');
const registerSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
        unique:true,
        trim: true,
    },
    password:{
        type:String,
        required:true,
        trim: true,
    },
    confirmPassword :{
        type:String,
        trim: true,
    },
    name: {
        type: String,
    },
    image: {
        type: String,
    },
    verificationCode: {
        type: String,
    },
    verificationCodeExpiration: {
        type: Date,
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    resetToken: {
        type: String,
    },
    resetTokenExpiration: {
        type: Date,
    },
    

  });

// We are Creating a new Collection.
const Register = new mongoose.model("Register",registerSchema)

module.exports = Register;