const express = require('express');
const mongoose = require('mongoose');
const loginSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
    },
    password:{
        type:String,
        required:true,
        trim: true,
    },
});

// We are Creating a new Collection.
const Login = new mongoose.model("Login",loginSchema)

module.exports = Login;