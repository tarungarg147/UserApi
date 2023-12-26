const mongoose = require('mongoose');

uri = "mongodb://localhost/db";

const connectDB = ()=>{
    // console.log("Connected to mongodb")
        return mongoose.connect(uri,{
           useNewUrlParser:true,
        }).then(() => {
           useUnifiedTopology: true, 
            console.log("Connected to monodb!...");
        }).catch((err) => {
            console.log("Failed to connect db!..." + err);
        });
       
    };
module.exports = connectDB;