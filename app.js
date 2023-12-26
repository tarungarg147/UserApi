const express = require("express");
const connectDB = require("./db/conn.js"); 
const app = express();
const registerApi = require("./routers/registerRoute.js")
const port = process.env.PORT || 3000;

const bodyParser = require('express').json;
app.use(bodyParser());

app.use('/registerApi',registerApi)


connectDB();
app.listen(port,()=>{
    console.log(`connection is live on the 
port no. ${port}`);
})
