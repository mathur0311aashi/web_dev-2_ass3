const jwt = require("jsonwebtoken");
const auth = (req, res, next)=>{
    try{
        const token = req.headers.authorization.split(" ")[1]; // Assuming the token is sent as "Bearer <token>"
        console.log("token received", token);
        if (!token) {
            return res.status(401).send({msg: "login first"});
        }

        const decoded = jwt.verify(token, "coding");
        req.user = decoded;
        console.log("DECODED TOKEN:", decoded);
        next();
    } catch (error) {
        console.log("JWT ERROR:", error.message);
        res.status(401).send({msg: "Invalid or expired token"});
    }
};
const adminAuth = (req, res, next)=> {
    if (!req.user || req.user.role !== "admin"){
        return res.status(403).send({msg: "Access denied. Admins only."});
    }
    next();
};
module.exports = {auth, adminAuth};