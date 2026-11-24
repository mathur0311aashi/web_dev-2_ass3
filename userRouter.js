const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { userModel } = require("./userModel");
const { auth, adminAuth } = require("./auth.middleware");
const userRouter = express.Router();

// register route
userRouter.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const extinguisher = await userModel.findOne({ email });
        if (extinguisher) {
            return res.status(409).send({ msg: "Email already registered" });
        }

        bcrypt.hash(password, 5, async (err, hash) => {
            if (hash) {
                const user = new userModel({ name, email, password: hash });
                await user.save();
                res.status(201).send({ msg: "user registered successfully" });
            } else {
                res.send({ msg: "Something went wrong" })
            }
        });
    } catch (error) {
        console.log("Register Error:", error);
        res.status(500).send({
            msg: "Something went wrong",
            error: error.message
        });
    }
});

userRouter.post("/login", async (req, res) => {
    const { email, password } = req.body;
    try {
        // ye to check krna hoga na apne pehle database me ki ye wala already registered user h ya nhi
        // for checking
        const user = await userModel.find({ email });
        console.log("Email received:", email);
        console.log("User found:", user.length);
        if (user.length > 0) {
            // check password
            // load hash from your password db
            // pehle hi hm password ko hash kr chuke h na to decode krake hi to check kremge
            bcrypt.compare(password, user[0].password, async (err, result) => {
                console.log("Password match:", result);
                console.log("Bcrypt error:", err);
                // if found
                if (result) {
                    const token = jwt.sign({
                        foo: "bar",
                        id: user[0]._id,
                        role: user[0].role
                    }, "coding");
                    // coding is secret code jo database ko dena hoga
                    console.log("GENERATED TOKEN:", token);
                    res.send({ msg: "User login successfully", token });
                } else {
                    res.send({ msg: "wrong credentials" });
                }
            });
            // console.log(user);
        } else {
            res.send({ msg: "signup first" });
        }
    } catch (error) {
        res.send({ msg: "Something went wrong" });
    }
    userRouter.post("/logout", (req, res) => {
        res.send({ msg: "Logout successfully" });
    })
});
// update route
userRouter.get("/profile", auth, async (req, res) => {
    try {
        // ab hmne isme hm file search kr rhe h backend me, find krke and selected show kre
        const user = await userModel.findById(req.user.id).select("-password"); // password ko show nhi krna h
        if (!user) {
            return res.status(400).send({ msg: "User not found" });
        }
        res.send({ user });
    } catch (error) {
        res.status(500).send({ msg: "Something went wrong" });
    }
});
userRouter.patch("/update", auth, async (req, res) => {
    try {
        // name and email pehlle server se
        const { name, email } = req.body;
        const updatedUser = await userModel.findByIdAndUpdate(
            req.user.id,
            { name, email },
            { new: true, runValodators: true }
        ).select("-password");
        if (!updatedUser) {
            res.status(404).send({ msg: "User not found" });
        }
        res.send({
            msg: "Profile updated successfully",
            user: updatedUser
        });
    } catch (error) {
        res.status(500).send({ msg: "Something went wrong" });
    }
});

// delete 
userRouter.delete("/delete", auth, async (req, res) => {
    // delete iss uspe karenge na ki pehle pehle wala match huye to uske liye
    try {
        const deleteUser = await userModel.findByIdAndDelete(req.user.id);

        if (!deleteUser) {
            return res.status(404).send({ msg: "user not found" });
        }
        res.send({ msg: "user deleted successfully" });
    } catch (error) {
        res.status(500).send({ msg: "Something went wrong" });
    }
});

// read - all users
userRouter.get("/all", auth, adminAuth, async (req, res) => {
    try {
        const users = await userModel.find().select("-password");
        res.send({ users });
    } catch (error) {
        res.status(500).send({ msg: "something went wrong" });
    }
});

// read- by user id
userRouter.get("/:id", auth, adminAuth, async (req, res) => {
    try {
        const user = await userModel.findById(req.params.id).select("-password");
        if (!user) {
            return res.status(404).send({ msg: "User not found" });
        }
        res.send({ user });
    } catch (error) {
        res.status(500).send({ msg: "Something went wrong" });
    }
});

// update by any user deny krna h
userRouter.patch("/admin/update/:id", auth, adminAuth, async (req, res) => {
    try {
        const { name, email, role } = req.body;
        const updatedUser = await userModel.findByIdAndUpdate(
            req.params.id,
            { name, email, role },
            { new: true, runValidators: true }
        ).select("-password");
        if (!updatedUser) {
            return res.status(404).send({ msg: "user not found" });
        }
        res.send({
            msg: "User updated successfully",
            user: updatedUser
        })
    } catch (error) {
        res.status(400).send({ msg: "invalid data or user id" });
    }
})
userRouter.delete("/admin/delete/:id", auth, adminAuth, async (req, res) => {
    try {
        const deletedUser = await userModel.findByIdAndDelete(req.params.id);
        if (!deletedUser) {
            return res.status(404).send({ msg: "user not found" });
        }
        res.send({ msg: "user deleted successfully" });
    } catch (error) {
        res.status(400).send({ msg: "invalid user id" });
    }
});
module.exports = { userRouter }