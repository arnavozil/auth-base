const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
	firstName: { type: String, default: null },
	lastName: { type: String, default: null },
	email: { type: String, unique: true },
	password: { type: String },
	token: { type: String },
});

userSchema.set('toJSON', {
    virtuals: true,
    versionKey: false,
    transform: (doc, ret) => {
        delete ret._id,
        delete ret.password
    }
});

module.exports = mongoose.model("user", userSchema);