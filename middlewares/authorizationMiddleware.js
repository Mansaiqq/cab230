const jwt = require('jsonwebtoken');
module.exports = function (req, res, next) {
    if (!("authorization" in req.headers)
        || !req.headers.authorization.match(/^Bearer /)
    ) {
        res.status(401).json({ error: true, message: "Authorization header ('Bearer token') not found" });
        return;
    }
    const token = req.headers.authorization.replace(/^Bearer /, "");
    try {
        const decodeToken = jwt.verify(token, process.env.JWT_SECRET);
        req.email = decodeToken.email;
        const queryUser = req.db.from("users").select("logout_timestamp").where("email", "=", decodeToken.email);
        queryUser
            .then((user) => {
                const logoutTimestamp = user[0] ? parseInt(user[0].logout_timestamp, 10) : null;
                if (user && (logoutTimestamp === null || decodeToken.iat < logoutTimestamp)){
                    res.status(401).json({ error: true, message: "JWT token has expired" });
                } else {
                    next();
                }
            })
            .catch((err) => {
                console.log(err);
                res.status(500).json({ error: true, message: "Error retrieving logout timestamp" });
            });
    } catch (e) {
        if (e.name === "TokenExpiredError") {
            res.status(401).json({ error: true, message: "JWT token has expired" });
        } else {
            res.status(401).json({ error: true, message: "Invalid JWT token" });
        }
    }
};