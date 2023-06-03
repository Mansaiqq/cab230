var express = require('express');
var router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const TokenGenerator = require('../token-generator');
const tokenGenerator = new TokenGenerator(process.env.JWT_SECRET, process.env.JWT_SECRET);
const authorizationMiddleware = require("../middlewares/authorizationMiddleware");
router.use('/people/',authorizationMiddleware);
router.use('/user/:email/profile',authorizationMiddleware);
const rateLimit =require("express-rate-limit");
const limiter = rateLimit({
  windowMs: 60* 1000,
  max:100,
  message:"Too many requests, please try again later."
})
/* GET home page. */
router.get("/movies/search", limiter, function (req, res) {
  req.db;
  const { title, year, page } = req.query;

  const perPage = 100;
  const currentPage = page ? parseInt(page) : 1;

  let query = req.db.from("basics");

  if (title) {
    query = query.where("primaryTitle", "regexp", title);
  }

  if (year) {
    if (!/^\d{4}$/.test(year)) {
      res.status(400).json({
        error: true,
        message: "Invalid year format. Format must be yyyy.",
      });
      return;
    }
    query = query.where("year", year);
  }

  query
    .select(
      "primaryTitle as title",
      "year",
      "tconst as imdbID",
      req.db.raw("CAST(imdbRating AS UNSIGNED) AS imdbRating"),
      req.db.raw("CAST(rottentomatoesRating AS UNSIGNED) AS rottenTomatoesRating"),
      req.db.raw("CAST(metacriticRating AS UNSIGNED) AS metacriticRating"),
      "rated as classification"
    )
    .then((rows) => {
      const totalCount = rows.length;
      const lastPage = Math.ceil(totalCount / perPage);

      const from = (currentPage - 1) * perPage;
      const to = Math.min(from + perPage, totalCount);

      const paginatedData = rows.slice(from, to);

      const pagination = {
        total: totalCount,
        lastPage: lastPage,
        perPage: perPage,
        currentPage: currentPage,
        from: from + 1,
        to: to,
      };

      res.json({ data: paginatedData, pagination: pagination });
    })
    .catch((err) => {
      console.log(err);
      res.json({ Error: true, Message: "Error in MySQL query" });
    });

});


router.get("/movies/data/:imdbID", limiter, function (req, res, next) {

  req.db
    .select(
      "basics.primaryTitle as title",
      "basics.year",
      "basics.runtimeMinutes as runtime",
      "basics.genres",
      "basics.country",
      "basics.boxoffice",
      "basics.poster",
      "basics.plot",
      "principals.tconst",
      "principals.nconst as id",
      "principals.category",
      "principals.name",
      "principals.characters"
    )
    .from("basics")
    .leftJoin("principals", "basics.tconst", "principals.tconst")
    .where("basics.tconst", req.params.imdbID)
    .then((rows) => {
      if (rows.length > 0) {
        const movieData = {
          title: rows[0].title,
          year: rows[0].year,
          runtime: rows[0].runtime,
          genres: rows[0].genres.split(","),
          country: rows[0].country,
          principals: rows.map((row) => ({
            id: row.id,
            category: row.category,
            name: row.name,
            characters: row.characters ? JSON.parse(row.characters) : [],
          })),
          boxoffice: rows[0].boxoffice,
          poster: rows[0].poster,
          plot: rows[0].plot,
        };
        res.json({ data: movieData });
      } else {
        res.status(404).json({ Error: true, Message: "No record exists of a movie with this ID" });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ Error: true, Message: "Error in MySQL query" });
    });
});

router.get("/people/:id", function (req, res, next) {
  const personId = req.params.id;
 

  req.db
    .select(
      "names.primaryName as name",
      "names.birthYear",
      "names.deathYear",
      "principals.tconst as movieId",
      "basics.primaryTitle as movieName",
      "principals.category",
      "principals.characters",
      "basics.imdbRating"
    )
    .from("principals")
    .leftJoin("basics", "principals.tconst", "basics.tconst")
    .leftJoin("names", "principals.nconst", "names.nconst")
    .where("names.nconst", personId)
    .then((rows) => {
      if (rows.length > 0) {
        const personData = {
          name: rows[0].name,
          birthYear: rows[0].birthYear,
          deathYear: rows[0].deathYear,
          roles: rows.map((row) => ({
            movieName: row.movieName,
            movieId: row.movieId,
            category: row.category,
            characters: row.characters ? JSON.parse(row.characters) : [],
            imdbRating: row.imdbRating,
          })),
        };
        res.json(personData);
      } else {
        res.status(404).json({ Error: true, Message: "No data found" });
      }
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ Error: true, Message: "Error in MySQL query" });
    });
});

router.post('/user/register', function (req, res, next) {
  // Retrieve email and password from req.body
  const email = req.body.email;
  const password = req.body.password;

  // Verify body
  if (!email || !password) {
    res.status(400).json({
      error: true,
      message: "Request body incomplete, both email and password are required"
    });
    return;
  }

  // Determine if user already exists in table
  const queryUsers = req.db.from("users").select("*").where("email", "=", email);
  queryUsers.then(users => {
    if (users.length > 0) {
      throw new Error("User already exists");
    }

    // Insert user into DB
    const saltRounds = 10;
    const hash = bcrypt.hashSync(password, saltRounds);
    return req.db.from("users").insert({ email, hash });
  })
  .then(() => {
    // Insert email into profile table
    return req.db.from("profile").insert({ email });
  })
    .then(() => {
      res.status(201).json({ message: "User created" });
    })
    .catch(e => {
      res.status(500).json({ success: false, message: e.message });
    });
});

router.post('/user/login', function (req, res, next) {
  // 1. Retrieve email and password from req.body
  const email = req.body.email;
  const password = req.body.password;
  // Verify body
  if (!email || !password) {
    res.status(400).json({
      error: true,
      message: "Request body incomplete, both email and password are required"
    });
    return;
  }
  // 2. Determine if user already exists in table

  const queryUsers = req.db.from("users").select("*").where("email", "=", email);
  queryUsers
    .then(users => {
      if (users.length === 0) {
        res.status(401).json({
          error: true,
          message: "Request body incomplete, both email and password are required"
        });
        return;
      }

      // Compare password hashes
      const user = users[0];
      return bcrypt.compare(password, user.hash);
    })
    .then(match => {
      if (!match) {
        res.status(401).json({
          error: true,
          message: "Request body incomplete, both email and password are required"
        });
        return;
      }
      const expires_in = 60 * 10; // 24 hours
      const refreshTokenexpires_in = 60 * 60 * 24; // 24 hours
      const exp = Math.floor(Date.now() / 1000) + expires_in;
      const refreshTokenexp = Math.floor(Date.now() / 1000) + refreshTokenexpires_in;
      const token = jwt.sign({ exp, email }, process.env.JWT_SECRET);
      const refreshToken = tokenGenerator.sign({ exp: refreshTokenexp, email });
      res.status(200).json({
        "bearerToken": {
          "token": token,
          "token_type": "Bearer",
          "expires_in": expires_in
        },
        "refreshToken": {
          "token": refreshToken,
          "token_type": "Refresh",
          "expires_in": refreshTokenexpires_in
        }

      });
    });

});

router.post('/user/refresh', function (req, res, next) {
  const refreshToken = req.body.refreshToken;
  if (!refreshToken) {
    res.status(400).json({
      error: true,
      message: "Request body incomplete, refresh token required"
    });
    return;
  }


  try {
    const decodeToken = jwt.verify(refreshToken, process.env.JWT_SECRET);
    const refreshTokenexpires_in = decodeToken.exp - Math.floor(Date.now() / 1000);
    if (Date.now() >= decodeToken.exp * 1000) {
      res.status(401).json({
        error: true,
        message: "JWT token has expired"
      });
      return;
    }
    const expires_in = 600;
    const bearerToken = jwt.sign({ exp: expires_in, email: decodeToken.email }, process.env.JWT_SECRET);

    res.status(200).json({
      "bearerToken": {
        "token": bearerToken,
        "token_type": "Bearer",
        "expires_in": expires_in
      },
      "refreshToken": {
        "token": refreshToken,
        "token_type": "Refresh",
        "expires_in": refreshTokenexpires_in
      },
    });

  } catch (error) {
    res.status(401).json({
      error: true,
      message: "Invalid refresh request"
    });
    return;
  }


});
router.post('/user/logout', function (req, res, next) {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    res.status(400).json({
      error: true,
      message: "Request body incomplete, refresh token required"
    });
    return;
  }

  try {
    const decodeToken = jwt.verify(refreshToken, process.env.JWT_SECRET);
    if (Date.now() >= decodeToken.exp * 1000) {
      res.status(401).json({
        error: true,
        message: "JWT token has expired"
      });
      return;
    }
    const email = decodeToken.email;

    const updateData = {
      logout_timestamp: Math.floor(Date.now() / 1000)
    };

    const queryUsers = req.db.from("users").where("email", "=", email).update(updateData);

    queryUsers
      .then(() => {
        res.status(200).json({
          error: false,
          message: "Token successfully invalidated"
        });
      })
      .catch((err) => {
        console.log(err);
        res.status(500).json({
          error: true,
          message: "Error updating logout token"
        });
      });
  } catch (error) {
    res.status(401).json({
      error: true,
      message: "Invalid logout request"
    });
    return;
  }
});
router.get('/user/:email/profile', function (req, res, next) {
  let email = req.params.email;
  email = email.replace('/%40/g', '@');
  const queryUser = req.db.from("profile").select("*").where("email", "=", email);
  queryUser
    .then((user) => {
      if (user.length === 0) {
        throw new Error("User does not exist");
      }

      const userProfile = {
        email: user[0].email,
        firstName: user[0].firstName,
        lastName: user[0].lastName,
      };
      // Check if the bearer token belongs to the profile's owner
      if (userProfile.email === req.email) {
        userProfile.dob = user[0].dob;
        userProfile.address = user[0].address;
      }

      res.status(200).json(userProfile);
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ error: true, message: 'Error retrieving user profile' });
    });
});
router.put('/user/:email/profile', function (req, res, next) {


  let email = req.params.email;
  email = email.replace('/%40/g', '@');
  console.log(email);
  const queryUser = req.db.from("profile").select("*").where("email", "=", email);
  queryUser.then((user) => {
    if (user.length === 0) {
      throw new Error("User does not exist");
    }

    // Update user profile in DB
    const { firstName, lastName, dob, address } = req.query;

    const updateData = {};

    if (firstName !== undefined) {
      updateData.firstName = firstName;
    }

    if (lastName !== undefined) {
      updateData.lastName = lastName;
    }

    if (dob !== undefined) {
      updateData.dob = dob;
    }

    if (address !== undefined) {
      updateData.address = address;
    }

    return req.db("profile").where("email", "=", email).update(updateData);
  })
    .then(() => {
      return req.db("profile").where("email", email).first();
    })
    .then((updatedProfile) => {
      const { email, firstName, lastName, dob, address } = updatedProfile;

      const userProfile = {
        email,
        firstName,
        lastName,
        dob,
        address,
      };

      res.json({
        data: userProfile,
      });
    })
    .catch((err) => {
      console.log(err);
      res.status(500).json({ error: true, message: 'Error updating user profile' });
    });
});
module.exports = router;
