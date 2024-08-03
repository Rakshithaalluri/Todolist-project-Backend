const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require('cors');

dotenv.config();

const app = express();
app.use(cors());

const dbPath = path.join(__dirname, "database.db");

const jwtSecret = process.env.JWT_SECRET || "your_jwt_secret_key";

let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database
    });

    // Create users table
    await db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
      );
    `);

    // Create todos table
    await db.run(`
      CREATE TABLE IF NOT EXISTS todos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        description TEXT NOT NULL,
        status TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
    `);

    await db.run(`
        CREATE TABLE IF NOT EXISTS login_activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER NOT NULL,
          login_time TEXT NOT NULL,
          FOREIGN KEY (user_id) REFERENCES users(id)
        );
      `);
          
    app.listen(3000, () => {
      console.log("Server Running at http://localhost:3000/");
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

app.use(express.json());

// Registration endpoint
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const selectUserQuery = `SELECT * FROM users WHERE username = ?`;
    const dbUser = await db.get(selectUserQuery, [username]);

    if (dbUser === undefined) {
      const createUserQuery = `
        INSERT INTO users (username, password)
        VALUES (?, ?)`;
      const dbResponse = await db.run(createUserQuery, [username, hashedPassword]);
      const newUserId = dbResponse.lastID;
      res.status(201).send(`Created new user with ID ${newUserId}`);
    } else {
      res.status(400).send("User already exists");
    }
  } catch (e) {
    res.status(500).send("Error registering user");
  }
});

// Login endpoint
app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    try {
      const selectUserQuery = `SELECT * FROM users WHERE username = ?`;
      const dbUser = await db.get(selectUserQuery, [username]);
  
      if (dbUser === undefined) {
        res.status(400).send("Invalid User");
      } else {
        const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
        if (isPasswordMatched) {
          const token = jwt.sign({ id: dbUser.id }, jwtSecret, { expiresIn: '30d' });
  
          // Record the login activity
          const loginTime = new Date().toISOString(); 
          await db.run(`
            INSERT INTO login_activity (user_id, login_time)
            VALUES (?, ?)`,
            [dbUser.id, loginTime]
          );
  
          res.json({ token });
        } else {
          res.status(400).send("Invalid Password");
        }
      }
    } catch (e) {
      res.status(500).send("Error logging in");
    }
  });
  

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};


  app.post("/todos", authenticateJWT, async (req, res) => {
    const { description, status } = req.body;
    const userId = req.user.id;
  
    if (!description || !status) {
      return res.status(400).send("Description and status are required");
    }
  
    try {
      const dbResponse = await db.run(`
        INSERT INTO todos (user_id, description, status)
        VALUES (?, ?, ?)`,
        [userId, description, status]
      );
  
      const newTodo = {
        id: dbResponse.lastID,
        user_id: userId,
        description,
        status,
      };
  
      res.status(201).json(newTodo);
    } catch (e) {
      console.error("Error creating to-do item:", e);
      res.status(500).send("Error creating to-do item");
    }
  });
  
  
  app.get("/todos", authenticateJWT, async (req, res) => {
    const userId = req.user.id;
  
    try {
      const todos = await db.all(`
        SELECT * FROM todos WHERE user_id = ?`,
        [userId]
      );
      res.json(todos);
    } catch (e) {
      res.status(500).send("Error fetching to-do items");
    }
  });

  // Endpoint to get a single to-do item by ID
app.get("/todos/:id", authenticateJWT, async (req, res) => {
    const { id } = req.params;
    try {
      const todo = await db.get(`
        SELECT * FROM todos WHERE id = ? AND user_id = ?`,
        [id, req.user.id]
      );
  
      if (todo) {
        res.json(todo);
      } else {
        res.status(404).send("To-Do item not found");
      }
    } catch (e) {
      res.status(500).send("Error fetching to-do item");
    }
  });
  
  app.put("/todos/:id", authenticateJWT, async (req, res) => {
    const { description, status } = req.body;
    const todoId = req.params.id;
    const userId = req.user.id;
  
    try {
      const todo = await db.get(`
        SELECT * FROM todos WHERE id = ? AND user_id = ?`,
        [todoId, userId]
      );
  
      if (todo) {
        await db.run(`
          UPDATE todos
          SET description = ?, status = ?
          WHERE id = ?`,
          [description, status, todoId]
        );
        res.send("To-Do item updated successfully");
      } else {
        res.status(404).send("To-Do item not found");
      }
    } catch (e) {
      res.status(500).send("Error updating to-do item");
    }
  });
  
  app.delete("/todos/:id", authenticateJWT, async (req, res) => {
    const todoId = req.params.id;
    const userId = req.user.id;
  
    try {
      const todo = await db.get(`
        SELECT * FROM todos WHERE id = ? AND user_id = ?`,
        [todoId, userId]
      );
  
      if (todo) {
        await db.run(`
          DELETE FROM todos WHERE id = ?`,
          [todoId]
        );
        res.send("To-Do item deleted successfully");
      } else {
        res.status(404).send("To-Do item not found");
      }
    } catch (e) {
      res.status(500).send("Error deleting to-do item");
    }
  });
  
  // Protected route example
  app.get("/protected", authenticateJWT, (req, res) => {
    res.send("This is a protected route");
  });

