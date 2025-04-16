
const express = require('express');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware pour parser le JSON du body des requêtes
app.use(express.json());

// Initialisation du client Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

app.get('/health', (req, res) => {
    res.json({ test: "hello world" });
  });

/**
 * Endpoint POST /register
 * Permet d’enregistrer un nouvel utilisateur
 * Reçoit dans le body : { name, email, password }
 */
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Vérifier que tous les champs sont présents
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Tous les champs (name, email, password) sont requis." });
  }

  try {
    // Hacher le mot de passe avant de l’enregistrer
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Insertion dans la table "users"
    const { data, error } = await supabase
      .from('users')
      .insert([{ name: name, email: email, password: hashedPassword }])
      .single();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    // Réponse en cas de succès
    return res.status(201).json({ message: "Utilisateur créé avec succès.", user: data });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Démarrage du serveur
app.listen(port, () => {
  console.log(`L'API est démarrée sur le port ${port}`);
});
