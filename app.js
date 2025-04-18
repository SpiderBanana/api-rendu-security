const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3000;

// Middleware pour parser le JSON du body
app.use(express.json());

// Initialisation du client Supabase
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Clé secrète pour signer les JWT
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * Middleware d'authentification :
 * - Vérifie le token JWT transmis dans l'en-tête Authorization.
 * - Récupère l'utilisateur ainsi que son rôle via une jointure entre les tables users et roles.
 */
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token manquant' });
  }

  jwt.verify(token, JWT_SECRET, async (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Token invalide' });
    }
    // Requête pour récupérer l'utilisateur avec ses informations de rôle
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, email, role_id, roles(id, name, can_post_login, can_get_my_user, can_get_users, can_post_products)')
      .eq('id', decoded.id)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Utilisateur non trouvé ou non authentifié' });
    }
    req.user = user;
    next();
  });
};

/**
 * Middleware de vérification de permission :
 * Vérifie si l'utilisateur authentifié possède la permission spécifiée.
 *
 * @param {string} permission - Par exemple "can_get_users" ou "can_get_my_user"
 */
const checkPermission = (permission) => {
  return (req, res, next) => {
    if (!req.user || !req.user.roles || !req.user.roles[permission]) {
      return res.status(403).json({ error: 'Permission refusée: ' + permission });
    }
    next();
  };
};

/**
 * Endpoint POST /register
 * Inscription d'un nouvel utilisateur.
 * Pour cette inscription, le rôle est fixé par défaut à "USER".
 */
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;

  // Vérifier la présence des champs requis
  if (!name || !email || !password) {
    return res.status(400).json({ error: "Les champs name, email et password sont requis." });
  }

  try {
    // Hacher le mot de passe
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Récupérer le rôle "USER" depuis la table roles
    const { data: roleData, error: roleError } = await supabase
      .from('roles')
      .select('id')
      .eq('name', 'USER')
      .single();

    if (roleError) {
      return res.status(500).json({ error: roleError.message });
    }

    // Insertion de l'utilisateur avec role_id correspondant
    const { data, error } = await supabase
      .from('users')
      .insert([{ name, email, password: hashedPassword, role_id: roleData.id }])
      .single();

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.status(201).json({ message: "Utilisateur créé avec succès.", user: data });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * Endpoint POST /login
 * Authentifie l'utilisateur et retourne un token JWT valable 1 heure.
 */
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Vérifier la présence de l'email et du mot de passe
  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' });
  }

  try {
    // Récupérer l'utilisateur par email
    const { data: user, error } = await supabase
      .from('users')
      .select('id, email, password')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    // Vérifier le mot de passe
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Identifiants invalides' });
    }

    // Générer le token JWT valable 1h
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * Endpoint GET /my-user
 * Retourne les informations de l'utilisateur connecté.
 * Nécessite que le token JWT soit envoyé dans l'en-tête Authorization.
 * Permission requise : can_get_my_user
 */
app.get('/my-user', authenticateToken, checkPermission('can_get_my_user'), async (req, res) => {
  const userId = req.user.id;
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('id, name, email')
      .eq('id', userId)
      .single();
    if (error || !user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    return res.json(user);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * Endpoint GET /users
 * Retourne la liste de tous les utilisateurs.
 * Accès réservé aux utilisateurs disposant de la permission "can_get_users".
 */
app.get('/users', authenticateToken, checkPermission('can_get_users'), async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from('users')
      .select('id, name, email');
    if (error) {
      return res.status(500).json({ error: error.message });
    }
    return res.json(users);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

/**
 * Endpoint POST /products
 * Crée un produit dans Shopify et enregistre l'ID du produit et l'ID de l'utilisateur.
 * Nécessite que le token JWT soit envoyé dans l'en-tête Authorization.
 * Permission requise : can_post_products
 */
app.post('/products', authenticateToken, checkPermission('can_post_products'), async (req, res) => {
  const { name, price } = req.body;
  const userId = req.user.id;

  if (!name || !price) {
    return res.status(400).json({ error: "Les champs name et price sont requis." });
  }

  try {
    const shopifyEndpoint = process.env.SHOPIFY_SHOP_URL + `/admin/api/2025-04/products.json`;
    const shopifyAccessToken = process.env.SHOPIFY_ACCESS_TOKEN; 
    const headers = {
      'Content-Type': 'application/json',
      'X-Shopify-Access-Token': shopifyAccessToken,
    };

    const productData = {
      product: {
        title: name,
        variants: [{ price: price }],
      },
    };

    const response = await fetch(shopifyEndpoint, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(productData),
    });

    const responseData = await response.json();

    if (!response.ok) {
      console.error('Shopify API Error:', responseData);
      return res.status(500).json({ error: `Erreur lors de la création du produit dans Shopify` });
    }

    const shopifyProductId = responseData.product.id;

    const { data, error } = await supabase
      .from('products')
      .insert([{ shopify_id: shopifyProductId, created_by: userId }])
      .single();

    if (error) {
      console.error('Supabase Error:', error);
      return res.status(500).json({ error: 'Erreur lors de l\'enregistrement dans la base de données' });
    }

    return res.status(201).json({ message: "Produit créé avec succès dans Shopify et enregistré dans la base de données.", productId: shopifyProductId });
  } catch (err) {
    console.error('Error:', err);
    return res.status(500).json({ error: err.message });
  }
});

app.get('/my-products', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  try {
    const { data: products, error } = await supabase
      .from('products')
      .select('*')
      .eq('created_by', userId);

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.json(products);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get('/products', async (req, res) => {
  try {
    const { data: products, error } = await supabase
      .from('products')
      .select('*');

    if (error) {
      return res.status(500).json({ error: error.message });
    }

    return res.json(products);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Démarrage du serveur
app.listen(port, () => {
  console.log(`L'API est démarrée sur le port ${port}`);
});
 