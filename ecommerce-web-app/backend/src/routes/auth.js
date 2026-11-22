import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
const router = Router();
const publicUser = user => ({ id: user._id, name: user.name, email: user.email, role: user.role });
const issueToken = user => jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
router.post('/register', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2 || name.length > 80 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 128) {
      return res.status(400).json({ message: 'Enter a valid name and email, and a password between 8 and 128 characters.' });
    }
    if (await User.exists({ email })) return res.status(409).json({ message: 'An account with this email already exists.' });
    const user = await User.create({ name, email, password: await bcrypt.hash(password, 12) });
    res.status(201).json({ token: issueToken(user), user: publicUser(user) });
  } catch (e) {
    if (e.code === 11000) return res.status(409).json({ message: 'An account with this email already exists.' });
    res.status(500).json({ message: 'Could not create account.' });
  }
});
router.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(String(req.body.password || ''), user.password))) return res.status(401).json({ message: 'Email or password is incorrect.' });
  res.json({ token: issueToken(user), user: publicUser(user) });
});
export default router;
