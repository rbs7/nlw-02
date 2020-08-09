import { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

import authConfig from '../config/auth.json';

import db from '../database/connection';

function generateToken(params = {}) {
  const token = jwt.sign(params, authConfig.secret, {
    expiresIn: 86400,
  });

  return token;
}
export default class UsersController {

  async create(request: Request, response: Response) {
    const { email, password, name } = request.body;

    const newPassword = await bcrypt.hash(password, 10);

    const oldUser = await db('users')
      .where('users.email', '=', email)
      .first();

    if (oldUser) {
      return response.status(400).json({ error: 'Email already registered' });
    }

    const trx = await db.transaction();
  
    try {
      const user = {
        email,
        password: newPassword,
        name,
        avatar: null,
        whatsapp: null,
        bio: null
      };

      const insertedUsersIds = await trx('users').insert(user);
    
      const user_id = insertedUsersIds[0];
      await trx.commit();
  
      return response.status(201).json({
        user: { ...user, id: user_id, password: undefined },
        token: generateToken({ id: user_id })
      });
    } catch (err) {
      console.log(err);

      await trx.rollback();
  
      return response.status(400).json({
        error: 'Unexpected error while creating a new user'
      });
    }
  }

  async authenticate(request: Request, response: Response) {
    const { email, password } = request.body;

    const user = await db('users')
      .where('users.email', '=', email)
      .first();

    if (!user) {
      return response.status(400).json({ error: 'User not found' });
    }

    if (!await bcrypt.compare(password, user.password)) {
      return response.status(400).json({ error: 'Invalid password' });
    }

    user.password = undefined;


    return response.status(200).json({
      user,
      token: generateToken({ id: user.id })
    });
  }
}