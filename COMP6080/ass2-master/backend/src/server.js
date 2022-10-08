import fs from 'fs';
import express from 'express';
import swaggerUi from 'swagger-ui-express';
import cors from 'cors';
import morgan from 'morgan';

import { InputError, AccessError, } from './error';
import { BACKEND_PORT } from '../../frontend/src/config';
import swaggerDocument from '../swagger.json';
import {
  save,
  getUserIdFromAuthorization,
  login,
  logout,
  register,
  assertValidChannel,
  assertValidUserId,
  getChannels,
  getChannel,
  addChannel,
  updateChannel,
  joinChannel,
  leaveChannel,
  inviteChannel,
  getUsers,
  getUser,
  updateProfile,
  getMessages,
  sendMessage,
  deleteMessage,
  editMessage,
  pinMessage,
  unpinMessage,
  reactMessage,
  unreactMessage,
} from './service';

const app = express();

app.use(cors());
app.use(express.urlencoded({ extended: true, }));
app.use(express.json({ limit: '50mb', }));
app.use(morgan(':method :url :status'));

const catchErrors = fn => async (req, res) => {
  try {
    console.log(`Authorization header is ${req.header('Authorization')}`);
    if (req.method === 'GET') {
      console.log(`Query params are ${JSON.stringify(req.params)}`);
    } else {
      console.log(`Body params are ${JSON.stringify(req.body)}`);
    }
    await fn(req, res);
    save();
  } catch (err) {
    if (err instanceof InputError) {
      res.status(400).send({ error: err.message, });
    } else if (err instanceof AccessError) {
      res.status(403).send({ error: err.message, });
    } else {
      console.log(err);
      res.status(500).send({ error: 'A system error ocurred', });
    }
  }
};

/***************************************************************
                         Auth Functions
***************************************************************/

const authed = fn => async (req, res) => {
  const userId = getUserIdFromAuthorization(req.header('Authorization'));
  await fn(req, res, userId);
};

app.post('/auth/login', catchErrors(async (req, res) => {
  const { email, password, } = req.body;
  return res.json(await login(email, password));
}));

app.post('/auth/register', catchErrors(async (req, res) => {
  const { email, password, name, } = req.body;
  return res.json(await register(email, password, name));
}));

app.post('/auth/logout', catchErrors(authed(async (req, res, authUserId) => {
  await logout(authUserId);
  return res.json({});
})));

/***************************************************************
                        Channel Functions
***************************************************************/

app.get('/channel', catchErrors(authed(async (req, res, authUserId) => {
  return res.json({ channels: await getChannels(), });
})));

app.get('/channel/:channelId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  await assertValidChannel(channelId);
  return res.json(await getChannel(authUserId, channelId));
})));

app.post('/channel', catchErrors(authed(async (req, res, authUserId) => {
  const { name, _, description, } = req.body;
  return res.json({
    channelId: await addChannel(authUserId, name, req.body.private, description),
  });
})));

app.put('/channel/:channelId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  const { name, description, } = req.body;
  await assertValidChannel(channelId);
  await updateChannel(authUserId, channelId, name, description);
  return res.status(200).send({});
})));

app.post('/channel/:channelId/join', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  await assertValidChannel(channelId);
  await joinChannel(authUserId, channelId);
  return res.status(200).send({});
})));

app.post('/channel/:channelId/leave', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  await assertValidChannel(channelId);
  await leaveChannel(authUserId, channelId);
  return res.status(200).send({});
})));

app.post('/channel/:channelId/invite', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  const { userId, } = req.body;
  await assertValidChannel(channelId);
  await assertValidUserId(userId.toString());
  await inviteChannel(authUserId, channelId, userId);
  return res.status(200).send({});
})));

/***************************************************************
                         User Functions
***************************************************************/

app.get('/user', catchErrors(authed(async (req, res, authUserId) => {
  return res.json({ users: await getUsers(), });
})));

app.get('/user/:userId', catchErrors(authed(async (req, res, authUserId) => {
  const { userId, } = req.params;
  await assertValidUserId(userId);
  return res.json(await getUser(userId));
})));

app.put('/user', catchErrors(authed(async (req, res, authUserId) => {
  const { email, password, name, bio, image, } = req.body;
  await updateProfile(authUserId, email, password, name, bio, image);
  return res.status(200).send({});
})));

/***************************************************************
                        Message Functions
***************************************************************/

app.get('/message/:channelId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  const { start, } = req.query;
  await assertValidChannel(channelId);
  return res.json({ messages: await getMessages(authUserId, channelId, parseInt(start, 10)), });
})));

app.post('/message/:channelId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, } = req.params;
  const { message, image, } = req.body;
  await assertValidChannel(channelId);
  await sendMessage(authUserId, channelId, message, image);
  return res.status(200).send({});
})));

app.put('/message/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  const { message, image, } = req.body;
  await assertValidChannel(channelId);
  await editMessage(authUserId, channelId, messageId, message, image);
  return res.status(200).send({});
})));

app.delete('/message/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  await assertValidChannel(channelId);
  await deleteMessage(authUserId, channelId, messageId);
  return res.status(200).send({});
})));

app.post('/message/pin/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  await assertValidChannel(channelId);
  await pinMessage(authUserId, channelId, messageId);
  return res.status(200).send({});
})));

app.post('/message/unpin/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  await assertValidChannel(channelId);
  await unpinMessage(authUserId, channelId, messageId);
  return res.status(200).send({});
})));

app.post('/message/react/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  const { react, } = req.body;
  await assertValidChannel(channelId);
  await reactMessage(authUserId, channelId, messageId, react);
  return res.status(200).send({});
})));

app.post('/message/unreact/:channelId/:messageId', catchErrors(authed(async (req, res, authUserId) => {
  const { channelId, messageId, } = req.params;
  const { react, } = req.body;
  await assertValidChannel(channelId);
  await unreactMessage(authUserId, channelId, messageId, react);
  return res.status(200).send({});
})));

/***************************************************************
                       Running Server
***************************************************************/

app.get('/', (req, res) => res.redirect('/docs'));

app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

const port = BACKEND_PORT || 5000;

const server = app.listen(port, () => {
  console.log(`Backend is now listening on port ${port}!`);
  console.log(`For API docs, navigate to http://localhost:${port}`);
});

export default server;
