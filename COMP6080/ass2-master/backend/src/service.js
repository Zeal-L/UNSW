import fs from 'fs';
import jwt from 'jsonwebtoken';
import AsyncLock from 'async-lock';
import { InputError, AccessError, } from './error';

const lock = new AsyncLock();

const JWT_SECRET = 'emilywashere';
const DATABASE_FILE = './database.json';

/***************************************************************
                       State Management
***************************************************************/

let users = {};
let channels = {};
let nextMessageId = 1;

const update = (users, channels, nextMessageId) =>
  new Promise((resolve, reject) => {
    lock.acquire('saveData', () => {
      try {
        fs.writeFileSync(DATABASE_FILE, JSON.stringify({
          users,
          channels,
          nextMessageId,
        }, null, 2));
        resolve();
      } catch {
        reject(new Error('Writing to database failed'));
      }
    });
  });

export const save = () => update(users, channels, nextMessageId);
export const reset = () => {
  update({}, {}, 1);
  users = {};
  channels = {};
  nextMessageId = 1;
};

try {
  const data = JSON.parse(fs.readFileSync(DATABASE_FILE));
  users = data.users;
  channels = data.channels;
  nextMessageId = data.nextMessageId;
} catch {
  console.log('WARNING: No database found, create a new one');
  save();
}

/***************************************************************
                        Helper Functions
***************************************************************/

const newUserId = _ => generateId(Object.keys(users), 99999);
const newChannelId = _ => generateId(Object.keys(channels));
const getNextMessageId = _ => {
  nextMessageId += 1;
  return nextMessageId - 1;
};

const userLock = callback => new Promise((resolve, reject) => {
  lock.acquire('userAuthLock', callback(resolve, reject));
});

const channelLock = callback => new Promise((resolve, reject) => {
  lock.acquire('channelMutateLock', callback(resolve, reject));
});

const randNum = max => Math.round(Math.random() * (max - Math.floor(max / 10)) + Math.floor(max / 10));
const generateId = (currentList, max = 999999) => {
  let R = randNum(max).toString();
  while (currentList.includes(R)) {
    R = randNum(max).toString();
  }
  return R;
};

export const assertValidUserId = (userId) => userLock((resolve, reject) => {
  if (!(userId in users)) {
    return reject(new InputError('Invalid user ID'));
  }
  resolve();
});

/***************************************************************
                         Auth Functions
***************************************************************/

export const getUserIdFromAuthorization = authorization => {
  try {
    const token = authorization.replace('Bearer ', '');
    const { userId, } = jwt.verify(token, JWT_SECRET);
    if (!(userId in users)) {
      throw new AccessError('Invalid token');
    }
    return userId.toString();
  } catch {
    throw new AccessError('Invalid token');
  }
};

const getUserIdFromEmail = email => {
  return Object.keys(users).find(id => users[id].email === email);
};

export const login = (email, password) => userLock((resolve, reject) => {
  const userId = getUserIdFromEmail(email);
  if (userId !== undefined && users[userId].password === password) {
    users[userId].sessionActive = true;
    resolve({
      token: jwt.sign({ userId, }, JWT_SECRET, { algorithm: 'HS256', }),
      userId: parseInt(userId, 10),
    });
  }
  reject(new InputError('Invalid email or password'));
});

export const logout = (authUserId) => userLock((resolve, reject) => {
  users[authUserId].sessionActive = false;
  resolve();
});

export const register = (email, password, name) => userLock((resolve, reject) => {
  if (getUserIdFromEmail(email) !== undefined) {
    return reject(new InputError('Email address already registered'));
  }
  const userId = newUserId();
  users[userId] = {
    email,
    name,
    password,
    bio: null,
    image: null,
    sessionActive: true,
  };
  resolve({
    token: jwt.sign({ userId, }, JWT_SECRET, { algorithm: 'HS256', }),
    userId: parseInt(userId, 10),
  });
});

/***************************************************************
                       Channel Functions
***************************************************************/

// creator and members array is user ids
const newChannelPayload = (name, creator, priv, description) => ({
  name,
  creator: parseInt(creator, 10),
  private: priv,
  description,
  createdAt: new Date().toISOString(),
  members: [parseInt(creator, 10)], // eslint-disable-line
  messages: [],
});

export const assertValidChannel = (channelId) => channelLock((resolve, reject) => {
  if (!(channelId in channels)) {
    return reject(new InputError('Invalid channel ID'));
  }
  resolve();
});

const isChannelMember = (userId, channelId) => {
  return channels[channelId].members.includes(parseInt(userId, 10));
};

const assertChannelMember = (userId, channelId) => {
  if (!isChannelMember(userId, channelId)) {
    throw new AccessError('Authorised user is not a member of this channel');
  };
};

// includes private channels user is not a member of
// when marking, can use a starter db that already has private channels so tutors don't need two accounts
// Returns the basic details of each channel
export const getChannels = () => channelLock((resolve, reject) => {
  resolve(Object.keys(channels).map(key => ({
    id: parseInt(key, 10),
    name: channels[key].name,
    creator: channels[key].creator,
    private: channels[key].private,
    members: channels[key].members,
  })));
});

export const getChannel = (authUserId, channelId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  const channelDetails = { ...channels[channelId], };
  delete channelDetails.messages;
  resolve(channelDetails);
});

export const addChannel = (authUserId, name, priv, description) => channelLock((resolve, reject) => {
  if (name === undefined) {
    return reject(new InputError('Must provide a name for new channel'));
  } else if (priv === undefined) {
    return reject(new InputError('Channel must have a privacy setting'));
  } else if (description === undefined) {
    return reject(new InputError('Must provide a description'));
  }
  const channelId = newChannelId();
  channels[channelId] = newChannelPayload(name, authUserId, priv, description);
  resolve(channelId);
});

export const updateChannel = (authUserId, channelId, name, description) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  if (name) { channels[channelId].name = name; }
  if (description) { channels[channelId].description = description; }
  resolve();
});

export const joinChannel = (authUserId, channelId) => channelLock((resolve, reject) => {
  if (isChannelMember(authUserId, channelId)) {
    return reject(new InputError('User is already a member of this channel'));
  } else if (channels[channelId].private) {
    return reject(new AccessError('You cannot join a private channel'));
  }
  channels[channelId].members.push(parseInt(authUserId, 10));
  resolve();
});

export const leaveChannel = (authUserId, channelId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  const index = channels[channelId].members.indexOf(parseInt(authUserId, 10));
  channels[channelId].members.splice(index, 1);
  resolve();
});

// userId is an integer
export const inviteChannel = (authUserId, channelId, userId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  if (isChannelMember(userId.toString(), channelId)) {
    return reject(new InputError('User is already a member of this channel'));
  }
  channels[channelId].members.push(userId);
  resolve();
});

/***************************************************************
                         User Functions
***************************************************************/

export const getUsers = () => userLock((resolve, reject) => {
  resolve(Object.keys(users).map(key => ({
    id: parseInt(key, 10),
    email: users[key].email,
  })));
});

export const getUser = (userId) => userLock((resolve, reject) => {
  const userDetails = { ...users[userId], };
  delete userDetails.password;
  delete userDetails.sessionActive;
  resolve(userDetails);
});

export const updateProfile = (authUserId, email, password, name, bio, image) => userLock((resolve, reject) => {
  if (name) { users[authUserId].name = name; }
  if (password) { users[authUserId].password = password; }
  if (bio) { users[authUserId].bio = bio; }
  if (image) { users[authUserId].image = image; }
  if (email && getUserIdFromEmail(email) !== undefined) {
    return reject(new InputError('Email address already taken'));
  } else if (email) { users[authUserId].email = email; }
  resolve();
});

/***************************************************************
                        Message Functions
***************************************************************/

const findMsgIdxInChannel = (chId, mId) => {
  const index = channels[chId].messages.findIndex(m => m.id === parseInt(mId, 10));
  if (index === -1) {
    throw new InputError('No message with this message ID exists in this channel');
  }
  return index;
};

const isInvalidMessage = (m) => {
  return typeof m !== 'string' && m !== undefined;
};

// start is an int
export const getMessages = (authUserId, channelId, start) => channelLock((resolve, reject) => {
  if (Number.isNaN(start)) {
    return reject(new InputError('Invalid start value'));
  } else if (start < 0) {
    return reject(new InputError('Start value cannot be negative'));
  }
  assertChannelMember(authUserId, channelId);
  resolve(channels[channelId].messages.slice(start, start + 25));
});

export const sendMessage = (authUserId, channelId, message, image) => channelLock((resolve, reject) => {
  if ((isInvalidMessage(message) || isInvalidMessage(image)) || (message === undefined && image === undefined)) {
    return reject(new InputError('Invalid message or image'));
  }
  assertChannelMember(authUserId, channelId);
  channels[channelId].messages.unshift({
    id: getNextMessageId(),
    message,
    image,
    sender: parseInt(authUserId, 10),
    sentAt: new Date().toISOString(),
    edited: false,
    editedAt: null,
    pinned: false,
    reacts: [],
  });
  resolve();
});

export const deleteMessage = (authUserId, channelId, messageId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  if (channels[channelId].messages[messageIndex].sender !== parseInt(authUserId, 10)) {
    return reject(new AccessError('You can\'t delete a message you didn\'t send'));
  }
  channels[channelId].messages.splice(messageIndex, 1);
  resolve();
});

export const editMessage = (authUserId, channelId, messageId, newMessage, newImage) => channelLock((resolve, reject) => {
  if ((isInvalidMessage(newMessage) || isInvalidMessage(newImage)) || (newMessage === undefined && newImage === undefined)) {
    return reject(new InputError('Invalid message or image'));
  }
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  if (channels[channelId].messages[messageIndex].sender !== parseInt(authUserId, 10)) {
    return reject(new AccessError('You can\'t edit a message you didn\'t send'));
  }
  channels[channelId].messages[messageIndex].message = newMessage;
  channels[channelId].messages[messageIndex].image = newImage;
  channels[channelId].messages[messageIndex].edited = true;
  channels[channelId].messages[messageIndex].editedAt = new Date().toISOString();
  resolve();
});

export const pinMessage = (authUserId, channelId, messageId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  if (channels[channelId].messages[messageIndex].pinned) {
    return reject(new InputError('This message is already pinned'));
  }
  channels[channelId].messages[messageIndex].pinned = true;
  resolve();
});

export const unpinMessage = (authUserId, channelId, messageId) => channelLock((resolve, reject) => {
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  if (!channels[channelId].messages[messageIndex].pinned) {
    return reject(new InputError('This message is not pinned'));
  }
  channels[channelId].messages[messageIndex].pinned = false;
  resolve();
});

export const reactMessage = (authUserId, channelId, messageId, react) => channelLock((resolve, reject) => {
  if (react === undefined) {
    return reject(new InputError('No react value provided'));
  }
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  if (channels[channelId].messages[messageIndex].reacts.findIndex(
    r => r.user === parseInt(authUserId, 10) && r.react === react
  ) !== -1) {
    return reject(new InputError('This message already contains a react of this type from this user'));
  }
  channels[channelId].messages[messageIndex].reacts.push({
    user: parseInt(authUserId, 10),
    react,
  });
  resolve();
});

export const unreactMessage = (authUserId, channelId, messageId, react) => channelLock((resolve, reject) => {
  if (react === undefined) {
    return reject(new InputError('No react value provided'));
  }
  assertChannelMember(authUserId, channelId);
  const messageIndex = findMsgIdxInChannel(channelId, messageId);
  const reactIndex = channels[channelId].messages[messageIndex].reacts.findIndex(
    r => r.user === parseInt(authUserId, 10) && r.react === react
  );
  if (reactIndex === -1) {
    return reject(new InputError('This message does not contain a react of this type from this user'));
  }
  channels[channelId].messages[messageIndex].reacts.splice(reactIndex, 1);
  resolve();
});
