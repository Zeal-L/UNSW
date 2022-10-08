import request from 'supertest';
import server from '../src/server';
import { reset } from '../src/service';

const IMAGE = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAUAAAAFCAYAAACNbyblAAAAHElEQVQI12P4//8/w38GIAXDIBKE0DHxgljNBAAO9TXL0Y4OHwAAAABJRU5ErkJggg==';

const INVALID_TOKEN = 'Emily';

const USER1 = {
  name: 'Betty',
  email: 'betty@email.com',
  password: 'cardigan',
  bio: 'when you are young they assume you know nothing',
};
const USER2 = {
  name: 'Augustine',
  email: 'augustine@email.com',
  password: 'august',
  bio: 'i can see us lost in the memory, august slipped away into a moment in time',
};
const USER3 = {
  name: 'James',
  email: 'james@email.com',
  password: 'betty',
  bio: 'if i just showed up at your party, would you have me?',
};
const CHANNEL_PUBLIC = {
  name: 'Inez\'s public rumour forum',
  name2: 'Inez\'s public rumour forum!',
  description: 'you heard the rumours from Inez, you can\'t believe a word she says',
  description2: 'moo',
  private: false,
};
const CHANNEL_PRIVATE = {
  name: 'Inez\'s private rumour mill',
  name2: 'Inez\'s private rumour mill!',
  description: 'you can\'t believe a word she says most times, but this time it was true',
  description2: 'baa',
  private: true,
};

const postTry = async (path, status, payload, token) => sendTry('post', path, status, payload, token);
const getTry = async (path, status, payload, token) => sendTry('get', path, status, payload, token);
const deleteTry = async (path, status, payload, token) => sendTry('delete', path, status, payload, token);
const putTry = async (path, status, payload, token) => sendTry('put', path, status, payload, token);

const sendTry = async (typeFn, path, status = 200, payload = {}, token = null) => {
  let req = request(server);
  if (typeFn === 'post') {
    req = req.post(path);
  } else if (typeFn === 'get') {
    req = req.get(path);
  } else if (typeFn === 'delete') {
    req = req.delete(path);
  } else if (typeFn === 'put') {
    req = req.put(path);
  }
  if (token !== null) {
    req = req.set('Authorization', `Bearer ${token}`);
  }
  const response = await req.send(payload);
  expect(response.statusCode).toBe(status);
  return response.body;
};

const validToken = async (user) => {
  const { token } = await postTry('/auth/login', 200, {
    email: user.email,
    password: user.password,
  });
  return token;
}

const publicChannelId = async () => {
  const { channels } = await getTry('/channel', 200, {}, await validToken(USER1));
  return channels[0].private ? channels[1].id : channels[0].id;
};

const privateChannelId = async () => {
  const { channels } = await getTry('/channel', 200, {}, await validToken(USER1));
  return channels[0].private ? channels[0].id : channels[1].id;
};

const getUserId = async (user) => {
  const { users, } = await getTry('/user', 200, {}, await validToken(USER1));
  return users.find(u => u.email === user.email).id;
}

describe('Auth tests', () => {

  beforeAll(() => {
    reset();
  });

  beforeAll(() => {
    server.close();
  });

  test('Registration of initial user', async () => {
    const { token, userId, } = await postTry('/auth/register', 200, {
      email: USER1.email,
      password: USER1.password,
      name: USER1.name,
    });
    expect(token instanceof String);
    expect(userId).toBe(await getUserId(USER1));
  });

  test('Inability to re-register a user', async () => {
    await postTry('/auth/register', 400, {
      email: USER1.email,
      password: USER1.password,
      name: USER1.name,
    });
  });

  test('Registration of second user', async () => {
    const { token, } = await postTry('/auth/register', 200, {
      email: USER2.email,
      password: USER2.password,
      name: USER2.name,
    });
    expect(token instanceof String);
  });

  test('Login to an existing user', async () => {
    const { token, userId, } = await postTry('/auth/login', 200, {
      email: USER1.email,
      password: USER1.password,
    });
    expect(token instanceof String);
    expect(userId).toBe(await getUserId(USER1));
  });

  test('Login attempt with invalid credentials 1', async () => {
    await postTry('/auth/login', 400, {
      email: 'inez@email.com',
      password: USER1.password,
    });
  });

  test('Login attempt with invalid credentials 2', async () => {
    await postTry('/auth/login', 400, {
      email: USER1.email,
      password: 'car again',
    });
  });

  test('Logout a valid session', async () => {
    const body = await postTry('/auth/logout', 200, {}, await validToken(USER1));
    expect(body).toMatchObject({});
  });

  test('Logout a session without auth token', async () => {
    const body = await postTry('/auth/logout', 403, {});
    expect(body).toMatchObject({});
  });

});

describe('Channel tests', () => {

  beforeAll(async () => {
    reset();

    await postTry('/auth/register', 200, {
      email: USER1.email,
      password: USER1.password,
      name: USER1.name,
    });

    await postTry('/auth/register', 200, {
      email: USER2.email,
      password: USER2.password,
      name: USER2.name,
    });

    await postTry('/auth/register', 200, {
      email: USER3.email,
      password: USER3.password,
      name: USER3.name,
    });
  });

  beforeAll(() => {
    server.close();
  });

  test('Viewing channels, invalid token', async () => {
    await getTry('/channel', 403, {}, INVALID_TOKEN);
  });

  test('Initially there are no channels', async () => {
    const { channels, } = await getTry('/channel', 200, {}, await validToken(USER1));
    expect(channels).toHaveLength(0);
  });

  test('Creating a single channel, token missing', async () => {
    await postTry('/channel', 403, {
      name: CHANNEL_PUBLIC.name,
      private: CHANNEL_PUBLIC.private,
      description: CHANNEL_PUBLIC.description,
    });
  });

  test('Creating a single channel, invalid token', async () => {
    await postTry('/channel', 403, {
      name: CHANNEL_PUBLIC.name,
      private: CHANNEL_PUBLIC.private,
      description: CHANNEL_PUBLIC.description,
    }, INVALID_TOKEN);
  });

  test('Creating a single channel, all values missing', async () => {
    await postTry('/channel', 400, {}, await validToken(USER1));
  });

  test('Creating a single channel, name missing', async () => {
    await postTry('/channel', 400, {
      private: CHANNEL_PUBLIC.private,
      description: CHANNEL_PUBLIC.description,
    }, await validToken(USER1));
  });

  test('Creating a single channel, public setting missing', async () => {
    await postTry('/channel', 400, {
      name: CHANNEL_PUBLIC.name,
      description: CHANNEL_PUBLIC.description,
    }, await validToken(USER1));
  });

  test('Creating a single channel, description missing', async () => {
    await postTry('/channel', 400, {
      name: CHANNEL_PUBLIC.name,
      private: CHANNEL_PUBLIC.private,
    }, await validToken(USER1));
  });

  test('Creating a single public channel', async () => {
    await postTry('/channel', 200, {
      name: CHANNEL_PUBLIC.name,
      private: CHANNEL_PUBLIC.private,
      description: CHANNEL_PUBLIC.description,
    }, await validToken(USER1));
  });

  test('That there is now one channel', async () => {
    const { channels, } = await getTry('/channel', 200, {}, await validToken(USER1));
    expect(channels).toHaveLength(1);
    expect(typeof channels[0].id).toBe('number');
    expect(channels[0].name).toBe(CHANNEL_PUBLIC.name);
    expect(typeof channels[0].creator).toBe('number');
    expect(channels[0].private).toBe(CHANNEL_PUBLIC.private);
    expect(channels[0].members).toMatchObject([channels[0].creator]);
  });

  test('That the one channel\'s details can be viewed', async () => {
    const channelId = await publicChannelId();
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER1));
    expect(channel.name).toBe(CHANNEL_PUBLIC.name);
    expect(typeof channel.creator).toBe('number');
    expect(channel.private).toBe(CHANNEL_PUBLIC.private);
    expect(channel.description).toBe(CHANNEL_PUBLIC.description);
    expect(typeof channel.createdAt).toBe('string');
    expect(channel.members).toMatchObject([channel.creator]);
  });

  test('Viewing one channel\'s details, invalid token', async () => {
    const channelId = await publicChannelId();
    await getTry(`/channel/${channelId}`, 403, {}, INVALID_TOKEN);
  });

  test('Viewing one channel\'s details, invalid channelId', async () => {
    await getTry('/channel/999999999', 400, {}, await validToken(USER1));
  });

  test('Viewing one channel\'s details, user not a member', async () => {
    const channelId = await publicChannelId();
    await getTry(`/channel/${channelId}`, 403, {}, await validToken(USER2));
  });

  test('Create a second private channel', async () => {
    await postTry('/channel', 200, {
      name: CHANNEL_PRIVATE.name,
      private: CHANNEL_PRIVATE.private,
      description: CHANNEL_PRIVATE.description,
    }, await validToken(USER1));
  });

  test('That there are now two channels', async () => {
    const { channels, } = await getTry('/channel', 200, {}, await validToken(USER1));
    expect(channels).toHaveLength(2);
    expect(channels[0].id !== channels[1].id)
  });

  test('First user can\'t join invalid channel', async () => {
    await postTry('/channel/999999999/join', 400, {}, await validToken(USER1));
  });

  test('First user can\'t join channels they\'re already in', async () => {
    const channelIdPublic = await publicChannelId();
    const channelIdPrivate = await privateChannelId();
    await postTry(`/channel/${channelIdPublic}/join`, 400, {}, await validToken(USER1));
    await postTry(`/channel/${channelIdPrivate}/join`, 400, {}, await validToken(USER1));
  });

  test('Second user can join public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
  });

  test('Second user can now view channel details', async () => {
    const channelId = await publicChannelId();
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER2));
    expect(channel.name).toBe(CHANNEL_PUBLIC.name);
    expect(typeof channel.creator).toBe('number');
    expect(channel.private).toBe(CHANNEL_PUBLIC.private);
    expect(channel.description).toBe(CHANNEL_PUBLIC.description);
    expect(typeof channel.createdAt).toBe('string');
    expect(channel.members).toHaveLength(2);
  });

  test('Second user can\'t join private channel', async () => {
    const channelId = await privateChannelId();
    await postTry(`/channel/${channelId}/join`, 403, {}, await validToken(USER2));
  });

  test('Invalid token can\'t join public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 403, {}, INVALID_TOKEN);
  });

  test('Invalid token can\'t join private channel', async () => {
    const channelId = await privateChannelId();
    await postTry(`/channel/${channelId}/join`, 403, {}, INVALID_TOKEN);
  });

  test('Second user can leave public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 200, {}, await validToken(USER2));
  });

  test('Second user can\'t leave channel they aren\'t in', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 403, {}, await validToken(USER2));
  });

  test('Invalid token can\'t leave channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 403, {}, INVALID_TOKEN);
  });

  test('First user can\'t leave invalid channel', async () => {
    await postTry('/channel/999999999/leave', 400, {}, await validToken(USER1));
  });

  test('Second user can\'t update channel they aren\'t in', async () => {
    const channelId = await publicChannelId();
    await putTry(`/channel/${channelId}`, 403, {}, await validToken(USER2));
  });

  test('Invalid token can\'t update channel', async () => {
    const channelId = await publicChannelId();
    await putTry(`/channel/${channelId}`, 403, {}, INVALID_TOKEN);
  });

  test('First user can\'t update invalid channel', async () => {
    await putTry('/channel/999999999', 400, {}, await validToken(USER1));
  });

  test('Can update channel details with nothing new', async () => {
    const channelId = await publicChannelId();
    await putTry(`/channel/${channelId}`, 200, {}, await validToken(USER1));
  });

  test('First user can update public channel details', async () => {
    const channelId = await publicChannelId();
    await putTry(`/channel/${channelId}`, 200, {
      name: CHANNEL_PUBLIC.name2,
      description: CHANNEL_PUBLIC.description2,
    }, await validToken(USER1));
  });

  test('Updates were applied', async () => {
    const channelId = await publicChannelId();
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER1));
    expect(channel.name).toBe(CHANNEL_PUBLIC.name2);
    expect(typeof channel.creator).toBe('number');
    expect(channel.private).toBe(CHANNEL_PUBLIC.private);
    expect(channel.description).toBe(CHANNEL_PUBLIC.description2);
    expect(typeof channel.createdAt).toBe('string');
    expect(channel.members).toMatchObject([channel.creator]);
  });

  test('First user can update private channel details', async () => {
    const channelId = await privateChannelId();
    await putTry(`/channel/${channelId}`, 200, {
      name: CHANNEL_PRIVATE.name2,
      description: CHANNEL_PRIVATE.description2,
    }, await validToken(USER1));
  });

  test('Updates were applied #2', async () => {
    const channelId = await privateChannelId();
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER1));
    expect(channel.name).toBe(CHANNEL_PRIVATE.name2);
    expect(typeof channel.creator).toBe('number');
    expect(channel.private).toBe(CHANNEL_PRIVATE.private);
    expect(channel.description).toBe(CHANNEL_PRIVATE.description2);
    expect(typeof channel.createdAt).toBe('string');
    expect(channel.members).toMatchObject([channel.creator]);
  });

  test('Invalid user can\'t invite user to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 403, {
      userId: await getUserId(USER3),
    }, INVALID_TOKEN);
  });

  test('User can\'t invite invalid user to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 400, {
      userId: 999999999,
    }, await validToken(USER1));
  });

  test('User can\'t invite other user to invalid channel', async () => {
    await postTry('/channel/999999999/invite', 400, {
      userId: await getUserId(USER2),
    }, await validToken(USER1));
  });

  test('Non-member can\'t invite user to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 403, {
      userId: await getUserId(USER3),
    }, await validToken(USER2));
  });

  test('Non-member can\'t invite self to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 403, {
      userId: await getUserId(USER3),
    }, await validToken(USER3));
  });

  test('Creator can invite second user to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 200, {
      userId: await getUserId(USER2),
    }, await validToken(USER1));
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER2));
    expect(channel.members).toHaveLength(2);
  });

  test('Can\'t invite user who is already a member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 400, {
      userId: await getUserId(USER2),
    }, await validToken(USER1));
  });

  test('Second user (member) can invite third user to public channel', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/invite`, 200, {
      userId: await getUserId(USER3),
    }, await validToken(USER2));
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER3));
    expect(channel.members).toHaveLength(3);
  });

  test('Creator can invite second user to private channel', async () => {
    const channelId = await privateChannelId();
    await postTry(`/channel/${channelId}/invite`, 200, {
      userId: await getUserId(USER2),
    }, await validToken(USER1));
    const channel = await getTry(`/channel/${channelId}`, 200, {}, await validToken(USER2));
    expect(channel.members).toHaveLength(2);
  });
});

describe('User tests', () => {

  beforeAll(async () => {
    reset();

    await postTry('/auth/register', 200, {
      email: USER1.email,
      password: USER1.password,
      name: USER1.name,
    });

    await postTry('/auth/register', 200, {
      email: USER2.email,
      password: USER2.password,
      name: USER2.name,
    });
  });

  beforeAll(() => {
    server.close();
  });

  test('Viewing users, invalid token', async () => {
    await getTry('/user', 403, {}, INVALID_TOKEN);
  });

  test('Both users can view all users', async () => {
    let { users, } = await getTry('/user', 200, {}, await validToken(USER1));
    expect(users).toHaveLength(2);
    ({ users, } = await getTry('/user', 200, {}, await validToken(USER2)));
    expect(users).toHaveLength(2);
  });

  test('First user can view own profile', async () => {
    const profile = await getTry(`/user/${await getUserId(USER1)}`, 200, {}, await validToken(USER1));
    expect(profile.name).toBe(USER1.name);
    expect(profile.bio).toBe(null);
  });

  test('First user can view second user\'s profile', async () => {
    const profile = await getTry(`/user/${await getUserId(USER2)}`, 200, {}, await validToken(USER1));
    expect(profile.name).toBe(USER2.name);
    expect(profile.bio).toBe(null);
  });

  test('Second user can view first user\'s profile', async () => {
    const profile = await getTry(`/user/${await getUserId(USER1)}`, 200, {}, await validToken(USER2));
    expect(profile.name).toBe(USER1.name);
    expect(profile.bio).toBe(null);
  });

  test('Invalid token can\'t view other user\'s profiles', async () => {
    await getTry(`/user/${await getUserId(USER1)}`, 403, {}, INVALID_TOKEN);
  });

  test('Can\'t view invalid user\'s profiles', async () => {
    await getTry('/user/99999999', 400, {}, await validToken(USER1));
  });

  test('First user can update own profile', async () => {
    await putTry('/user', 200, {
      bio: USER1.bio,
      image: IMAGE,
    }, await validToken(USER1));
  });

  test('Updates applied', async () => {
    const profile = await getTry(`/user/${await getUserId(USER1)}`, 200, {}, await validToken(USER1));
    expect(profile.name).toBe(USER1.name);
    expect(profile.bio).toBe(USER1.bio);
    expect(profile.image).toBe(IMAGE);
  });

  test('Invalid user can\'t update own profile', async () => {
    await putTry('/user', 403, {
      bio: USER1.bio,
    }, INVALID_TOKEN);
  });

  test('Can\'t reuse email', async () => {
    await putTry('/user', 400, {
      email: USER2.email,
    }, await validToken(USER1));
  });

  test('Can update nothing', async () => {
    await putTry('/user', 200, {}, await validToken(USER1));
  });

  test('Can change everything in profile', async () => {
    await putTry('/user', 200, {
      email: USER3.email,
      password: USER3.password,
      name: USER3.name,
      bio: USER3.bio,
    }, await validToken(USER2));
  });

  test('Updates applied', async () => {
    const profile = await getTry(`/user/${await getUserId(USER3)}`, 200, {}, await validToken(USER1));
    expect(profile.name).toBe(USER3.name);
    expect(profile.bio).toBe(USER3.bio);
  });

  test('Check if can log in with new credentials and revert profile', async () => {
    await putTry('/user', 200, {
      email: USER2.email,
      password: USER2.password,
      name: USER2.name,
      bio: USER2.bio,
    }, await validToken(USER3));
  });

  test('Updating with used email won\'t work but other fields will still update', async () => {
    await putTry('/user', 400, {
      email: USER1.email,
      name: USER3.name,
      bio: USER3.bio,
    }, await validToken(USER2));
    const profile = await getTry(`/user/${await getUserId(USER2)}`, 200, {}, await validToken(USER1));
    expect(profile.email).toBe(USER2.email);
    expect(profile.name).toBe(USER3.name);
    expect(profile.bio).toBe(USER3.bio);
  });

});

describe('Message tests', () => {

  beforeAll(async () => {
    reset();

    await postTry('/auth/register', 200, {
      email: USER1.email,
      password: USER1.password,
      name: USER1.name,
    });

    await postTry('/auth/register', 200, {
      email: USER2.email,
      password: USER2.password,
      name: USER2.name,
    });

    await postTry('/channel', 200, {
      name: CHANNEL_PUBLIC.name,
      private: CHANNEL_PUBLIC.private,
      description: CHANNEL_PUBLIC.description,
    }, await validToken(USER1));

    await postTry('/channel', 200, {
      name: CHANNEL_PRIVATE.name,
      private: CHANNEL_PRIVATE.private,
      description: CHANNEL_PRIVATE.description,
    }, await validToken(USER1));
  });

  beforeAll(() => {
    server.close();
  });

  test('Viewing messages, invalid token', async () => {
    const channelId = await publicChannelId();
    await getTry(`/message/${channelId}?start=0`, 403, {}, INVALID_TOKEN);
  });

  test('Viewing messages, invalid channel ID', async () => {
    await getTry('/message/999999999?start=0', 400, {}, await validToken(USER1));
  });

  test('Viewing public messages, not member', async () => {
    const channelId = await publicChannelId();
    await getTry(`/message/${channelId}?start=0`, 403, {}, await validToken(USER2));
  });

  test('Viewing private messages, not member', async () => {
    const channelId = await privateChannelId();
    await getTry(`/message/${channelId}?start=0`, 403, {}, await validToken(USER2));
  });

  test('Viewing public messages, no start value', async () => {
    const channelId = await publicChannelId();
    await getTry(`/message/${channelId}`, 400, {}, await validToken(USER2));
  });

  test('Viewing public messages, negative start value', async () => {
    const channelId = await publicChannelId();
    await getTry(`/message/${channelId}?start=-2`, 400, {}, await validToken(USER2));
  });

  test('Viewing public messages, should succeed but have no messages', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages).toHaveLength(0);
  });

  test('Sending message, invalid token', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 403, {
      message: 'message',
      image: IMAGE,
    }, INVALID_TOKEN);
  });

  test('Sending message, invalid channel ID', async () => {
    await postTry('/message/999999999', 400, {
      message: 'message',
      image: IMAGE,
    }, await validToken(USER1));
  });

  test('Sending public message, not member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 403, {
      message: 'message',
      image: IMAGE,
    }, await validToken(USER2));
  });

  test('Sending private message, not member', async () => {
    const channelId = await privateChannelId();
    await postTry(`/message/${channelId}`, 403, {
      message: 'message',
      image: IMAGE,
    }, await validToken(USER2));
  });

  test('Sending message, no message or image', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 400, {}, await validToken(USER1));
  });

  test('Sending messages, messages or images not strings', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 400, {
      message: 123,
      image: IMAGE,
    }, await validToken(USER1));

    await postTry(`/message/${channelId}`, 400, {
      message: 'if i can\'t have love i want power',
      image: true,
    }, await validToken(USER1));
  });

  test('Sending message', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 200, {
      message: 'message1',
    }, await validToken(USER1));
  });

  test('Viewing messages, there should be one message', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages).toHaveLength(1);
    expect(typeof messages[0].id).toBe('number');
    expect(messages[0].message).toBe('message1');
    expect(messages[0].image).toBe(undefined);
    expect(messages[0].sender).toBe(await getUserId(USER1));
    expect(typeof messages[0].sentAt).toBe('string');
    expect(messages[0].edited).toBe(false);
    expect(messages[0].editedAt).toBe(null);
    expect(messages[0].pinned).toBe(false);
    expect(messages[0].reacts).toMatchObject([]);
  });

  test('Viewing messages with start value 1, should be empty', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=1`, 200, {}, await validToken(USER1));
    expect(messages).toHaveLength(0);
  });

  test('Sending 25 more messages', async () => {
    const channelId = await publicChannelId();
    for (let i = 2; i < 27; i += 1) {
      await postTry(`/message/${channelId}`, 200, {
        message: `message${i}`,
      }, await validToken(USER1));
    }
  });

  test('Viewing messages, there should be 25 message (pagination) in the correct order', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages).toHaveLength(25);
    expect(messages[0].message).toBe('message26');
    expect(messages[24].message).toBe('message2');
  });

  test('Viewing messages with start value 25', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=25`, 200, {}, await validToken(USER1));
    expect(messages).toHaveLength(1);
    expect(messages[0].message).toBe('message1');
  });

  test('Sending image', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/${channelId}`, 200, {
      image: IMAGE,
    }, await validToken(USER1));
  });

  test('Check if image was sent', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(typeof messages[0].id).toBe('number');
    expect(messages[0].message).toBe(undefined);
    expect(messages[0].image).toBe(IMAGE);
    expect(messages[0].sender).toBe(await getUserId(USER1));
    expect(typeof messages[0].sentAt).toBe('string');
    expect(messages[0].edited).toBe(false);
    expect(messages[0].editedAt).toBe(null);
    expect(messages[0].pinned).toBe(false);
    expect(messages[0].reacts).toMatchObject([]);
  });

  test('Deleting message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await deleteTry(`/message/${channelId}/${messages[0].id}`, 403, {}, INVALID_TOKEN);
  });

  test('Deleting message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await deleteTry(`/message/999999999/${messages[0].id}`, 400, {}, await validToken(USER1));
  });

  test('Deleting message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await deleteTry(`/message/${channelId}/999999999`, 400, {}, await validToken(USER1));
  });

  test('Deleting message, not channel member', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await deleteTry(`/message/${channelId}/${messages[0].id}`, 403, {}, await validToken(USER2));
  });

  test('Deleting message, not sender', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await deleteTry(`/message/${channelId}/${messages[0].id}`, 403, {}, await validToken(USER2));
  });

  test('Message hasn\'t been deleted', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].image).toBe(IMAGE);
  });

  test('Deleting message', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await deleteTry(`/message/${channelId}/${messages[0].id}`, 200, {}, await validToken(USER1));
  });

  test('Message has been deleted', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].image).toBe(undefined);
    expect(messages[0].message).toBe('message26');
  });

  test('Editing message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 403, {
      message: 'message26!',
    }, INVALID_TOKEN);
  });

  test('Editing message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/999999999/${messages[0].id}`, 400, {
      message: 'message26!',
    }, await validToken(USER1));
  });

  test('Editing message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await putTry(`/message/${channelId}/999999999`, 400, {
      message: 'message26!',
    }, await validToken(USER1));
  });

  test('Editing message, not channel member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 403, {
      message: 'message26!',
    }, await validToken(USER2));
  });

  test('Editing message, no new message given', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 400, {}, await validToken(USER1));
  });

  test('Editing message, not sender', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 403, {
      message: 'message26!',
    }, await validToken(USER2));
  });

  test('Message hasn\'t been edited', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].message).toBe('message26');
    expect(messages[0].edited).toBe(false);
  });

  test('Editing message', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 200, {
      message: 'message26!',
    }, await validToken(USER1));
  });

  test('Viewing messages, edit reflected', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].message).toBe('message26!');
    expect(messages[0].edited).toBe(true);
    expect(typeof messages[0].editedAt).toBe('string');
  });

  test('Editing message to image', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await putTry(`/message/${channelId}/${messages[0].id}`, 200, {
      image: IMAGE,
    }, await validToken(USER1));
  });

  test('Viewing messages, edit reflected #2', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].message).toBe(undefined);
    expect(messages[0].image).toBe(IMAGE);
    expect(messages[0].edited).toBe(true);
    expect(typeof messages[0].editedAt).toBe('string');
  });

  test('Pinning message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/${channelId}/${messages[1].id}`, 403, {}, INVALID_TOKEN);
  });

  test('Pinning message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/999999999/${messages[1].id}`, 400, {}, await validToken(USER1));
  });

  test('Pinning message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/pin/${channelId}/999999999`, 400, {}, await validToken(USER1));
  });

  test('Pinning message, not channel member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/${channelId}/${messages[1].id}`, 403, {}, await validToken(USER2));
  });

  test('Successful pin by sender', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/${channelId}/${messages[1].id}`, 200, {}, await validToken(USER1));
  });

  test('Viewing messages, pin reflected', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[1].pinned).toBe(true);
  });

  test('Pinning already pinned message', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/${channelId}/${messages[1].id}`, 400, {}, await validToken(USER1));
  });

  test('Successful pin by not-sender', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/pin/${channelId}/${messages[2].id}`, 200, {}, await validToken(USER2));
  });

  test('Viewing messages, pin reflected #2', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[2].pinned).toBe(true);
  });

  test('Unpinning message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unpin/${channelId}/${messages[1].id}`, 403, {}, INVALID_TOKEN);
  });

  test('Unpinning message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unpin/999999999/${messages[1].id}`, 400, {}, await validToken(USER1));
  });

  test('Unpinning message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/unpin/${channelId}/999999999`, 400, {}, await validToken(USER1));
  });

  test('Unpinning message, not channel member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unpin/${channelId}/${messages[1].id}`, 403, {}, await validToken(USER2));
  });

  test('Successful unpin by pinner', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unpin/${channelId}/${messages[1].id}`, 200, {}, await validToken(USER1));
  });

  test('Viewing messages, unpin reflected', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[1].pinned).toBe(false);
  });

  test('Unpinning unpinned message', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unpin/${channelId}/${messages[1].id}`, 400, {}, await validToken(USER1));
  });

  test('Reacting message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 403, {
      react: 1,
    }, INVALID_TOKEN);
  });

  test('Reacting message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/999999999/${messages[5].id}`, 400, {
      react: 1,
    }, await validToken(USER1));
  });

  test('Reacting message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/react/${channelId}/999999999`, 400, {
      react: 1,
    }, await validToken(USER1));
  });

  test('Reacting message, no react value', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 400, {}, await validToken(USER1));
  });

  test('Reacting message, not channel member', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 403, {
      react: 1,
    }, await validToken(USER2));
  });

  test('Reacting messages, various users/messages/types', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 200, {
      react: 1,
    }, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 200, {
      react: 2,
    }, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[6].id}`, 200, {
      react: 'sad',
    }, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 200, {
      react: 2,
    }, await validToken(USER2));
    await postTry(`/message/react/${channelId}/${messages[6].id}`, 200, {
      react: 'laugh',
    }, await validToken(USER2));
  });

  test('Viewing messages, reacts reflected', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].reacts).toHaveLength(0);
    expect(messages[5].reacts).toHaveLength(3);
    expect(messages[6].reacts).toHaveLength(2);
  });

  test('Can\'t react same users/messages/type twice', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/react/${channelId}/${messages[5].id}`, 400, {
      react: 1,
    }, await validToken(USER1));
  });

  test('Unreacting message, invalid token', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 403, {
      react: 1,
    }, INVALID_TOKEN);
  });

  test('Unreacting message, invalid channel id', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/999999999/${messages[5].id}`, 400, {
      react: 1,
    }, await validToken(USER1));
  });

  test('Unreacting message, invalid message id', async () => {
    const channelId = await publicChannelId();
    await postTry(`/message/unreact/${channelId}/999999999`, 400, {
      react: 1,
    }, await validToken(USER1));
  });

  test('Unreacting message, no react value', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 400, {}, await validToken(USER1));
  });

  test('Unreacting message, not channel member', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/leave`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 403, {
      react: 1,
    }, await validToken(USER2));
  });

  test('Unreacting messages, various users/messages/types', async () => {
    const channelId = await publicChannelId();
    await postTry(`/channel/${channelId}/join`, 200, {}, await validToken(USER2));
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 200, {
      react: 1,
    }, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 200, {
      react: 2,
    }, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[6].id}`, 200, {
      react: 'sad',
    }, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[5].id}`, 200, {
      react: 2,
    }, await validToken(USER2));
  });

  test('Viewing messages, unreacts reflected', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    expect(messages[0].reacts).toHaveLength(0);
    expect(messages[5].reacts).toHaveLength(0);
    expect(messages[6].reacts).toHaveLength(1);
  });

  test('Can\'t unreact if no react exists', async () => {
    const channelId = await publicChannelId();
    const { messages, } = await getTry(`/message/${channelId}?start=0`, 200, {}, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[6].id}`, 400, {
      react: 'laugh',
    }, await validToken(USER1));
    await postTry(`/message/unreact/${channelId}/${messages[6].id}`, 400, {
      react: 1,
    }, await validToken(USER1));
  });
});
