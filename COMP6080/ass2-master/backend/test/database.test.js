import request from 'supertest';
import server from '../src/server';
import { reset } from '../src/service';

const postTry = async (path, payload, token) => sendTry('post', path, payload, token);
const getTry = async (path, payload, token) => sendTry('get', path, payload, token);

const sendTry = async (typeFn, path, payload = {}, token = null) => {
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
    return response.body;
};

describe('Making the database', () => {

    beforeAll(() => {
        reset();
    });

    beforeAll(() => {
        server.close();
    });

    test('Public channel', async () => {
        let body = await postTry('/auth/register', {
            email: 'mia@email.com',
            password: 'solongbouldercity',
            name: 'Mia',
        });
        const mia = body.token;
        body = await postTry('/auth/register', {
            email: 'sebastian@email.com',
            password: 'chickenonastick',
            name: 'Sebastian',
        });
        const seb = body.token;

        body = await postTry('/channel', {
            name: 'public channel',
            private: false,
            description: '',
        }, mia);
        const channelId = body.channelId;

        const { users, } = await getTry('/user', {}, mia);
        const sebId = users.find(u => u.email === 'sebastian@email.com').id;

        await postTry(`/channel/${channelId}/invite`, {
            userId: sebId,
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'when do you leave? in the morning?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'yeah, 6:45. boise',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'boise?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'boise',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'to boise!',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'you should come',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'to boise?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'yeah, you can knock that off your bucketlist',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'oh, that would be... really exciting. i wish i could',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'what are you doing after the tour?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'why can\'t you?',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'come to boise?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'yeah',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'cause i have to rehearse',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'yeah, but can\'t you rehearse anywhere?',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: '...anywhere you are?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'i mean... i guess',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'um... well all my stuff is here and it\'s in two weeks',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'so i don\'t really think that would be...',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'okay',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'the best idea right now',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'well...',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'but... i wish i could',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'we\'re just gonna have to try and see each other, y\'know, so that we see each other',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'i know, but when are you done?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'what do you mean? i mean...',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'when are you finished with the whole tour?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'but after we finish, we\'re gonna go to record and then we\'ll go back on tour',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'you know, we tour so we can make the record so we can go back and tour the record',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'so it\'s like the long haul?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'what do you mean "the long haul"?',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'i mean the long haul, like you\'re gonna stay in this band... for a long time... on tour',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'i mean, what did you think i was gonna do?',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'i don\'t... i hadn\'t really thought it through. i didn\'t know that the band... was so important',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'you didn\'t think it would be successful',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'um... no, that\'s not really what i mean. i just mean that you, i mean, you\'re gonna be on tour for what? months now? years?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'yeah it\'ll be, this is it. i mean, this is it. it could feasibly be ever. i could be on tour with this... for a couple years at least, just this record',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'do you like the music you\'re playing?',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'i don\'t... i don\'t know what it matters',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'well, it matters because if you\'re gonna give up your dream, i think it matters that you like what you\'re playing on the road for years',
        }, mia);

        await postTry(`/message/${channelId}`, {
            message: 'do you like the music i\'m playing?',
        }, seb);

        await postTry(`/message/${channelId}`, {
            message: 'yeah, i do! i just didn\'t think that you did',
        }, mia);

    });

});
