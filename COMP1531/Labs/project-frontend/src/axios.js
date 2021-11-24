import axios from 'axios';
// import qs from 'qs';
import _ from 'lodash';

import { url } from './utils/constants';
import { DEFAULT_ERROR_TEXT } from './utils/text';
import { toast } from 'react-toastify';

axios.defaults.baseURL = url;
axios.defaults.headers.put['Content-Type'] = 'application/json';
axios.defaults.headers.post['Content-Type'] = 'application/json';
axios.defaults.headers.delete['Content-Type'] = 'application/json';

// temporarily cancel all requests until backend is ready
const CancelToken = axios.CancelToken;

axios.interceptors.request.use((request) => {
    // if (request.method === 'put' || request.method === 'post' || request.method === 'delete') {
    //     request.data = qs.stringify(request.data);
    // }
    return request;
});

const errorHandler = (error) => {
    // great gist https://gist.github.com/saqueib/a495af17d7c0e2fd5c2316b0822ebac3

    // if has response show the error
    console.error(error);

    let message = DEFAULT_ERROR_TEXT;

    if (error.response) {
        const found = typeof error.response.data === 'string'
            && error.response.data.match(/<p>(.*)<\/p>/);
        const responseMessage = found && found.length > 1 && found[1];
        message = _.get(error, 'response.data.message') || responseMessage || DEFAULT_ERROR_TEXT;
    }

    toast.error(message);

    return Promise.reject({ ...error })
}

const responseHandler = (response) => {
    return response;
}

axios.interceptors.response.use(responseHandler, errorHandler);