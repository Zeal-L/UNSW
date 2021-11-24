import React from 'react';
import {useInterval} from './index';

export let stepSubscribers = [];

export const subscribeToStep = (subscriber, interval=1) => {
    if (stepSubscribers.find(o => o.subscriber === subscriber) !== undefined) return;
    stepSubscribers.push({ subscriber, interval });
}
export const unsubscribeToStep = (unsubscriber) => stepSubscribers = stepSubscribers.filter(o => o.subscriber !== unsubscriber);

export const step = (iter) => {
    stepSubscribers.forEach(o => {
        console.log(iter, o.interval, iter % o.interval == 0, o.subscriber)
        if (!iter || iter % o.interval == 0) {
            o.subscriber()
        }
    });
}

export const useStep = (subscriber, watches=[], interval=1) => {
    const shouldSubscribe = subscriber && typeof subscriber === "function";
    React.useEffect(() => {
        if (shouldSubscribe) {
            subscriber();
            subscribeToStep(subscriber, interval);
            return () => unsubscribeToStep(subscriber);
        }
    }, watches);
    return step;
};

let isPolling = false;
export const pollingInterval = 2000;
export const getIsPolling = () => isPolling;
export const setIsPolling = bool => {
    isPolling = !!bool; // force boolean type
}

/* IMPORTANT: Called in PollToggle */
let count = 0;
export const usePolling = () => {
    useInterval(() => {
        if (isPolling) step(count++);
    }, pollingInterval);
}
