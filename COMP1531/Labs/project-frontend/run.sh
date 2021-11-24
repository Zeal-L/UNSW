#!/bin/sh
echo "REACT_APP_BACKEND_PORT=$1" > .env
echo "PORT=$2" >> .env
npm run start-react

