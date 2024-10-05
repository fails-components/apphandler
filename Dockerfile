FROM node:20-bookworm-slim

ARG ENV

WORKDIR /usr/src/apphandler

COPY package*.json ./
COPY .npmrc ./

#debug
RUN --mount=type=secret,id=GH_TOKEN export GH_TOKEN=`cat /run/secrets/GH_TOKEN`; if [ "$ENV" = "debug" ] ; then npm install ; else  npm ci --only=production; fi

COPY . .

EXPOSE 8080

VOLUME ["/usr/src/apphandler/files"]

CMD [ "node", "src/server.js" ]
