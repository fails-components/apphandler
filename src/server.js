/*
    Fails Components (Fancy Automated Internet Lecture System - Components)
    Copyright (C)  2015-2017 (original FAILS), 
                   2021- (FAILS Components)  Marten Richter <marten.richter@freenet.de>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

import express from 'express'
import * as redis from 'redis'
import MongoClient from 'mongodb'
import cors from 'cors'
import {
  FailsJWTSigner,
  FailsJWTVerifier,
  FailsAssets
} from '@fails-components/security'
import { FailsConfig } from '@fails-components/config'

import { AppHandler } from './apphandler.js'

const initServer = async () => {
  console.log('start initialize server')

  const cfg = new FailsConfig()

  const redisclient = redis.createClient({
    socket: { port: cfg.redisPort(), host: cfg.redisHost() },
    password: cfg.redisPass()
  })

  await redisclient.connect()
  console.log('redisclient connected')

  const mongoclient = await MongoClient.connect(cfg.getMongoURL(), {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  const mongodb = mongoclient.db(cfg.getMongoDB())

  const assets = new FailsAssets({
    datadir: cfg.getDataDir(),
    dataurl: cfg.getURL('data'),
    savefile: cfg.getStatSaveType(),
    webservertype: cfg.getWSType(),
    privateKey: cfg.getStatSecret()
  })

  const appsecurity = new FailsJWTSigner({
    redis: redisclient,
    type: 'app',
    expiresIn: '10m',
    secret: cfg.getKeysSecret()
  })
  const lecturesecurity = new FailsJWTSigner({
    redis: redisclient,
    type: 'lecture',
    expiresIn: '1m',
    secret: cfg.getKeysSecret()
  })
  const notessecurity = new FailsJWTSigner({
    redis: redisclient,
    type: 'notes',
    expiresIn: '1m',
    secret: cfg.getKeysSecret()
  })
  const appverifier = new FailsJWTVerifier({ redis: redisclient, type: 'app' })

  const notepadurl = cfg.getURL('notepad')
  const notesurl = cfg.getURL('notes')

  const apphandler = new AppHandler({
    signServerJwt: appsecurity.signToken,
    signLectureJwt: lecturesecurity.signToken,
    signNotesJwt: notessecurity.signToken,
    redis: redisclient,
    mongo: mongodb,
    saveFile: assets.saveFile,
    getFileURL: assets.getFileURL,
    fixednotepadURL: notepadurl,
    fixednotesURL: notesurl
  })

  const app = express()

  app.use(express.urlencoded({ extended: true }))
  app.use(express.json())

  // if (true) {
  // only in development!
  if (cfg.devmode) {
    app.use(cors())
  }
  // }

  if (assets.localServer()) {
    console.log('Local server started', assets.localServer())
    // this is for static serving, may be in production a more clever alternative to circuvent the mime problem might be found
    app.use(
      cfg.getSDataDir(),
      assets.getLocalVerifier(),
      express.static(assets.datadir, {})
    )
  }

  app.use(cfg.getSPath('app'), appverifier.express()) // secure all app routes

  apphandler.installHandlers(app)

  let port = cfg.getPort('app')
  if (port === 443) port = 8080 // we are in production mode inside a container
  app.listen(port, cfg.getHost(), function () {
    console.log(
      'Failsserver app handler listening port:',
      port,
      ' host:',
      cfg.getHost()
    )
  })
}
initServer()
