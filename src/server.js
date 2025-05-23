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

  let rediscl
  let redisclusterconfig
  if (cfg.getRedisClusterConfig)
    redisclusterconfig = cfg.getRedisClusterConfig()
  if (!redisclusterconfig) {
    console.log(
      'Connect to redis database with host:',
      cfg.redisHost(),
      'and port:',
      cfg.redisPort()
    )
    rediscl = redis.createClient({
      socket: { port: cfg.redisPort(), host: cfg.redisHost() },
      password: cfg.redisPass()
    })
  } else {
    // cluster case
    console.log('Connect to redis cluster with config:', redisclusterconfig)
    rediscl = redis.createCluster(redisclusterconfig)
  }

  await rediscl.connect()
  console.log('redisclient connected')

  const mongoclient = await MongoClient.connect(cfg.getMongoURL(), {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  const mongodb = mongoclient.db(cfg.getMongoDB())

  let ready = false

  const assets = new FailsAssets({
    datadir: cfg.getDataDir(),
    dataurl: cfg.getURL('data'),
    savefile: cfg.getStatSaveType(),
    webservertype: cfg.getWSType(),
    privateKey: cfg.getStatSecret(),
    swift: cfg.getSwift(),
    s3: cfg.getS3()
  })

  const appsecurity = new FailsJWTSigner({
    redis: rediscl,
    type: 'app',
    expiresIn: '10m',
    secret: cfg.getKeysSecret()
  })
  const lecturesecurity = new FailsJWTSigner({
    redis: rediscl,
    type: 'lecture',
    expiresIn: '1m',
    secret: cfg.getKeysSecret()
  })
  const notessecurity = new FailsJWTSigner({
    redis: rediscl,
    type: 'notes',
    expiresIn: '1m',
    secret: cfg.getKeysSecret()
  })
  const appverifier = new FailsJWTVerifier({ redis: rediscl, type: 'app' })

  const notepadurl = cfg.getURL('notepad')
  const notesurl = cfg.getURL('notes')

  const apphandler = new AppHandler({
    signServerJwt: appsecurity.signToken,
    signLectureJwt: lecturesecurity.signToken,
    signNotesJwt: notessecurity.signToken,
    redis: rediscl,
    mongo: mongodb,
    handleFileUpload: assets.handleFileUpload,
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

  // Kubernetes livelyness and readyness probes
  app.get('/ready', (req, res) => {
    if (ready) return res.send('Ready')
    else res.status(500).send('Not ready')
  })

  app.get('/health', async (req, res) => {
    res.send('Healthy')
  })

  app.use(cfg.getSPath('app'), appverifier.express()) // secure all app routes

  apphandler.installHandlers(cfg.getSPath('app'), app)

  let port = cfg.getPort('app')
  if (port === 443) port = 8080 // we are in production mode inside a container
  app.listen(port, cfg.getHost(), function () {
    console.log(
      'Failsserver app handler listening port:',
      port,
      ' host:',
      cfg.getHost()
    )
    ready = true
  })
}
initServer()
