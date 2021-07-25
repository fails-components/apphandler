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

import  express  from "express";
import * as redis  from "redis";
import MongoClient from 'mongodb';
import cors from 'cors';
import {FailsJWTSigner,FailsJWTVerifier, FailsAssets} from 'fails-components-security';
import {FailsConfig} from 'fails-components-config';

import {AppHandler} from './apphandler.js';

let cfg=new FailsConfig();

const redisclient = redis.createClient({detect_buffers: true /* required by notescreen connection*/});

let mongoclient = await MongoClient.connect(cfg.getMongoURL(),{useNewUrlParser: true , useUnifiedTopology: true });
let mongodb =mongoclient.db(cfg.getMongoDB());

let assets= new FailsAssets( { datadir: cfg.getDataDir(), dataurl: cfg.getURL('data'), savefile: cfg.getStatSaveType(), webservertype: cfg.getWSType(), privateKey: cfg.getStatSecret()});

let appsecurity=new FailsJWTSigner ({redis: redisclient, type: 'app', expiresIn: "10m", secret: cfg.getKeysSecret() });
let lecturesecurity=new FailsJWTSigner ({redis: redisclient, type: 'lecture', expiresIn: "1m", secret:  cfg.getKeysSecret() });
let notessecurity=new FailsJWTSigner ({redis: redisclient, type: 'notes', expiresIn: "1m", secret: cfg.getKeysSecret() });
let appverifier= new FailsJWTVerifier({redis: redisclient, type: 'app'} );



let notepadurl=cfg.getURL('notepad');
let notesurl=cfg.getURL('notes');


var apphandler = new AppHandler({
  signServerJwt: appsecurity.signToken,
  signLectureJwt: lecturesecurity.signToken,
  signNotesJwt: notessecurity.signToken,
  redis: redisclient, mongo: mongodb,
  saveFile: assets.saveFile,
  getFileURL: assets.getFileURL,
  fixednotepadURL: notepadurl,
  fixednotesURL: notesurl,

});


var app = express();




app.use(express.urlencoded({ extended: true }));
app.use(express.json());



if (true) // only in development!
{
  app.use(cors());
}

if (assets.localServer) {
  // this is for static serving, may be in production a more clever alternative to circuvent the mime problem might be found
  app.use(cfg.getSDataDir(), assets.getLocalVerifier(),
    express.static(assets.datadir, {
      
    }));
}

app.use(cfg.getSPath('app'),appverifier.express()); //secure all app routes

apphandler.installHandlers(app);


app.listen(cfg.getPort('app'),cfg.getHost(),function() {
    console.log('Failsserver app handler listening port:',cfg.getPort('app'),' host:',cfg.getHost());
      });

