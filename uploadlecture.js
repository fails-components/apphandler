import * as dotenv from 'dotenv'
import { FailsConfig } from '@fails-components/config'
import MongoClient from 'mongodb'
import { validate as isUUID } from 'uuid'
import { access, constants, readFile } from 'node:fs/promises'
import JSZip from 'jszip'
import path from 'node:path'
import { FailsAssets } from '@fails-components/security'
dotenv.config()

let mongoclient

const globalfunc = async () => {
  const cfg = new FailsConfig()
  const assets = new FailsAssets({
    datadir: cfg.getDataDir(),
    dataurl: cfg.getURL('data'),
    savefile: cfg.getStatSaveType(),
    webservertype: cfg.getWSType(),
    privateKey: cfg.getStatSecret(),
    swift: cfg.getSwift(),
    s3: cfg.getS3()
  })
  console.log('mongo connect string', cfg.getMongoURL())

  mongoclient = await MongoClient.connect(cfg.getMongoURL(), {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  const mongodb = mongoclient.db(cfg.getMongoDB())

  let uuid
  const boardsavetime = Date.now()

  if (process.argv.length > 3) {
    // do the action
    if (!isUUID(process.argv[2]))
      throw new Error('Second argument is not a guid')
    uuid = process.argv[2]

    await access(process.argv[3], constants.R_OK)
  } else throw new Error('wrong number of arguments passed')

  const zip = await JSZip.loadAsync(await readFile(process.argv[3]))
  const info = JSON.parse(await zip.file('info.json').async('text'))
  console.log('original info', info)
  if (info.usedpictures)
    info.usedpictures = info.usedpictures.map((el) => ({
      ...el,
      sha: Buffer.from(el.sha, 'hex'),
      tsha: Buffer.from(el.tsha || el.sha, 'hex')
    }))
  if (info.backgroundpdf)
    info.backgroundpdf = {
      ...info.backgroundpdf,
      sha: Buffer.from(info.backgroundpdf.sha, 'hex')
    }
  // now we have to extract the boards
  info.boards = []
  const boardload = []
  zip.forEach((rpath, file) => {
    const mypath = path.parse(rpath)
    if (mypath.ext !== '.json') return
    if (mypath.name === 'info') return
    // it is a board!
    const boardname = mypath.name
    info.boards.push(boardname)
    // now laod board
    boardload.push(file.async('text'))
  })
  console.log('info', info)
  const loadedboards = (await Promise.all(boardload))
    .map((el) => JSON.parse(el))
    .map((el) => ({
      board: el.name,
      uuid,
      boarddata: Buffer.from(el.data, 'base64'),
      boardsavetime
    }))
  console.log('Loaded baords', loadedboards)
  const upassets = []
  if (info.usedpictures) upassets.push(...info.usedpictures)
  if (info.backgroundpdf) upassets.push(info.backgroundpdf)
  await Promise.all(
    upassets.map(async (el) => {
      const file = await zip.file('assets/' + el.sha.toString('hex'))
      if (file) {
        const filecontents = await file.async('nodebuffer')
        console.log('Uploading asset', el.name, el.mimetype)
        await assets.saveFile(filecontents, el.sha, el.mimetype)
      } else {
        console.log(
          'missing assets',
          'assets/' + el.sha.toString('hex'),
          el.name
        )
      }
    })
  )
  // upload to db
  console.log('Start uploading boards')
  const lbcol = mongodb.collection('lectureboards')
  await Promise.all(
    loadedboards.map(
      async (el) =>
        await lbcol.updateOne(
          { uuid, board: el.board },
          { $set: el },
          { upsert: true }
        )
    )
  )
  console.log('Update lecture record')
  await mongodb.collection('lectures').updateOne({ uuid }, { $set: info })
  await mongoclient.close()
}

globalfunc().catch((error) => {
  console.log('usage GUID lecture zipfile')
  console.log('global error', error)
  if (mongoclient)
    mongoclient
      .close()
      .catch((error) => console.log('Problem closing mongo:', error))
})
