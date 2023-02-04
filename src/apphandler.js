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

import { v4 as uuidv4, validate as isUUID } from 'uuid'
import multer from 'multer'
import { createHash } from 'crypto'

export class AppHandler {
  constructor(args) {
    this.redis = args.redis
    this.mongo = args.mongo
    this.signLectureJwt = args.signLectureJwt
    this.signNotesJwt = args.signNotesJwt
    this.signServerJwt = args.signServerJwt
    this.saveFile = args.saveFile
    this.getFileURL = args.getFileURL
    this.fixednotepadURL = args.fixednotepadURL
    this.fixednotesURL = args.fixednotesURL

    this.upload = multer({ limits: { fileSize: 20000000, files: 2 } })
  }

  notepadURL(lectureuuid) {
    // later we will ask redis, where the primary lecture is handled, or if a new one should be started

    return this.fixednotepadURL
  }

  notesURL(lectureuuid) {
    // later we will ask redis, where the secondary lecture is handled, or if a new one should be started

    return this.fixednotesURL
  }

  installHandlers(path, app) {
    // secure the lecture permissions
    app.use(path + '/lecture', (req, res, next) => {
      if (!req.token.role) return res.status(401).send('unauthorized')
      if (
        !req.token.role.includes('instructor') &&
        !req.token.role.includes('audience')
      )
        return res.status(401).send('unauthorized')
      next()
    })

    // renew the auth token
    app.get(path + '/token', async (req, res) => {
      if (
        !req.token.role.includes('instructor') &&
        !req.token.role.includes('audience')
      )
        return res.status(401).send('unauthorized')

      const oldtoken = req.token
      const newtoken = {
        course: oldtoken.course,
        user: oldtoken.user,
        role: oldtoken.role,
        appversion: oldtoken.appversion,
        context: oldtoken.context,
        maxrenew: oldtoken.maxrenew - 1
      }
      if (!oldtoken.maxrenew || !(oldtoken.maxrenew > 0)) return {}
      res.status(200).json({ token: await this.signServerJwt(newtoken) })
    })

    // get auth token for notebook
    app.get(path + '/lecture/notepadtoken', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(400).send('unauthorized uuid') // supply valid data
      const oldtoken = req.token

      const lecturetokendata = {
        user: oldtoken.user,
        purpose: 'notepad',
        name: 'Primary Notebook',
        lectureuuid: lectureuuid,
        appversion: oldtoken.appversion,
        maxrenew: 288, // 24-48h, depending on renewal frequency
        notescreenuuid: uuidv4(),
        notepadhandler: this.notepadURL(lectureuuid)
      }
      res
        .status(200)
        .json({ token: await this.signLectureJwt(lecturetokendata) })
    })

    app.get(path + '/lecture/studenttoken', async (req, res) => {
      if (!req.token.role.includes('audience'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(400).send('unauthorized uuid') // supply valid data
      const oldtoken = req.token

      const lecturetokendata = {
        user: oldtoken.user,
        purpose: 'notes',
        name: 'Notes',
        lectureuuid: lectureuuid,
        appversion: oldtoken.appversion,
        maxrenew: 288, // 24-48h, depending on renewal frequency
        notescreenuuid: uuidv4(),
        noteshandler: this.notesURL(lectureuuid)
      }
      res.status(200).json({ token: await this.signNotesJwt(lecturetokendata) })
    })

    app.post(path + '/lecture/auth', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(401).send('unauthorized uuid') // supply valid data

      const user = req.token.user

      const payload = {
        uuid: lectureuuid,
        user: user,
        appversion: req.token.appversion
      }
      if (!req.body.id || !/[A-Za-z0-9+/]/g.test(req.body.id))
        return res.status(400).send('malformed id')

      const id = req.body.id
      // now we check if the key is in our redis db
      const ex = await this.redis.exists('auth::' + id)
      if (ex[0]) return res.status(400).send('unknown id')
      console.log('redis publish for ', id, payload)
      // ok it is legitimate, so send it please to redis pubsub
      this.redis.publish('auth::' + id, JSON.stringify(payload))

      res.status(200).json({ message: 'success' })
    })

    app.patch(path + '/lecture/course', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(400).send('unauthorized uuid') // supply valid data

      const details = await this.getLectureDetails(lectureuuid)
      if (!details) return res.status(404).send('not found')
      // console.log('patch request', req.body)

      if (!details.lms.iss) return res.status(404).send('lect without iss')
      if (!details.lms.course_id)
        return res.status(404).send('lect without course_id')

      try {
        const data = req.body

        const lecturescol = this.mongo.collection('lectures')

        if (data.appversion) {
          if (
            data.appversion !== 'stable' &&
            data.appversion !== 'experimental'
          )
            res.status(400).send('malformed request: unknown appversion')
          await lecturescol.updateMany(
            {
              $and: [
                {
                  'lms.iss': details.lms.iss
                },
                {
                  'lms.course_id': details.lms.course_id
                }
              ]
            },
            {
              $set: { appversion: data.appversion },
              $currentDate: { lastaccess: true }
            }
          )
        }
        return res.status(200).json({})
      } catch (error) {
        console.log('lecture patch db error', error)
        return res.status(500).send('db error')
      }
    })

    app.patch(path + '/lecture', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(400).send('unauthorized uuid') // supply valid data

      const details = await this.getLectureDetails(lectureuuid)
      if (!details) return res.status(404).send('not found')
      // console.log('patch request', req.body)

      try {
        const data = req.body

        const lecturescol = this.mongo.collection('lectures')

        if (data.date) {
          // we like to change the date
          await lecturescol.updateOne(
            { uuid: lectureuuid },
            {
              $set: { date: new Date(data.date) },
              $currentDate: { lastaccess: true }
            }
          )
        }
        if (data.polls) {
          // console.log(data.polls)
          if (
            !data.polls.id ||
            typeof data.polls.id !== 'string' ||
            data.polls.id > 20 ||
            (!data.polls.name && !('multi' in data.polls))
          )
            return res.status(400).send('malformed request')

          if (data.polls.parentid) {
            await lecturescol.updateOne(
              {
                uuid: lectureuuid,
                'polls.children.id': { $ne: data.polls.id }
              },
              {
                $addToSet: {
                  'polls.$[pollparchange].children': { id: data.polls.id }
                }
              },
              { arrayFilters: [{ 'pollparchange.id': data.polls.parentid }] }
            )
            const tochange = { $set: {}, $currentDate: { lastaccess: true } }
            if (data.polls.name)
              tochange.$set[
                'polls.$[pollparchange].children.$[pollchange].name'
              ] = data.polls.name
            if ('multi' in data.polls)
              tochange.$set[
                'polls.$[pollparchange].children.$[pollchange].multi'
              ] = data.polls.multi
            await lecturescol.updateOne({ uuid: lectureuuid }, tochange, {
              arrayFilters: [
                { 'pollparchange.id': data.polls.parentid },
                { 'pollchange.id': data.polls.id }
              ]
            })
          } else {
            await lecturescol.updateOne(
              { uuid: lectureuuid, 'polls.id': { $ne: data.polls.id } },
              { $addToSet: { polls: { id: data.polls.id } } }
            )
            const tochange = { $set: {}, $currentDate: { lastaccess: true } }
            if (data.polls.name)
              tochange.$set['polls.$[pollchange].name'] = data.polls.name
            if ('multi' in data.polls)
              tochange.$set['polls.$[pollchange].multi'] = data.polls.multi
            await lecturescol.updateOne({ uuid: lectureuuid }, tochange, {
              arrayFilters: [{ 'pollchange.id': data.polls.id }]
            })
          }
        }
        if (data.removepolls) {
          if (data.polls) return res.status(400).send('malformed request') // please not simultaneously
          if (
            !data.removepolls.id ||
            typeof data.removepolls.id !== 'string' ||
            data.removepolls.id > 20
          )
            return res.status(400).send('malformed request')
          const tochange = { $currentDate: { lastaccess: true } }
          if (data.removepolls.parentid) {
            // poll ids should be unique...
            tochange.$pull = {
              'polls.$[].children': { id: data.removepolls.id }
            }
          } else {
            tochange.$pull = { polls: { id: data.removepolls.id } }
          }
          await lecturescol.updateOne({ uuid: lectureuuid }, tochange)
        }
        /* if (shouldpatch) {
                     
                         
                         if (shouldprepatch) {
                             await lecturescol.updateOne(prepatchsel, prechange,{arrayFilters: prearrayfilters});
                         }
                         lecturescol.updateOne({ uuid: lectureuuid }, tochange,{arrayFilters: arrayfilters});
                         console.log("pacthed",shouldpatch,tochange,arrayfilters);
                         return res.status(200).json({});
     
                     
                 } else return res.status(200).json({}); */
        return res.status(200).json({})
      } catch (error) {
        console.log('lecture patch db error', error)
        return res.status(500).send('db error')
      }
    })

    app.get(path + '/lecture', async (req, res) => {
      // ok folks, we get the lecture id from the token
      const lectureuuid = req.token.course.lectureuuid
      // TODO code for administrators to overrule the token uuid
      if (!isUUID(lectureuuid)) return res.status(401).send('unauthorized uuid') // supply valid data
      const details = await this.getLectureDetails(lectureuuid)
      // console.log('details', details)

      if (details) {
        const toret = {
          title: details.title,
          uuid: details.uuid,
          date: details.date
        }
        if (details.coursetitle) toret.coursetitle = details.coursetitle
        if (details.ownersdisplaynames)
          toret.ownersdisplaynames = details.ownersdisplaynames
        if (details.running) toret.running = true
        else toret.running = false
        if (details.date) {
          toret.date = details.date
        }
        // TODO add additional fields for instructor such as pools, pictures, pdfbackground etc.
        if (req.token.role.includes('instructor')) {
          // fields only available for the instructors
          if (details.pictures) {
            const retpict = details.pictures.map((el) => {
              return {
                name: el.name,
                mimetype: el.mimetype,
                sha: el.sha.buffer.toString('hex'),
                url: this.getFileURL(el.sha.buffer, el.mimetype),
                urlthumb: this.getFileURL(el.tsha.buffer, el.mimetype)
              }
            })
            // console.log("pictures",details.pictures);
            // console.log(retpict);
            toret.pictures = retpict
          }
          const bgpdf = {}
          if (details.backgroundpdfuse) {
            // indicates that a lectures has already use the background pdf, no change possible
            bgpdf.fixed = true
            if (details.backgroundpdf && details.backgroundpdf.name)
              bgpdf.name = details.backgroundpdf.name
            // fill it with the name
            else bgpdf.none = true
          } else if (details.backgroundpdf) {
            let none = true
            if (details.backgroundpdf.name) {
              bgpdf.name = details.backgroundpdf.name
              none = false
            }
            if (details.backgroundpdf.sha) {
              bgpdf.sha = details.backgroundpdf.sha
              none = false
              bgpdf.url = this.getFileURL(
                details.backgroundpdf.sha,
                'application/pdf'
              )
            }
            if (none) bgpdf.none = true
          } else bgpdf.none = true
          toret.bgpdf = bgpdf
          if (details.polls) toret.polls = details.polls
        }

        return res.status(200).json(toret)
      } else return res.status(404).send('not found')
    })

    app.get(path + '/lectures', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      // ok folks, we get the user id and lecture id from the token
      // console.log('user data', req.token)
      const lectureuuid = req.token.course.lectureuuid // used to identify the course
      const useruuid = req.token.user.useruuid

      const orquery = []
      try {
        const lecturescol = this.mongo.collection('lectures')

        if (lectureuuid) {
          const lect = await lecturescol.findOne({ uuid: lectureuuid })
          if (lect) {
            const lms = lect.lms
            if (lms && lms.course_id && lms.platform_id) {
              orquery.push({
                'lms.course_id': lms.course_id,
                'lms.platform_id': lms.platform_id
              })
            }
          }
        }
        if (useruuid) {
          orquery.push({ owners: useruuid })
        }
        if (orquery.length < 1) return res.status(400).send('malformed request') // maybe also malformed request
        const cursor = lecturescol
          .find(
            { $or: orquery },
            {
              projection: {
                title: 1,
                coursetitle: 1,
                uuid: 1,
                date: 1,
                'lms.course_id': 1,
                _id: 0
              }
            }
          )
          .sort({ 'lms.course_id': -1, coursetitle: 1, date: 1, title: 1 })

        const toret = await cursor.toArray()
        // console.log('toret', toret)
        return res.status(200).json(toret)
      } catch (error) {
        console.log('lectures error', error)
        return res.status(500).send('error converting')
      }

      /*
                return res.status(200).json(toret);

            } else return res.status(404).send("not found"); */
    })

    app.get(path + '/lecture/pdfdata', async (req, res) => {
      if (
        !req.token.role.includes('instructor') &&
        !req.token.role.includes('audience')
      )
        return res.status(401).send('unauthorized')
      let lectureuuid = req.token.course.lectureuuid

      let find

      if (req.query.lectureuuid) {
        const useruuid = req.token.user.useruuid
        // first check if it is allowed
        if (!req.token.role.includes('instructor'))
          return res.status(401).send('unauthorized')
        if (!isUUID(req.query.lectureuuid))
          return res.status(400).send('unauthorized uuid') // supply valid data
        find = { uuid: req.query.lectureuuid, owners: useruuid }
        lectureuuid = req.query.lectureuuid
      } else {
        if (!isUUID(lectureuuid))
          return res.status(400).send('unauthorized uuid') // supply valid data
        find = { uuid: lectureuuid }
      }

      // ok, we have to get board data
      const lecturescol = this.mongo.collection('lectures')
      const boardscol = this.mongo.collection('lectureboards')
      // ok we have green light, we can transfer the data from mongo to redis
      const lecturedoc = await lecturescol.findOne(find, {
        projection: {
          _id: 0,
          usedpictures: 1,
          title: 1,
          coursetitle: 1,
          ownersdisplaynames: 1,
          date: 1,
          backgroundpdfuse: 1,
          backgroundpdf: 1
        }
      })

      if (!lecturedoc) return res.status(401).send('unauthorized, not found')
      const cursor = boardscol.find({ uuid: lectureuuid })
      let boards = cursor.toArray()

      // lecturedoc= await lecturedoc;

      if (
        lecturedoc.backgroundpdfuse &&
        lecturedoc.backgroundpdf &&
        lecturedoc.backgroundpdf.sha
      ) {
        lecturedoc.backgroundpdf.url = this.getFileURL(
          lecturedoc.backgroundpdf.sha,
          'application/pdf'
        )
      }

      boards = (await boards)
        .filter((el) => el.board && el.boarddata)
        .map((el) => ({ name: el.board, data: el.boarddata }))

      if (!lecturedoc.usedpictures) lecturedoc.usedpictures = []

      lecturedoc.usedpictures = lecturedoc.usedpictures.map((el) => {
        return {
          name: el.name,
          mimetype: el.mimetype,
          sha: el.sha.buffer.toString('hex'),
          url: this.getFileURL(el.sha.buffer, el.mimetype),
          urlthumb: this.getFileURL(el.tsha.buffer, el.mimetype)
        }
      })
      // console.log("check lecture doc for tranfer",lecturedoc);

      res.status(200).json({ info: lecturedoc, boards: boards })
    })

    app.post(path + '/lecture/copy', async (req, res) => {
      if (!req.token.role.includes('instructor'))
        return res.status(401).send('unauthorized')
      const lectureuuid = req.token.course.lectureuuid
      if (!isUUID(lectureuuid)) return res.status(401).send('unauthorized uuid') // supply valid data

      if (!req.body.fromuuid || !isUUID(req.body.fromuuid))
        return res.status(401).send('unauthorized uuid')

      if (req.body.fromuuid === lectureuuid)
        return res.status(401).send('unauthorized equal uuid')

      let filter = { _id: 0 }

      if (req.body.what === 'pictures' || req.body.what === 'all') {
        filter = { ...filter, pictures: 1 }
      }
      if (req.body.what === 'polls' || req.body.what === 'all') {
        filter = { ...filter, polls: 1 }
      }
      if (req.body.what === 'lecture' || req.body.what === 'all') {
        filter = {
          ...filter,
          usedpictures: 1,
          backgroundpdfuse: 1,
          backgroundpdf: 1,
          boards: 1,
          boardsavetime: 1
        }
      }
      // perfect now we have to get the lecture, but not only the uuid but also the useruuid
      const useruuid = req.token.user.useruuid

      const lecturescol = this.mongo.collection('lectures')
      const boardscol = this.mongo.collection('lectureboards')
      if (req.body.what === 'lecture' || req.body.what === 'all') {
        const lecturedocdest = await lecturescol.findOne(
          { uuid: lectureuuid },
          { projection: { backgroundpdfuse: 1 } }
        )
        if (lecturedocdest && lecturedocdest.backgroundpdfuse)
          return res.status(401).send('unauthorized already started')
      }
      const lecturedoc = await lecturescol.findOne(
        { uuid: req.body.fromuuid, owners: useruuid },
        { projection: filter }
      )

      if (!lecturedoc) return res.status(404).send('unauthorized, not found')
      // got it now we can copy/modify destination, but we have to get it first
      const promis = []

      if (req.body.what === 'pictures' || req.body.what === 'all') {
        if (lecturedoc.pictures) {
          promis.push(
            lecturescol.updateOne(
              { uuid: lectureuuid },
              { $addToSet: { pictures: { $each: lecturedoc.pictures } } }
            )
          )
        }
      }
      if (req.body.what === 'polls' || req.body.what === 'all') {
        if (lecturedoc.polls) {
          const toremove = lecturedoc.polls.map((el) => el.id)
          promis.push(
            lecturescol.updateOne(
              { uuid: lectureuuid },
              { $pull: { polls: { id: { $in: toremove } } } }
            )
          )
          // now we removed dublettes, we can insert the current ones
          promis.push(
            lecturescol.updateOne(
              { uuid: lectureuuid },
              { $push: { polls: { $each: lecturedoc.polls } } }
            )
          )
        }
      }
      if (req.body.what === 'lecture' || req.body.what === 'all') {
        const set = {}
        if (lecturedoc.backgroundpdfuse) set.backgroundpdfuse = 1
        if (lecturedoc.backgroundpdf)
          set.backgroundpdf = lecturedoc.backgroundpdf
        if (lecturedoc.boardsavetime)
          set.boardsavetime = lecturedoc.boardsavetime
        if (lecturedoc.usedpictures) set.usedpictures = lecturedoc.usedpictures

        const boards = []
        if (lecturedoc.boards) {
          // ok we to iterate over all boards
          const cursor = boardscol.find({ uuid: req.body.fromuuid })
          while (await cursor.hasNext()) {
            const boardinfo = await cursor.next()
            // console.log('boardinfo', boardinfo)
            // ok we have one document so push it to redis, TODO think of sending the documents directly to clients?
            if (!boardinfo.board || !boardinfo.boarddata) continue // no valid data
            boards.push(boardinfo.board)
            const update = boardscol.updateOne(
              { uuid: lectureuuid, board: boardinfo.board },
              {
                $set: {
                  savetime: boardinfo.savetime,
                  boarddata: boardinfo.boarddata
                }
              },
              { upsert: true }
            )
            promis.push(update)
          }
          promis.push(
            lecturescol.updateOne(
              { uuid: lectureuuid },
              { $addToSet: { boards: { $each: boards } } }
            )
          )
        }
        promis.push(lecturescol.updateOne({ uuid: lectureuuid }, { $set: set }))
      }
      await Promise.all(promis)

      res.status(200).json({ message: 'success' })
    })

    app.post(
      path + '/lecture/picture',
      this.upload.fields([
        { name: 'file', maxCount: 1 },
        { name: 'filethumbnail', maxCount: 1 }
      ]),
      async (req, res) => {
        if (!req.token.role.includes('instructor'))
          return res.status(401).send('unauthorized')
        const lectureuuid = req.token.course.lectureuuid
        if (!isUUID(lectureuuid))
          return res.status(401).send('unauthorized uuid') // supply valid data
        // now we have to calcuate SHA256 data for picture and thumbnail
        // console.log("req files",req.files);
        // console.log("picture",req.files.file);
        // console.log("picture thumbnail",req.files.filethumbnail);
        const cmd = JSON.parse(req.body.data)
        if (!req.files.file || !req.files.filethumbnail || !cmd.filename)
          return res.status(401).send('malformed request')

        const supportedMime = ['image/jpeg', 'image/png']

        if (
          !supportedMime.includes(req.files.file[0].mimetype) ||
          !supportedMime.includes(req.files.file[0].mimetype)
        )
          return res.status(401).send('unsupported mime type')

        try {
          const picturehash = createHash('sha256')
          const thumbnailhash = createHash('sha256')

          picturehash.update(req.files.file[0].buffer)
          thumbnailhash.update(req.files.filethumbnail[0].buffer)

          const pictsha256 = picturehash.digest()
          const thumbsha256 = thumbnailhash.digest()

          await this.saveFile(
            req.files.file[0].buffer,
            pictsha256,
            req.files.file[0].mimetype
          )
          await this.saveFile(
            req.files.filethumbnail[0].buffer,
            thumbsha256,
            req.files.filethumbnail[0].mimetype
          )

          const pictinfo = {
            name: cmd.filename,
            mimetype: req.files.file[0].mimetype,
            sha: pictsha256,
            tsha: thumbsha256
          } // attention field order matters for the addtoset operation!

          const lecturescol = this.mongo.collection('lectures')

          await lecturescol.updateOne(
            { uuid: lectureuuid },
            {
              $addToSet: { pictures: pictinfo },
              $currentDate: { lastaccess: true }
            }
          )

          return res.status(200).json({}) // no return just success
        } catch (error) {
          console.log('picture conversion error', error)
          return res.status(500).send('error converting')
        }
      }
    )

    app.post(
      path + '/lecture/bgpdf',
      this.upload.fields([{ name: 'file', maxCount: 1 }]),
      async (req, res) => {
        if (!req.token.role.includes('instructor'))
          return res.status(401).send('unauthorized')
        const lectureuuid = req.token.course.lectureuuid
        if (!isUUID(lectureuuid))
          return res.status(401).send('unauthorized uuid') // supply valid data
        // now we have to calcuate SHA256 data for bgpdf
        // console.log("req files",req.files);
        // console.log("bgpdf",req.files.file);
        // first we have to check, if the pdf is already locked by the lecture system
        const details = await this.getLectureDetails(lectureuuid)
        if (!details) return res.status(404).send('not found')
        if (details.backgroundpdfuse)
          return res.status(401).send('background pdf is in use')

        try {
          const lecturescol = this.mongo.collection('lectures')
          const cmd = JSON.parse(req.body.data)
          if (cmd.none) {
            // we have to reset
            /* if (details.backgroundpdf.name) {bgpdf.name=details.backgroundpdf.name; none=false;}
                            if (details.backgroundpdf.sha) {bgpdf.sha=details.backgroundpdf.sha; none=false;}
                            if (none)  bgpdf.none=true; */

            await lecturescol.updateOne(
              { uuid: lectureuuid },
              {
                $set: { 'backgroundpdf.none': true },
                $unset: { 'backgroundpdf.name': '', 'backgroundpdf.sha': '' },
                $currentDate: { lastaccess: true }
              }
            )
            return res.status(200).json({}) // no return just success
          }

          if (!req.files.file || !cmd.filename)
            return res.status(401).send('malformed request')

          const pdfhash = createHash('sha256')

          pdfhash.update(req.files.file[0].buffer)

          const pdfsha256 = pdfhash.digest()

          await this.saveFile(
            req.files.file[0].buffer,
            pdfsha256,
            'application/pdf'
          )

          await lecturescol.updateOne(
            { uuid: lectureuuid },
            {
              $unset: { 'backgroundpdf.none': '' },
              $set: {
                'backgroundpdf.name': cmd.filename,
                'backgroundpdf.sha': pdfsha256
              },
              $currentDate: { lastaccess: true }
            }
          )

          return res.status(200).json({}) // no return just success
        } catch (error) {
          console.log('upload pdf error', error)
          return res.status(500).send('error converting')
        }
      }
    )
  }

  async getLectureDetails(uuid) {
    try {
      const lecturescol = this.mongo.collection('lectures')
      const andquery = []

      andquery.push({ uuid: uuid })

      // TODO add course stuff
      // console.log("andquery", andquery);
      const lecturedoc = await lecturescol.findOne({ uuid: uuid })

      if (lecturedoc) {
        // now ask redis, if it is running
        const numberclients = await this.redis.sCard(
          'lecture:' + uuid + ':notescreens'
        ) // TODO fix me inactive clients! and notescreens

        if (numberclients > 0) lecturedoc.running = true
        else lecturedoc.running = false
        return lecturedoc
      } else return null
    } catch (err) {
      console.log('Error in getLecture Details ', uuid, err)
      return null
    }
  }
}
