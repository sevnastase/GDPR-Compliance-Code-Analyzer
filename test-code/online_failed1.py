#JavaScript

const express = require('express')
const app = express()
const fake = require('@praveen_prajapati/fakeit')
const db = require('./db')
const port = 3000


app.get('/', async (req, res) => {

  const count = await db.count()

  if (count < 20) {
    const name = `${fake.person.name()} ${fake.person.surname()}`
    db.insert(name)
    console.log(`Inserindo ${name}`)
  } else {
    console.log("Já existem 20 registros")
  }

  const rows = await db.findAll()
  console.log("rows", rows)

  const header = `<h1>Full Cycle Rocks!</h1>`

  let response = header

  if (rows) {
    const items = rows.map(row => `<li>${row.id}: ${row.name}</li>`).join('')
    const list = `<ul>${items}</ul>`
    response = response + list
  }

  res.send(response)
})

app.listen(port, '0.0.0.0', () => {
  console.log(`Fullcycle app ouvindo na porta http://localhost:${port}`)
})