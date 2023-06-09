const express = require('express');
const path = require('path');
const app = express();

const exampleName = process.argv[2] || 'simpleform';

app.use('/pkg', express.static(path.join(__dirname, 'pkg')));
app.use('/', express.static(path.join(__dirname, exampleName)));

app.listen(8000, function () {
  console.log('App listening on port 8000, serving example: ' + exampleName);
});

