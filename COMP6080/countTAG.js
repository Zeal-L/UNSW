import fetch from 'node-fetch';
import express from 'express';
const app = express();

app.get('/scrape', (req, res) => {
    const pageurl = req.query.pageurl;
    const tag = req.query.tag;

    fetch(pageurl).then((response) => {
        response.text().then(body => {
            const count = body.split(`<${tag}`).length - 1;
            res.send(`${pageurl} has ${count} ${tag} tags`);
        })
    });
});

app.listen(6080, () => {
    console.log('Example app listening on port 6080!');
    console.log('http://localhost:6080/scrape?pageurl=https://www.reddit.com&tag=img');
    setTimeout(() => {
        console.log('Timeout');
        process.exit(0);
    }, 2 * 60 * 1000);
});

