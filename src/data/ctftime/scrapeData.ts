import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import fs from 'fs';

const TEAM_URL = 'https://ctftime.org/team/279998';

async function scrapeCTFEvents() {
  const res = await fetch(TEAM_URL);
  const html = await res.text();
  const $ = cheerio.load(html);

  const events: any[] = [];

  $('.table tbody tr').each((_, row) => {
    const cols = $(row).find('td');
    if (cols.length >= 5) {
      const place = $(cols[1]).text().trim();
      const event = $(cols[2]).text().trim();
      const ctfPoints = $(cols[3]).text().trim();
      const ratingPoints = $(cols[4]).text().trim();
      const href = $(cols[2]).find('a').attr('href');
    
    events.push({
        place,
        event,
        ctfPoints,
        ratingPoints,
        href
    });
    }
  });

  fs.writeFileSync('ctf_events.json', JSON.stringify(events, null, 2));
  console.log('✅ Event data saved to ctf_events.json');
}

scrapeCTFEvents().catch(console.error);