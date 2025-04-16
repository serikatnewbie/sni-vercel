/* eslint-disable */
import fetch from "node-fetch";
import * as cheerio from "cheerio";
import fs from "fs";

const TEAM_URL = "https://ctftime.org/team/279998";

async function scrapeCTFEvents(html: string) {
  const $ = cheerio.load(html);

  const events: any[] = [];

  $(".table tbody tr").each((_, row) => {
    const cols = $(row).find("td");
    if (cols.length >= 5) {
      const place = $(cols[1]).text().trim();
      const event = $(cols[2]).text().trim();
      const ctfPoints = $(cols[3]).text().trim();
      const ratingPoints = $(cols[4]).text().trim();
      const href = $(cols[2]).find("a").attr("href");

      events.push({
        place,
        event,
        ctfPoints,
        ratingPoints,
        href,
      });
    }
  });

  fs.writeFileSync("ctf_events.json", JSON.stringify(events, null, 2));
  console.log("✅ Event data saved to ctf_events.json");
}

async function scrapePlacements(html: string) {
  const $ = cheerio.load(html);

  const placements: any[] = [];

  let year = 2024;

  while (true) {
    const accessor = `#rating_${year}`;
    const ratingParagraphs = $(accessor)
      .map((_, el) => $(el).children().first().text())
      .get()
      .join("\n");

    if (ratingParagraphs.length === 0) {
      break;
    }

    const countryRatingParagraphs = $(accessor)
      .map((_, el) => $(el).children().first().next().text())
      .get()
      .join("\n");

    const regex =
      /Overall rating place:\s*(\d+)\s*with\s*([\d.]+)\s*pts\s*in\s*(\d{4})/gi;

    let match;
    if ((match = regex.exec(ratingParagraphs)) !== null) {
      const place = Number(match[1]);
      const points = Number(match[2]);
      const countryPlace = Number(countryRatingParagraphs.split(" ")[2]);

      placements.push({ place, countryPlace, points, year });
    }

    year += 1;
  }
  fs.writeFileSync("ctf_placement.json", JSON.stringify(placements, null, 2));
  console.log("✅ All yearly placements saved to ctf_placement.json");
}

async function main() {
  const res = await fetch(TEAM_URL);
  const html = await res.text();
  await scrapeCTFEvents(html);
  await scrapePlacements(html);
}

main().catch(console.error);
