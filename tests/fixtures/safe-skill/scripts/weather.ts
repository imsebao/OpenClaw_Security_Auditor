/**
 * Weather Checker Skill — safe reference implementation.
 * Fetches weather data from Open-Meteo public API.
 */
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';

interface WeatherResponse {
  current_weather: {
    temperature: number;
    windspeed: number;
    weathercode: number;
  };
}

/** Fetch weather for given lat/lon (uses HTTPS to public API only). */
function fetchWeather(lat: number, lon: number): Promise<WeatherResponse> {
  return new Promise((resolve, reject) => {
    const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true`;
    https.get(url, (res) => {
      let body = '';
      res.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      res.on('end', () => {
        try { resolve(JSON.parse(body) as WeatherResponse); }
        catch (e) { reject(e); }
      });
    }).on('error', reject);
  });
}

/** Cache results locally to reduce API calls. */
function getCachePath(city: string): string {
  const cacheDir = path.join(process.cwd(), 'weather-cache');
  if (!fs.existsSync(cacheDir)) fs.mkdirSync(cacheDir, { recursive: true });
  return path.join(cacheDir, `${city.replace(/[^a-z0-9]/gi, '_')}.json`);
}

async function main() {
  const city = process.argv[2] ?? 'London';
  // Hardcoded coordinates for demo; real impl would use a geocoding API
  const coords: Record<string, [number, number]> = {
    London: [51.5074, -0.1278],
    Berlin: [52.5200, 13.4050],
    Tokyo: [35.6762, 139.6503],
    'New York': [40.7128, -74.0060],
  };

  const [lat, lon] = coords[city] ?? coords['London']!;
  const cachePath = getCachePath(city);

  // Use cache if fresh (< 10 minutes old)
  if (fs.existsSync(cachePath)) {
    const stat = fs.statSync(cachePath);
    if (Date.now() - stat.mtimeMs < 10 * 60 * 1000) {
      const cached = JSON.parse(fs.readFileSync(cachePath, 'utf-8')) as WeatherResponse;
      console.log(`Weather in ${city} (cached): ${cached.current_weather.temperature}°C`);
      return;
    }
  }

  try {
    const data = await fetchWeather(lat, lon);
    fs.writeFileSync(cachePath, JSON.stringify(data));
    console.log(`Weather in ${city}: ${data.current_weather.temperature}°C, ` +
      `wind ${data.current_weather.windspeed} km/h`);
  } catch (err) {
    console.error('Failed to fetch weather:', err);
    process.exit(1);
  }
}

main();
