"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * Weather Checker Skill — safe reference implementation.
 * Fetches weather data from Open-Meteo public API.
 */
const https = __importStar(require("https"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
/** Fetch weather for given lat/lon (uses HTTPS to public API only). */
function fetchWeather(lat, lon) {
    return new Promise((resolve, reject) => {
        const url = `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true`;
        https.get(url, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk.toString(); });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(body));
                }
                catch (e) {
                    reject(e);
                }
            });
        }).on('error', reject);
    });
}
/** Cache results locally to reduce API calls. */
function getCachePath(city) {
    const cacheDir = path.join(process.cwd(), 'weather-cache');
    if (!fs.existsSync(cacheDir))
        fs.mkdirSync(cacheDir, { recursive: true });
    return path.join(cacheDir, `${city.replace(/[^a-z0-9]/gi, '_')}.json`);
}
async function main() {
    const city = process.argv[2] ?? 'London';
    // Hardcoded coordinates for demo; real impl would use a geocoding API
    const coords = {
        London: [51.5074, -0.1278],
        Berlin: [52.5200, 13.4050],
        Tokyo: [35.6762, 139.6503],
        'New York': [40.7128, -74.0060],
    };
    const [lat, lon] = coords[city] ?? coords['London'];
    const cachePath = getCachePath(city);
    // Use cache if fresh (< 10 minutes old)
    if (fs.existsSync(cachePath)) {
        const stat = fs.statSync(cachePath);
        if (Date.now() - stat.mtimeMs < 10 * 60 * 1000) {
            const cached = JSON.parse(fs.readFileSync(cachePath, 'utf-8'));
            console.log(`Weather in ${city} (cached): ${cached.current_weather.temperature}°C`);
            return;
        }
    }
    try {
        const data = await fetchWeather(lat, lon);
        fs.writeFileSync(cachePath, JSON.stringify(data));
        console.log(`Weather in ${city}: ${data.current_weather.temperature}°C, ` +
            `wind ${data.current_weather.windspeed} km/h`);
    }
    catch (err) {
        console.error('Failed to fetch weather:', err);
        process.exit(1);
    }
}
main();
//# sourceMappingURL=weather.js.map