// Country code to coordinates and name mapping
export interface CountryInfo {
    name: string;
    lat: number;
    lng: number;
}

export const THAILAND: CountryInfo = {
    name: "Thailand",
    lat: 15.8700,
    lng: 100.9925,
};

export const COUNTRY_DATA: Record<string, CountryInfo> = {
    "AF": { name: "Afghanistan", lat: 33.9391, lng: 67.7100 },
    "AL": { name: "Albania", lat: 41.1533, lng: 20.1683 },
    "AU": { name: "Australia", lat: -25.2744, lng: 133.7751 },
    "AT": { name: "Austria", lat: 47.5162, lng: 14.5501 },
    "BE": { name: "Belgium", lat: 50.5039, lng: 4.4699 },
    "BR": { name: "Brazil", lat: -14.2350, lng: -51.9253 },
    "BG": { name: "Bulgaria", lat: 42.7339, lng: 25.4858 },
    "CA": { name: "Canada", lat: 56.1304, lng: -106.3468 },
    "CN": { name: "China", lat: 35.8617, lng: 104.1954 },
    "CZ": { name: "Czech Republic", lat: 49.8175, lng: 15.4730 },
    "DK": { name: "Denmark", lat: 56.2639, lng: 9.5018 },
    "EG": { name: "Egypt", lat: 26.8206, lng: 30.8025 },
    "EE": { name: "Estonia", lat: 58.5953, lng: 25.0136 },
    "FI": { name: "Finland", lat: 61.9241, lng: 25.7482 },
    "FR": { name: "France", lat: 46.2276, lng: 2.2137 },
    "DE": { name: "Germany", lat: 51.1657, lng: 10.4515 },
    "GR": { name: "Greece", lat: 39.0742, lng: 21.8243 },
    "HK": { name: "Hong Kong", lat: 22.3193, lng: 114.1694 },
    "HU": { name: "Hungary", lat: 47.1625, lng: 19.5033 },
    "IS": { name: "Iceland", lat: 64.9631, lng: -19.0208 },
    "IN": { name: "India", lat: 20.5937, lng: 78.9629 },
    "ID": { name: "Indonesia", lat: -0.7893, lng: 113.9213 },
    "IR": { name: "Iran", lat: 32.4279, lng: 53.6880 },
    "IQ": { name: "Iraq", lat: 33.2232, lng: 43.6793 },
    "IE": { name: "Ireland", lat: 53.1424, lng: -7.6921 },
    "IL": { name: "Israel", lat: 31.0461, lng: 34.8516 },
    "IT": { name: "Italy", lat: 41.8719, lng: 12.5674 },
    "JP": { name: "Japan", lat: 36.2048, lng: 138.2529 },
    "KZ": { name: "Kazakhstan", lat: 48.0196, lng: 66.9237 },
    "KE": { name: "Kenya", lat: -0.0236, lng: 37.9062 },
    "KR": { name: "South Korea", lat: 35.9078, lng: 127.7669 },
    "KW": { name: "Kuwait", lat: 29.3117, lng: 47.4818 },
    "LV": { name: "Latvia", lat: 56.8796, lng: 24.6032 },
    "LB": { name: "Lebanon", lat: 33.8547, lng: 35.8623 },
    "LK": { name: "Sri Lanka", lat: 7.8731, lng: 80.7718 },
    "LT": { name: "Lithuania", lat: 55.1694, lng: 23.8813 },
    "LU": { name: "Luxembourg", lat: 49.8153, lng: 6.1296 },
    "MY": { name: "Malaysia", lat: 4.2105, lng: 101.9758 },
    "MX": { name: "Mexico", lat: 23.6345, lng: -102.5528 },
    "MD": { name: "Moldova", lat: 47.4116, lng: 28.3699 },
    "MA": { name: "Morocco", lat: 31.7917, lng: -7.0926 },
    "NL": { name: "Netherlands", lat: 52.1326, lng: 5.2913 },
    "NZ": { name: "New Zealand", lat: -40.9006, lng: 174.8860 },
    "NG": { name: "Nigeria", lat: 9.0820, lng: 8.6753 },
    "KP": { name: "North Korea", lat: 40.3399, lng: 127.5101 },
    "NO": { name: "Norway", lat: 60.4720, lng: 8.4689 },
    "PK": { name: "Pakistan", lat: 30.3753, lng: 69.3451 },
    "PA": { name: "Panama", lat: 8.5380, lng: -80.7821 },
    "PH": { name: "Philippines", lat: 12.8797, lng: 121.7740 },
    "PL": { name: "Poland", lat: 51.9194, lng: 19.1451 },
    "PT": { name: "Portugal", lat: 39.3999, lng: -8.2245 },
    "QA": { name: "Qatar", lat: 25.3548, lng: 51.1839 },
    "RO": { name: "Romania", lat: 45.9432, lng: 24.9668 },
    "RU": { name: "Russia", lat: 61.5240, lng: 105.3188 },
    "SA": { name: "Saudi Arabia", lat: 23.8859, lng: 45.0792 },
    "RS": { name: "Serbia", lat: 44.0165, lng: 21.0059 },
    "SG": { name: "Singapore", lat: 1.3521, lng: 103.8198 },
    "SK": { name: "Slovakia", lat: 48.6690, lng: 19.6990 },
    "SI": { name: "Slovenia", lat: 46.1512, lng: 14.9955 },
    "ZA": { name: "South Africa", lat: -30.5595, lng: 22.9375 },
    "ES": { name: "Spain", lat: 40.4637, lng: -3.7492 },
    "SE": { name: "Sweden", lat: 60.1282, lng: 18.6435 },
    "CH": { name: "Switzerland", lat: 46.8182, lng: 8.2275 },
    "SY": { name: "Syria", lat: 34.8021, lng: 38.9968 },
    "TW": { name: "Taiwan", lat: 23.6978, lng: 120.9605 },
    "TH": { name: "Thailand", lat: 15.8700, lng: 100.9925 },
    "TR": { name: "Turkey", lat: 38.9637, lng: 35.2433 },
    "UA": { name: "Ukraine", lat: 48.3794, lng: 31.1656 },
    "AE": { name: "United Arab Emirates", lat: 23.4241, lng: 53.8478 },
    "GB": { name: "United Kingdom", lat: 55.3781, lng: -3.4360 },
    "US": { name: "United States", lat: 37.0902, lng: -95.7129 },
    "VN": { name: "Vietnam", lat: 14.0583, lng: 108.2772 },
    "YE": { name: "Yemen", lat: 15.5527, lng: 48.5164 },
};

// Get country name from code
export function getCountryName(code: string): string {
    return COUNTRY_DATA[code.toUpperCase()]?.name || code;
}

// Get country coordinates from code
export function getCountryCoords(code: string): { lat: number; lng: number } | null {
    const country = COUNTRY_DATA[code.toUpperCase()];
    if (!country) return null;
    return { lat: country.lat, lng: country.lng };
}

// Severity color mapping
export function getSeverityColor(severity: string): string {
    const colors: Record<string, string> = {
        critical: '#e53935',
        high: '#ff9800',
        medium: '#ffc107',
        low: '#4caf50',
        clean: '#2196f3',
    };
    return colors[severity?.toLowerCase()] || '#666';
}
