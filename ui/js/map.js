"use strict";

/*
==============================================================
 MY SIEM — GLOBAL WORLD THREAT MAP
==============================================================

 REAL DATA SOURCES
 -------------------------------------------------------------
 /api/agents
 /api/alerts
 /api/threats
 /api/threat-map

 MAP
 -------------------------------------------------------------
 Mapbox GL JS
 streets-v12
 satellite-streets-v12

 FEATURES
 -------------------------------------------------------------
 Real SIEM server
 Real monitored agents
 Real threat IP locations
 Real attack arcs
 Real endpoint links
 Heat layer
 Radar sweep
 Clickable markers
 Live refresh
 Satellite mode
 India view
 Global view
==============================================================
*/


/* ============================================================
   GLOBAL STATE
============================================================ */

let map = null;

let mapInitialized = false;

let isLive = true;

let isSatellite = false;

let liveInterval = null;

let refreshInProgress = false;

let radarTimer = null;

let radarAngle = 0;


/* ============================================================
   REAL MAP DATA
============================================================ */

let realDevices = [];

let realThreats = [];

let realAlerts = [];


/* ============================================================
   API SERVER
============================================================ */

/*
 * IMPORTANT:
 *
 * Dashboard already uses this API server.
 *
 * World Map must use the SAME backend.
 */

const API_BASE =
    "http://100.90.174.77:5000";


/* ============================================================
   MAPBOX TOKEN
============================================================ */

function getMapboxToken() {
    return window.MAPBOX_TOKEN ||
        localStorage.getItem('siem_mapbox_token') ||
        "";
}

const MAPBOX_TOKEN = getMapboxToken();


/* ============================================================
   MAPBOX STYLES
============================================================ */

const MAPBOX_STYLES = {

    normal:
        "mapbox://styles/mapbox/streets-v12",

    satellite:
        "mapbox://styles/mapbox/satellite-streets-v12"

};


/* ============================================================
   GLOBAL VIEW
============================================================ */

const GLOBAL_VIEW = {

    center: [
        20,
        20
    ],

    zoom: 2

};


/* ============================================================
   INDIA VIEW
============================================================ */

const INDIA_VIEW = {

    center: [
        78.9629,
        20.5937
    ],

    zoom: 4.5

};


/* ============================================================
   SIEM SERVER LOCATION
============================================================ */

const SERVER_LOCATION = {

    lat:
        11.5056,

    lon:
        77.2383,

    city:
        "Sathyamangalam",

    state:
        "Tamil Nadu",

    country:
        "India",

    ip:
        "100.90.174.77"

};


/* ============================================================
   KNOWN AGENT LOCATIONS
============================================================ */

const MANUAL_LOCATIONS = {

    "omen-kali": {

        lat:
            11.0168,

        lon:
            76.9558,

        city:
            "Coimbatore",

        state:
            "Tamil Nadu",

        country:
            "India"

    },


    "kali": {

        lat:
            11.0168,

        lon:
            76.9558,

        city:
            "Coimbatore",

        state:
            "Tamil Nadu",

        country:
            "India"

    },


    /*
     * Dashboard currently shows "zorin"
     */

    "zorin": {

        lat:
            12.9716,

        lon:
            77.5946,

        city:
            "Bangalore",

        state:
            "Karnataka",

        country:
            "India"

    },


    "dell-zorin": {

        lat:
            12.9716,

        lon:
            77.5946,

        city:
            "Bangalore",

        state:
            "Karnataka",

        country:
            "India"

    },


    "edge-gw01": {

        lat:
            19.0760,

        lon:
            72.8777,

        city:
            "Mumbai",

        state:
            "Maharashtra",

        country:
            "India"

    },


    "db-cluster01": {

        lat:
            13.0827,

        lon:
            80.2707,

        city:
            "Chennai",

        state:
            "Tamil Nadu",

        country:
            "India"

    }

};


/* ============================================================
   COLORS
============================================================ */

const COLORS = {

    server:
        "#00e5ff",

    online:
        "#00f5a0",

    warning:
        "#facc15",

    offline:
        "#ff4757",

    threat:
        "#ff3158",

    link:
        "#38bdf8",

    heat:
        "#ff3158",

    radar:
        "#00e5ff"

};


/* ============================================================
   LAYER VISIBILITY
============================================================ */

const layerVisibility = {

    links:
        true,

    threats:
        true,

    heat:
        true,

    radar:
        true

};


/* ============================================================
   HTML ESCAPE
============================================================ */

function escapeHTML(
    value
) {

    return String(
        value ?? ""
    )

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );

}


/* ============================================================
   VALID COORDINATE
============================================================ */

function validCoordinate(
    lat,
    lon
) {

    const latitude =
        Number(lat);

    const longitude =
        Number(lon);


    return (

        Number.isFinite(latitude) &&

        Number.isFinite(longitude) &&

        latitude >= -90 &&

        latitude <= 90 &&

        longitude >= -180 &&

        longitude <= 180

    );

}


/* ============================================================
   NORMALIZE STATUS
============================================================ */

function normalizeStatus(
    status
) {

    const value =
        String(
            status ||
            "online"
        )
            .toLowerCase();


    if (

        value.includes(
            "offline"
        ) ||

        value.includes(
            "down"
        ) ||

        value.includes(
            "dead"
        )

    ) {

        return "offline";

    }


    if (

        value.includes(
            "warning"
        ) ||

        value.includes(
            "warn"
        ) ||

        value.includes(
            "degraded"
        ) ||

        value.includes(
            "alert"
        )

    ) {

        return "warning";

    }


    return "online";

}


/* ============================================================
   API FETCH
============================================================ */

async function fetchAPI(
    endpoint
) {

    const url =
        `${API_BASE}${endpoint}`;


    try {

        const response =
            await fetch(
                url,
                {

                    method:
                        "GET",

                    cache:
                        "no-store",

                    headers: {

                        "Accept":
                            "application/json",

                        "Cache-Control":
                            "no-cache"

                    }

                }
            );


        if (
            !response.ok
        ) {

            throw new Error(
                `${endpoint} HTTP ${response.status}`
            );

        }


        return await response.json();

    }

    catch (error) {

        console.error(
            `[SIEM API] ${endpoint}`,
            error
        );


        return null;

    }

}


/* ============================================================
   FETCH ALL REAL DATA
============================================================ */

async function fetchAllRealData() {

    const result = {

        agents:
            [],

        alerts:
            [],

        threats:
            [],

        threatMap:
            null

    };


    /*
     * Fetch everything independently.
     *
     * One endpoint failing should NOT destroy
     * the other data.
     */

    const [

        agents,

        alerts,

        threats,

        threatMap

    ] = await Promise.all([

        fetchAPI(
            "/api/agents"
        ),

        fetchAPI(
            "/api/alerts"
        ),

        fetchAPI(
            "/api/threats"
        ),

        fetchAPI(
            "/api/threat-map"
        )

    ]);


    if (
        Array.isArray(
            agents
        )
    ) {

        result.agents =
            agents;

    }


    if (
        Array.isArray(
            alerts
        )
    ) {

        result.alerts =
            alerts;

    }


    if (
        Array.isArray(
            threats
        )
    ) {

        result.threats =
            threats;

    }


    if (
        threatMap &&
        typeof threatMap ===
            "object"
    ) {

        result.threatMap =
            threatMap;

    }


    return result;

}


/* ============================================================
   GET MANUAL LOCATION
============================================================ */

function getManualLocation(
    agentId
) {

    if (!agentId) {

        return null;

    }


    const exact =
        MANUAL_LOCATIONS[
            agentId
        ];


    if (exact) {

        return exact;

    }


    const lower =
        String(
            agentId
        )
            .toLowerCase();


    if (
        MANUAL_LOCATIONS[
            lower
        ]
    ) {

        return MANUAL_LOCATIONS[
            lower
        ];

    }


    if (
        lower.includes(
            "kali"
        )
    ) {

        return MANUAL_LOCATIONS[
            "kali"
        ];

    }


    if (
        lower.includes(
            "zorin"
        )
    ) {

        return MANUAL_LOCATIONS[
            "zorin"
        ];

    }


    if (
        lower.includes(
            "server"
        )
    ) {

        return {

            lat:
                SERVER_LOCATION.lat,

            lon:
                SERVER_LOCATION.lon,

            city:
                SERVER_LOCATION.city,

            state:
                SERVER_LOCATION.state,

            country:
                SERVER_LOCATION.country

        };

    }


    return null;

}


/* ============================================================
   BUILD DEVICES
============================================================ */

function buildDevices(
    rawAgents,
    threatMap
) {

    const deviceMap =
        {};


    /*
     * ALWAYS add SIEM server.
     */

    deviceMap[
        "siem-server"
    ] = {

        id:
            "siem-server",

        name:
            "SIEM Core Server",

        hostname:
            "SIEM Server",

        type:
            "server",

        status:
            "online",

        ip:
            SERVER_LOCATION.ip,

        os:
            "Ubuntu Linux",

        lat:
            SERVER_LOCATION.lat,

        lon:
            SERVER_LOCATION.lon,

        city:
            SERVER_LOCATION.city,

        state:
            SERVER_LOCATION.state,

        country:
            SERVER_LOCATION.country

    };


    /*
     * Add real agents.
     */

    if (
        Array.isArray(
            rawAgents
        )
    ) {

        rawAgents.forEach(
            agent => {

                const id =

                    agent.agent_id ||

                    agent.id ||

                    agent.hostname;


                if (!id) {

                    return;

                }


                const manual =
                    getManualLocation(
                        id
                    );


                let lat =
                    Number(
                        agent.lat
                    );


                let lon =
                    Number(
                        agent.lon
                    );


                let city =
                    agent.city ||
                    "Unknown";


                let state =
                    agent.state ||
                    agent.region ||
                    "Unknown";


                let country =
                    agent.country ||
                    "Unknown";


                /*
                 * Private/Tailscale agents:
                 * use known static location.
                 */

                if (manual) {

                    lat =
                        manual.lat;

                    lon =
                        manual.lon;

                    city =
                        manual.city;

                    state =
                        manual.state;

                    country =
                        manual.country;

                }


                /*
                 * If backend didn't provide
                 * location, use safe India fallback.
                 */

                if (
                    !validCoordinate(
                        lat,
                        lon
                    )
                ) {

                    lat =
                        SERVER_LOCATION.lat;

                    lon =
                        SERVER_LOCATION.lon;

                    city =
                        SERVER_LOCATION.city;

                    state =
                        SERVER_LOCATION.state;

                    country =
                        SERVER_LOCATION.country;

                }


                deviceMap[id] = {

                    id:

                        id,

                    name:

                        agent.hostname ||

                        agent.agent_id ||

                        id,

                    hostname:

                        agent.hostname ||

                        agent.agent_id ||

                        id,

                    type:

                        "agent",

                    status:

                        normalizeStatus(
                            agent.status
                        ),

                    ip:

                        agent.ip_address ||

                        agent.ip ||

                        "Unknown",

                    os:

                        agent.os ||

                        "Linux",

                    lat,

                    lon,

                    city,

                    state,

                    country,

                    version:

                        agent.version ||

                        "Unknown",

                    last_seen:

                        agent.last_seen ||

                        null

                };

            }
        );

    }


    /*
     * If /api/threat-map contains agents,
     * merge them too.
     */

    if (
        threatMap &&
        Array.isArray(
            threatMap.agents
        )
    ) {

        threatMap.agents.forEach(
            agent => {

                const id =

                    agent.agent_id ||

                    agent.id ||

                    agent.hostname;


                if (
                    !id ||
                    deviceMap[id]
                ) {

                    return;

                }


                const manual =
                    getManualLocation(
                        id
                    );


                const location =
                    agent.location ||
                    {};


                let lat =
                    Number(
                        location.lat ??
                        agent.lat
                    );


                let lon =
                    Number(
                        location.lon ??
                        agent.lon
                    );


                if (manual) {

                    lat =
                        manual.lat;

                    lon =
                        manual.lon;

                }


                if (
                    !validCoordinate(
                        lat,
                        lon
                    )
                ) {

                    return;

                }


                deviceMap[id] = {

                    id,

                    name:
                        agent.hostname ||
                        agent.agent_id ||
                        id,

                    hostname:
                        agent.hostname ||
                        agent.agent_id ||
                        id,

                    type:
                        "agent",

                    status:
                        normalizeStatus(
                            agent.status
                        ),

                    ip:
                        agent.ip_address ||
                        agent.ip ||
                        location.ip ||
                        "Unknown",

                    os:
                        agent.os ||
                        "Linux",

                    lat,

                    lon,

                    city:
                        manual
                            ? manual.city
                            : (
                                location.city ||
                                "Unknown"
                            ),

                    state:
                        manual
                            ? manual.state
                            : (
                                location.state ||
                                location.region ||
                                "Unknown"
                            ),

                    country:
                        manual
                            ? manual.country
                            : (
                                location.country ||
                                "Unknown"
                            )

                };

            }
        );

    }


    return Object.values(
        deviceMap
    );

}


/* ============================================================
   BUILD THREATS
============================================================ */

function buildThreats(
    rawThreats,
    rawAlerts,
    threatMap
) {

    const threats =
        [];


    const seen =
        new Set();


    /*
     * --------------------------------------------------------
     * 1. /api/threat-map threats
     * --------------------------------------------------------
     */

    if (
        threatMap &&
        Array.isArray(
            threatMap.threats
        )
    ) {

        threatMap.threats.forEach(
            (item, index) => {

                const location =
                    item.location ||
                    item;


                const lat =
                    Number(
                        location.lat
                    );


                const lon =
                    Number(
                        location.lon
                    );


                if (
                    !validCoordinate(
                        lat,
                        lon
                    )
                ) {

                    return;

                }


                const ip =

                    location.ip ||

                    item.ip ||

                    item.source_ip ||

                    "Unknown";


                const key =
                    `${ip}-${lat}-${lon}`;


                if (
                    seen.has(
                        key
                    )
                ) {

                    return;

                }


                seen.add(
                    key
                );


                threats.push({

                    id:
                        item.id ||
                        `map-${index}`,

                    ip,

                    lat,

                    lon,

                    city:
                        location.city ||
                        item.city ||
                        "Unknown",

                    state:
                        location.region ||
                        location.regionName ||
                        item.region ||
                        "Unknown",

                    country:
                        location.country ||
                        item.country ||
                        "Unknown",

                    isp:
                        location.isp ||
                        item.isp ||
                        "Unknown",

                    org:
                        location.org ||
                        item.org ||
                        "Unknown",

                    type:
                        item.type ||
                        item.name ||
                        "Cyber Attack",

                    severity:
                        item.severity ||
                        "HIGH",

                    status:
                        item.status ||
                        "OPEN",

                    timestamp:
                        item.timestamp ||
                        null

                });

            }
        );

    }


    /*
     * --------------------------------------------------------
     * 2. /api/threats
     * --------------------------------------------------------
     */

    if (
        Array.isArray(
            rawThreats
        )
    ) {

        rawThreats.forEach(
            (item, index) => {

                const location =
                    item.location ||
                    item;


                const lat =
                    Number(
                        location.lat
                    );


                const lon =
                    Number(
                        location.lon
                    );


                if (
                    !validCoordinate(
                        lat,
                        lon
                    )
                ) {

                    return;

                }


                const ip =

                    location.ip ||

                    item.ip ||

                    item.source_ip ||

                    "Unknown";


                const key =
                    `${ip}-${lat}-${lon}`;


                if (
                    seen.has(
                        key
                    )
                ) {

                    return;

                }


                seen.add(
                    key
                );


                threats.push({

                    id:
                        item.id ||
                        `threat-${index}`,

                    ip,

                    lat,

                    lon,

                    city:
                        location.city ||
                        item.city ||
                        "Unknown",

                    state:
                        location.region ||
                        item.region ||
                        "Unknown",

                    country:
                        location.country ||
                        item.country ||
                        "Unknown",

                    isp:
                        location.isp ||
                        item.isp ||
                        "Unknown",

                    org:
                        location.org ||
                        item.org ||
                        "Unknown",

                    type:
                        item.type ||
                        item.name ||
                        item.alert_type ||
                        "Cyber Attack",

                    severity:
                        item.severity ||
                        "HIGH",

                    status:
                        item.status ||
                        "OPEN",

                    timestamp:
                        item.timestamp ||
                        null

                });

            }
        );

    }


    /*
     * --------------------------------------------------------
     * 3. Alerts
     *
     * Alerts may contain source IP but not coordinates.
     * If alert already contains lat/lon, use them.
     * --------------------------------------------------------
     */

    if (
        Array.isArray(
            rawAlerts
        )
    ) {

        rawAlerts.forEach(
            (alert, index) => {

                const lat =
                    Number(
                        alert.lat ??
                        alert.latitude
                    );


                const lon =
                    Number(
                        alert.lon ??
                        alert.longitude
                    );


                if (
                    !validCoordinate(
                        lat,
                        lon
                    )
                ) {

                    return;

                }


                const ip =

                    alert.source_ip ||

                    alert.src_ip ||

                    alert.ip ||

                    "Unknown";


                const key =
                    `${ip}-${lat}-${lon}`;


                if (
                    seen.has(
                        key
                    )
                ) {

                    return;

                }


                seen.add(
                    key
                );


                threats.push({

                    id:
                        alert.id ||
                        `alert-${index}`,

                    ip,

                    lat,

                    lon,

                    city:
                        alert.city ||
                        "Unknown",

                    state:
                        alert.state ||
                        alert.region ||
                        "Unknown",

                    country:
                        alert.country ||
                        "Unknown",

                    isp:
                        alert.isp ||
                        "Unknown",

                    org:
                        alert.org ||
                        "Unknown",

                    type:
                        alert.rule_name ||
                        alert.alert_type ||
                        alert.type ||
                        "Security Alert",

                    severity:
                        alert.severity ||
                        "HIGH",

                    status:
                        alert.status ||
                        "OPEN",

                    timestamp:
                        alert.timestamp ||
                        alert.created_at ||
                        null

                });

            }
        );

    }


    return threats;

}


/* ============================================================
   BUILD REAL MAP DATA
============================================================ */

async function buildMapData() {

    const {

        agents,

        alerts,

        threats,

        threatMap

    } = await fetchAllRealData();


    realAlerts =
        alerts;


    realDevices =
        buildDevices(
            agents,
            threatMap
        );


    realThreats =
        buildThreats(
            threats,
            alerts,
            threatMap
        );


    /*
     * If threat-map itself contains server location,
     * prefer it.
     */

    if (
        threatMap &&
        threatMap.server
    ) {

        const server =
            threatMap.server;


        const location =
            server.location ||
            server;


        if (
            validCoordinate(
                location.lat,
                location.lon
            )
        ) {

            const serverDevice =
                realDevices.find(
                    d =>
                        d.id ===
                        "siem-server"
                );


            if (serverDevice) {

                serverDevice.lat =
                    Number(
                        location.lat
                    );

                serverDevice.lon =
                    Number(
                        location.lon
                    );

                serverDevice.city =
                    location.city ||
                    serverDevice.city;

                serverDevice.state =
                    location.state ||
                    location.region ||
                    serverDevice.state;

                serverDevice.country =
                    location.country ||
                    serverDevice.country;

                serverDevice.ip =
                    location.ip ||
                    server.ip ||
                    serverDevice.ip;

            }

        }

    }


    console.log(
        "[SIEM MAP] REAL DATA",
        {

            agents:
                realDevices.length,

            threats:
                realThreats.length,

            alerts:
                realAlerts.length,

            api:
                API_BASE

        }
    );

}


/* ============================================================
   PROJECT GEO COORDINATE
============================================================ */

function project(
    lon,
    lat
) {

    if (
        !map ||
        !validCoordinate(
            lat,
            lon
        )
    ) {

        return null;

    }


    const point =
        map.project([
            Number(lon),
            Number(lat)
        ]);


    return {

        x:
            point.x,

        y:
            point.y

    };

}


/* ============================================================
   SVG ELEMENT
============================================================ */

function svgElement(
    tag,
    attributes
) {

    const element =
        document.createElementNS(
            "http://www.w3.org/2000/svg",
            tag
        );


    Object.entries(
        attributes
    )
        .forEach(
            ([key, value]) => {

                element.setAttribute(
                    key,
                    value
                );

            }
        );


    return element;

}


/* ============================================================
   CLEAR SVG GROUP
============================================================ */

function clearGroup(
    id
) {

    const group =
        document.getElementById(
            id
        );


    if (group) {

        group.innerHTML =
            "";

    }

}


/* ============================================================
   RESIZE SVG
============================================================ */

function resizeSVG() {

    const svg =
        document.getElementById(
            "svgOverlay"
        );


    const mapContainer =
        document.getElementById(
            "worldMap"
        );


    if (
        !svg ||
        !mapContainer
    ) {

        return;

    }


    svg.setAttribute(
        "width",
        mapContainer.clientWidth
    );


    svg.setAttribute(
        "height",
        mapContainer.clientHeight
    );

}


/* ============================================================
   ARC PATH
============================================================ */

function arcPath(
    source,
    target
) {

    const dx =
        target.x -
        source.x;


    const dy =
        target.y -
        source.y;


    const distance =
        Math.sqrt(
            dx * dx +
            dy * dy
        );


    if (
        distance < 5
    ) {

        return `
            M ${source.x}
              ${source.y}

            L ${target.x}
              ${target.y}
        `;

    }


    const midX =
        (
            source.x +
            target.x
        ) / 2;


    const midY =
        (
            source.y +
            target.y
        ) / 2;


    const curve =
        Math.min(
            140,
            Math.max(
                35,
                distance * 0.20
            )
        );


    return `
        M ${source.x}
          ${source.y}

        Q ${midX}
          ${midY - curve}

          ${target.x}
          ${target.y}
    `;

}


/* ============================================================
   DRAW HEAT
============================================================ */

function drawHeat() {

    const group =
        document.getElementById(
            "gHeat"
        );


    if (!group) return;


    group.innerHTML =
        "";


    if (
        !layerVisibility.heat
    ) {

        return;

    }


    realThreats.forEach(
        threat => {

            const point =
                project(
                    threat.lon,
                    threat.lat
                );


            if (!point) return;


            const circle =
                svgElement(
                    "circle",
                    {

                        cx:
                            point.x,

                        cy:
                            point.y,

                        r:
                            35,

                        class:
                            "heat-circle"

                    }
                );


            group.appendChild(
                circle
            );

        }
    );

}


/* ============================================================
   DRAW ENDPOINT LINKS
============================================================ */

function drawLinks() {

    const group =
        document.getElementById(
            "gLinks"
        );


    if (!group) return;


    group.innerHTML =
        "";


    if (
        !layerVisibility.links
    ) {

        return;

    }


    const server =
        realDevices.find(
            device =>
                device.type ===
                "server"
        );


    if (!server) {

        return;

    }


    const serverPoint =
        project(
            server.lon,
            server.lat
        );


    if (!serverPoint) {

        return;

    }


    realDevices

        .filter(
            device =>
                device.type !==
                "server"
        )

        .forEach(
            device => {

                const point =
                    project(
                        device.lon,
                        device.lat
                    );


                if (!point) {

                    return;

                }


                const line =
                    svgElement(
                        "line",
                        {

                            x1:
                                point.x,

                            y1:
                                point.y,

                            x2:
                                serverPoint.x,

                            y2:
                                serverPoint.y,

                            stroke:
                                COLORS.link,

                            "stroke-width":
                                "1.2",

                            "stroke-dasharray":
                                "6 6",

                            opacity:
                                "0.55"

                        }
                    );


                group.appendChild(
                    line
                );

            }
        );

}


/* ============================================================
   DRAW THREATS
============================================================ */

function drawThreats() {

    const group =
        document.getElementById(
            "gThreats"
        );


    if (!group) return;


    group.innerHTML =
        "";


    if (
        !layerVisibility.threats
    ) {

        return;

    }


    const server =
        realDevices.find(
            device =>
                device.type ===
                "server"
        );


    if (!server) {

        return;

    }


    const serverPoint =
        project(
            server.lon,
            server.lat
        );


    if (!serverPoint) {

        return;

    }


    realThreats.forEach(
        threat => {

            const threatPoint =
                project(
                    threat.lon,
                    threat.lat
                );


            if (!threatPoint) {

                return;

            }


            /*
             * ATTACK ARC
             */

            const arc =
                svgElement(
                    "path",
                    {

                        d:
                            arcPath(
                                threatPoint,
                                serverPoint
                            ),

                        class:
                            "threat-arc"

                    }
                );


            group.appendChild(
                arc
            );


            /*
             * OUTER PULSE
             */

            const pulse =
                svgElement(
                    "circle",
                    {

                        cx:
                            threatPoint.x,

                        cy:
                            threatPoint.y,

                        r:
                            "9",

                        class:
                            "threat-pulse"

                    }
                );


            group.appendChild(
                pulse
            );


            /*
             * THREAT NODE
             */

            const node =
                svgElement(
                    "circle",
                    {

                        cx:
                            threatPoint.x,

                        cy:
                            threatPoint.y,

                        r:
                            "5",

                        class:
                            "threat-point"

                    }
                );


            node.addEventListener(
                "click",
                event => {

                    event.stopPropagation();

                    showThreatPopup(
                        threat
                    );

                }
            );


            group.appendChild(
                node
            );

        }
    );

}


/* ============================================================
   DRAW RADAR
============================================================ */

function drawRadar() {

    const group =
        document.getElementById(
            "gRadar"
        );


    if (!group) return;


    group.innerHTML =
        "";


    if (
        !layerVisibility.radar
    ) {

        return;

    }


    const server =
        realDevices.find(
            device =>
                device.type ===
                "server"
        );


    if (!server) {

        return;

    }


    const point =
        project(
            server.lon,
            server.lat
        );


    if (!point) {

        return;

    }


    [
        18,
        35,
        52,
        68
    ]
        .forEach(
            radius => {

                const ring =
                    svgElement(
                        "circle",
                        {

                            cx:
                                point.x,

                            cy:
                                point.y,

                            r:
                                radius,

                            class:
                                "radar-ring"

                        }
                    );


                group.appendChild(
                    ring
                );

            }
        );


    const radians =
        radarAngle *
        Math.PI /
        180;


    const radius =
        68;


    const x2 =
        point.x +
        Math.cos(
            radians
        ) *
        radius;


    const y2 =
        point.y +
        Math.sin(
            radians
        ) *
        radius;


    const sweep =
        svgElement(
            "line",
            {

                x1:
                    point.x,

                y1:
                    point.y,

                x2,

                y2,

                class:
                    "radar-line"

            }
        );


    group.appendChild(
        sweep
    );

}


/* ============================================================
   DRAW MARKERS
============================================================ */

function drawMarkers() {

    const group =
        document.getElementById(
            "gMarkers"
        );


    if (!group) return;


    group.innerHTML =
        "";


    realDevices.forEach(
        device => {

            const point =
                project(
                    device.lon,
                    device.lat
                );


            if (!point) {

                return;

            }


            /*
             * SERVER
             */

            if (
                device.type ===
                "server"
            ) {

                const pulse =
                    svgElement(
                        "circle",
                        {

                            cx:
                                point.x,

                            cy:
                                point.y,

                            r:
                                14,

                            class:
                                "server-pulse"

                        }
                    );


                group.appendChild(
                    pulse
                );


                const marker =
                    svgElement(
                        "circle",
                        {

                            cx:
                                point.x,

                            cy:
                                point.y,

                            r:
                                6,

                            class:
                                "server-point"

                        }
                    );


                marker.addEventListener(
                    "click",
                    event => {

                        event.stopPropagation();

                        showServerPopup(
                            device
                        );

                    }
                );


                group.appendChild(
                    marker
                );


                return;

            }


            /*
             * AGENT
             */

            let className =
                "agent-point agent-online";


            if (
                device.status ===
                "warning"
            ) {

                className =
                    "agent-point agent-warning";

            }


            if (
                device.status ===
                "offline"
            ) {

                className =
                    "agent-point agent-offline";

            }


            const marker =
                svgElement(
                    "circle",
                    {

                        cx:
                            point.x,

                        cy:
                            point.y,

                        r:
                            5,

                        class:
                            className

                    }
                );


            marker.addEventListener(
                "click",
                event => {

                    event.stopPropagation();

                    showAgentPopup(
                        device
                    );

                }
            );


            group.appendChild(
                marker
            );

        }
    );

}


/* ============================================================
   DRAW LABELS
============================================================ */

function drawLabels() {

    const group =
        document.getElementById(
            "gLabels"
        );


    if (!group) return;


    group.innerHTML =
        "";


    realDevices.forEach(
        device => {

            const point =
                project(
                    device.lon,
                    device.lat
                );


            if (!point) {

                return;

            }


            const label =
                svgElement(
                    "text",
                    {

                        x:
                            point.x + 9,

                        y:
                            point.y - 9,

                        class:
                            "map-label"

                    }
                );


            label.textContent =

                device.type ===
                "server"

                    ? "SIEM SERVER"

                    : (
                        device.hostname ||
                        device.name
                    );


            group.appendChild(
                label
            );

        }
    );

}


/* ============================================================
   DRAW ALL
============================================================ */

function drawAll() {

    if (
        !map ||
        !mapInitialized
    ) {

        return;

    }


    resizeSVG();


    clearGroup(
        "gHeat"
    );


    clearGroup(
        "gLinks"
    );


    clearGroup(
        "gThreats"
    );


    clearGroup(
        "gRadar"
    );


    clearGroup(
        "gMarkers"
    );


    clearGroup(
        "gLabels"
    );


    drawHeat();

    drawLinks();

    drawThreats();

    drawRadar();

    drawMarkers();

    drawLabels();

}


/* ============================================================
   UPDATE STATISTICS
============================================================ */

function updateStats() {

    const agents =
        realDevices.filter(
            device =>
                device.type !==
                "server"
        );


    const online =
        agents.filter(
            device =>
                device.status ===
                "online"
        ).length;


    const warning =
        agents.filter(
            device =>
                device.status ===
                "warning"
        ).length;


    const offline =
        agents.filter(
            device =>
                device.status ===
                "offline"
        ).length;


    const countries =
        new Set();


    realDevices.forEach(
        device => {

            if (
                device.country
            ) {

                countries.add(
                    device.country
                );

            }

        }
    );


    realThreats.forEach(
        threat => {

            if (
                threat.country
            ) {

                countries.add(
                    threat.country
                );

            }

        }
    );


    setText(
        "mapCountryCount",
        countries.size
    );


    setText(
        "mapOnlineDevices",
        online
    );


    setText(
        "mapThreatCount",
        realThreats.length
    );


    setText(
        "mapOnlineCount",
        online
    );


    setText(
        "mapWarningCount",
        warning
    );


    setText(
        "mapOfflineCount",
        offline
    );


    setText(
        "mapThreatCountLabel",
        realThreats.length
    );


    /*
     * Perimeter health
     */

    const total =
        agents.length;


    const protectedPercentage =

        total === 0

            ? 100

            : Math.round(
                (
                    online /
                    total
                ) * 100
            );


    setText(
        "mapProtectedCount",
        `${protectedPercentage}%`
    );


    const status =
        document.getElementById(
            "protectedStatus"
        );


    if (status) {

        if (
            protectedPercentage >=
            80
        ) {

            status.textContent =
                "🟢 Secure";

        }

        else if (
            protectedPercentage >=
            50
        ) {

            status.textContent =
                "🟠 Elevated";

        }

        else {

            status.textContent =
                "🔴 Critical";

        }

    }


    /*
     * Sidebar badge
     */

    const badge =
        document.getElementById(
            "alertBadge"
        );


    if (badge) {

        badge.textContent =

            realThreats.length >
            99

                ? "99+"

                : realThreats.length;

    }

}


/* ============================================================
   SET TEXT
============================================================ */

function setText(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );


    if (element) {

        element.textContent =
            value;

    }

}


/* ============================================================
   UPDATE ZOOM
============================================================ */

function updateZoomBadge() {

    if (!map) {

        return;

    }


    const badge =
        document.getElementById(
            "zoomBadge"
        );


    if (!badge) {

        return;

    }


    const zoom =
        map.getZoom();


    let label =
        "Global";


    if (
        zoom >= 3.5
    ) {

        label =
            "Regional";

    }


    if (
        zoom >= 4.5
    ) {

        label =
            "India Core";

    }


    badge.textContent =
        `ZOOM: ${zoom.toFixed(1)} | ${label}`;

}


/* ============================================================
   UPDATE TIME
============================================================ */

function updateTime() {

    const now =
        new Date();


    const time =
        now.toLocaleTimeString(
            [],
            {

                hour:
                    "2-digit",

                minute:
                    "2-digit",

                second:
                    "2-digit"

            }
        );


    setText(
        "lastUpdate",
        time
    );


    const status =
        document.getElementById(
            "statusBarRight"
        );


    if (status) {

        status.textContent =
            `Last scan: ${time}`;

    }

}


/* ============================================================
   SERVER POPUP
============================================================ */

function showServerPopup(
    server
) {

    if (!map) {

        return;

    }


    new mapboxgl.Popup({

        closeButton:
            true,

        maxWidth:
            "320px"

    })

        .setLngLat([
            server.lon,
            server.lat
        ])

        .setHTML(`

            <div class="map-popup">

                <div
                    class="
                        map-popup-title
                        server
                    "
                >

                    <i
                        class="fas fa-server"
                    ></i>

                    SIEM Core Server

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Location
                    </span>

                    <span>
                        ${escapeHTML(
                            server.city
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        State
                    </span>

                    <span>
                        ${escapeHTML(
                            server.state
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Country
                    </span>

                    <span>
                        ${escapeHTML(
                            server.country
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        IP
                    </span>

                    <span>
                        ${escapeHTML(
                            server.ip
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Status
                    </span>

                    <span
                        style="
                            color:#00f5a0;
                            font-weight:700;
                        "
                    >
                        ONLINE
                    </span>

                </div>

            </div>

        `)

        .addTo(map);

}


/* ============================================================
   AGENT POPUP
============================================================ */

function showAgentPopup(
    agent
) {

    if (!map) {

        return;

    }


    let statusColor =
        COLORS.online;


    if (
        agent.status ===
        "warning"
    ) {

        statusColor =
            COLORS.warning;

    }


    if (
        agent.status ===
        "offline"
    ) {

        statusColor =
            COLORS.offline;

    }


    new mapboxgl.Popup({

        closeButton:
            true,

        maxWidth:
            "320px"

    })

        .setLngLat([
            agent.lon,
            agent.lat
        ])

        .setHTML(`

            <div class="map-popup">

                <div
                    class="
                        map-popup-title
                        agent
                    "
                >

                    <i
                        class="
                            fas
                            fa-desktop
                        "
                    ></i>

                    ${escapeHTML(
                        agent.hostname ||
                        agent.name
                    )}

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Agent ID
                    </span>

                    <span>
                        ${escapeHTML(
                            agent.id
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        IP
                    </span>

                    <span>
                        ${escapeHTML(
                            agent.ip
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Location
                    </span>

                    <span>
                        ${escapeHTML(
                            agent.city
                        )},
                        ${escapeHTML(
                            agent.country
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        OS
                    </span>

                    <span>
                        ${escapeHTML(
                            agent.os
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Status
                    </span>

                    <span
                        style="
                            color:${statusColor};
                            font-weight:700;
                        "
                    >
                        ${escapeHTML(
                            agent.status
                        ).toUpperCase()}
                    </span>

                </div>

            </div>

        `)

        .addTo(map);

}


/* ============================================================
   THREAT POPUP
============================================================ */

function showThreatPopup(
    threat
) {

    if (!map) {

        return;

    }


    new mapboxgl.Popup({

        closeButton:
            true,

        maxWidth:
            "330px"

    })

        .setLngLat([
            threat.lon,
            threat.lat
        ])

        .setHTML(`

            <div class="map-popup">

                <div
                    class="
                        map-popup-title
                        threat
                    "
                >

                    <i
                        class="
                            fas
                            fa-skull-crossbones
                        "
                    ></i>

                    Threat Actor

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Source IP
                    </span>

                    <span>
                        ${escapeHTML(
                            threat.ip
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Location
                    </span>

                    <span>
                        ${escapeHTML(
                            threat.city
                        )},
                        ${escapeHTML(
                            threat.country
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Attack
                    </span>

                    <span>
                        ${escapeHTML(
                            threat.type
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Severity
                    </span>

                    <span
                        style="
                            color:#ff4757;
                            font-weight:700;
                        "
                    >
                        ${escapeHTML(
                            threat.severity
                        )}
                    </span>

                </div>


                <div
                    class="map-popup-row"
                >

                    <span>
                        Status
                    </span>

                    <span>
                        ${escapeHTML(
                            threat.status
                        )}
                    </span>

                </div>

            </div>

        `)

        .addTo(map);

}


/* ============================================================
   REFRESH REAL DATA
============================================================ */

async function refreshMapData() {

    if (
        refreshInProgress
    ) {

        return;

    }


    refreshInProgress =
        true;


    try {

        await buildMapData();


        updateStats();

        updateTime();


        if (map) {

            drawAll();

        }


        console.log(
            "[SIEM MAP] Updated",
            {

                devices:
                    realDevices.length,

                threats:
                    realThreats.length,

                alerts:
                    realAlerts.length

            }
        );

    }

    catch (error) {

        console.error(
            "[SIEM MAP] Refresh failed:",
            error
        );

    }

    finally {

        refreshInProgress =
            false;

    }

}


/* ============================================================
   RADAR ANIMATION
============================================================ */

function startRadar() {

    stopRadar();


    radarTimer =
        setInterval(
            () => {

                if (
                    layerVisibility.radar
                ) {

                    radarAngle += 4;


                    if (
                        radarAngle >=
                        360
                    ) {

                        radarAngle =
                            0;

                    }


                    drawRadar();

                }

            },
            60
        );

}


function stopRadar() {

    if (radarTimer) {

        clearInterval(
            radarTimer
        );


        radarTimer =
            null;

    }

}


/* ============================================================
   INITIALIZE MAP
============================================================ */

async function initMap() {

    const container =
        document.getElementById(
            "worldMap"
        );


    if (!container) {

        console.error(
            "[SIEM MAP] #worldMap not found"
        );

        return;

    }


    if (map) {

        return;

    }


    if (
        typeof mapboxgl ===
        "undefined"
    ) {

        console.error(
            "[SIEM MAP] Mapbox GL JS not loaded"
        );

        return;

    }


    const resolvedToken = getMapboxToken();
    if (!resolvedToken || !resolvedToken.startsWith("pk.")) {
        console.error(
            "[SIEM MAP] Invalid or missing Mapbox token. Ensure MAPBOX_PUBLIC_TOKEN is configured in .env or ui/js/config.js."
        );
        const mapContainer = document.getElementById("worldMap");
        if (mapContainer) {
            mapContainer.innerHTML = `
                <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#ff4757;font-family:monospace;text-align:center;padding:24px;background:#030814;">
                    <i class="fas fa-shield-halved" style="font-size:2.4rem;color:#38bdf8;margin-bottom:14px;"></i>
                    <strong style="font-size:1.15rem;color:#f8fafc;">Mapbox Public Token Required</strong>
                    <p style="color:#94a3b8;font-size:0.85rem;max-width:500px;margin:10px 0 18px;line-height:1.5;">
                        To render the interactive 3D threat map, configure your public token (<code>pk.*</code>) in <code>ui/js/config.js</code>, the root <code>.env</code> file, or via SOC Settings.
                    </p>
                    <a href="settings.html" style="background:#00f5a0;color:#030814;padding:8px 18px;border-radius:6px;font-weight:700;text-decoration:none;font-size:0.8rem;">Open SOC Settings</a>
                </div>`;
        }
        return;
    }

    mapboxgl.accessToken = resolvedToken;


    /*
     * CREATE MAP
     */

    map =
        new mapboxgl.Map({

            container:
                "worldMap",

            style:
                MAPBOX_STYLES.normal,

            center:
                GLOBAL_VIEW.center,

            zoom:
                GLOBAL_VIEW.zoom,

            minZoom:
                1.5,

            maxZoom:
                14,

            projection:
                "mercator",

            renderWorldCopies:
                false,

            attributionControl:
                true

        });


    /*
     * NAVIGATION
     */

    map.addControl(

        new mapboxgl.NavigationControl({

            showZoom:
                true,

            showCompass:
                true

        }),

        "top-right"

    );


    /*
     * MAP LOAD
     */

    map.on(
        "load",
        async () => {

            console.log(
                "[SIEM MAP] Mapbox loaded"
            );


            mapInitialized =
                true;


            map.resize();


            /*
             * FIRST REAL DATA LOAD
             */

            await refreshMapData();


            /*
             * DRAW
             */

            drawAll();


            /*
             * RADAR
             */

            startRadar();


            /*
             * ZOOM
             */

            updateZoomBadge();

        }
    );


    /*
     * MOVE
     */

    map.on(
        "move",
        () => {

            updateZoomBadge();

            drawAll();

        }
    );


    /*
     * RESIZE
     */

    map.on(
        "resize",
        () => {

            drawAll();

        }
    );


    /*
     * ROTATE
     */

    map.on(
        "rotate",
        () => {

            drawAll();

        }
    );


    /*
     * PITCH
     */

    map.on(
        "pitch",
        () => {

            drawAll();

        }
    );


    /*
     * MAPBOX ERRORS
     */

    map.on(
        "error",
        event => {

            console.error(
                "[MAPBOX ERROR]",
                event?.error ||
                event
            );

        }
    );

}


/* ============================================================
   ZOOM IN
============================================================ */

function zoomInMap() {

    if (!map) return;


    map.zoomIn({

        duration:
            400

    });

}


/* ============================================================
   ZOOM OUT
============================================================ */

function zoomOutMap() {

    if (!map) return;


    map.zoomOut({

        duration:
            400

    });

}


/* ============================================================
   GLOBAL VIEW
============================================================ */

function resetView() {

    if (!map) return;


    map.flyTo({

        center:
            GLOBAL_VIEW.center,

        zoom:
            GLOBAL_VIEW.zoom,

        duration:
            900,

        essential:
            true

    });

}


/* ============================================================
   INDIA VIEW
============================================================ */

function flyToIndia() {

    if (!map) return;


    map.flyTo({

        center:
            INDIA_VIEW.center,

        zoom:
            INDIA_VIEW.zoom,

        duration:
            900,

        essential:
            true

    });

}


/* ============================================================
   SATELLITE TOGGLE
============================================================ */

function toggleSatellite() {

    if (!map) return;


    isSatellite =
        !isSatellite;


    const style =
        isSatellite

            ? MAPBOX_STYLES.satellite

            : MAPBOX_STYLES.normal;


    map.setStyle(
        style
    );


    const button =
        document.getElementById(
            "satToggle"
        );


    const label =
        document.getElementById(
            "satLabel"
        );


    if (button) {

        button.classList.toggle(
            "active",
            isSatellite
        );

    }


    if (label) {

        label.textContent =
            isSatellite
                ? "Standard"
                : "Satellite";

    }


    map.once(
        "style.load",
        () => {

            setTimeout(
                () => {

                    drawAll();

                },
                200
            );

        }
    );

}


/* ============================================================
   LAYER TOGGLE
============================================================ */

function toggleLayer(
    layer
) {

    if (
        !Object.prototype.hasOwnProperty.call(
            layerVisibility,
            layer
        )
    ) {

        return;

    }


    layerVisibility[layer] =
        !layerVisibility[layer];


    const buttonIds = {

        links:
            "btnLinks",

        threats:
            "btnThreats",

        heat:
            "btnHeat",

        radar:
            "btnRadar"

    };


    const button =
        document.getElementById(
            buttonIds[layer]
        );


    if (button) {

        button.classList.toggle(
            "active",
            layerVisibility[layer]
        );

    }


    drawAll();

}


/* ============================================================
   LIVE TOGGLE
============================================================ */

function toggleLive() {

    isLive =
        !isLive;


    const label =
        document.getElementById(
            "liveLabel"
        );


    if (label) {

        label.textContent =
            isLive
                ? "LIVE"
                : "PAUSED";

    }


    if (isLive) {

        startLiveRefresh();

        refreshMapData();

    }

    else {

        stopLiveRefresh();

    }

}


/* ============================================================
   LIVE REFRESH
============================================================ */

function startLiveRefresh() {

    stopLiveRefresh();


    liveInterval =
        setInterval(
            () => {

                if (
                    isLive
                ) {

                    refreshMapData();

                }

            },
            5000
        );

}


function stopLiveRefresh() {

    if (liveInterval) {

        clearInterval(
            liveInterval
        );


        liveInterval =
            null;

    }

}


/* ============================================================
   MANUAL FULL RELOAD
============================================================ */

async function fullReload() {

    await refreshMapData();


    if (map) {

        map.resize();

        drawAll();

    }

}


/* ============================================================
   WINDOW RESIZE
============================================================ */

window.addEventListener(
    "resize",
    () => {

        if (map) {

            map.resize();

            drawAll();

        }

    }
);


/* ============================================================
   DOM READY
============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        console.log(
            "[SIEM MAP] Starting World Map..."
        );


        /*
         * Start Mapbox
         */

        initMap();


        /*
         * Start 5-second telemetry
         */

        startLiveRefresh();

    }
);


/* ============================================================
   GLOBAL FUNCTIONS
============================================================ */

window.zoomInMap =
    zoomInMap;


window.zoomOutMap =
    zoomOutMap;


window.resetView =
    resetView;


window.flyToIndia =
    flyToIndia;


window.toggleSatellite =
    toggleSatellite;


window.toggleLayer =
    toggleLayer;


window.toggleLive =
    toggleLive;


window.fullReload =
    fullReload;


/* ============================================================
   DEBUG
============================================================ */

window.SIEM_WORLD_MAP = {

    map:
        () => map,

    devices:
        () => realDevices,

    threats:
        () => realThreats,

    alerts:
        () => realAlerts,

    refresh:
        refreshMapData,

    redraw:
        drawAll

};