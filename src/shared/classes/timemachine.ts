// This file modifies the behavior of Date.now()
// The reason is to solve certain issues with the Ebsi tests that do not validate some tokens
// due to time synchronization. In theory, they should have a clockTolerance that absorbs
// small discrepancies. In the meantime, this solution is proposed. If this solution is no longer necessary,
// simply delete this file and its import in server.ts.

import { SERVER } from "../../shared/config/configuration";

const secondsToFix = SERVER.time_fix;

const originalNow = Date.now;
Date.now = function () {
    return originalNow() + (1000 * secondsToFix);
};