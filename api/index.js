// /api/index.js (Final and Secure Version)

/**
 * SHIB Ads WebApp Backend API
 * Handles all POST requests from the Telegram Mini App frontend.
 * Uses the Supabase REST API for persistence.
 */
const crypto = require('crypto');

// Load environment variables for Supabase connection
const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL;
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;
// ⚠️ BOT_TOKEN must be set in Vercel environment variables
const BOT_TOKEN = process.env.BOT_TOKEN;

// ------------------------------------------------------------------
// Fully secured and defined server-side constants
// ------------------------------------------------------------------
const REWARD_PER_AD = 3;
const REFERRAL_COMMISSION_RATE = 0.05;
const DAILY_MAX_ADS = 100; // Max ads limit
const DAILY_MAX_SPINS = 15; // Max spins limit
const MIN_TIME_BETWEEN_ACTIONS_MS = 3000; // 3 seconds minimum time between watchAd/spin requests
const ACTION_ID_EXPIRY_MS = 60000; // 60 seconds for Action ID to be valid
const SPIN_SECTORS = [5, 10, 15, 20, 5];

/**
 * Helper function to randomly select a prize from the defined sectors and return its index.
 */
function calculateRandomSpinPrize() {
    const randomIndex = Math.floor(Math.random() * SPIN_SECTORS.length);
    const prize = SPIN_SECTORS[randomIndex];
    return { prize, prizeIndex: randomIndex };
}

// --- Helper Functions ---

function sendSuccess(res, data = {}) {
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, data }));
}

function sendError(res, message, statusCode = 400) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: false, error: message }));
}

async function supabaseFetch(tableName, method, body = null, queryParams = '?select=*') {
  if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
    throw new Error('Supabase environment variables are not configured.');
  }

  const url = `${SUPABASE_URL}/rest/v1/${tableName}${queryParams}`;

  const headers = {
    'apikey': SUPABASE_ANON_KEY,
    'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
    'Content-Type': 'application/json',
    'Prefer': 'return=representation'
  };

  const options = {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  };

  const response = await fetch(url, options);

  if (response.ok) {
      const responseText = await response.text();
      try {
          const jsonResponse = JSON.parse(responseText);
          return Array.isArray(jsonResponse) ? jsonResponse : { success: true };
      } catch (e) {
          return { success: true };
      }
  }

  let data;
  try {
      data = await response.json();
  } catch (e) {
      const errorMsg = `Supabase error: ${response.status} ${response.statusText}`;
      throw new Error(errorMsg);
  }

  const errorMsg = data.message || `Supabase error: ${response.status} ${response.statusText}`;
  throw new Error(errorMsg);
}

/**
 * Daily Reset Logic: Resets ad/spin counters if 24 hours passed since last activity.
 */
async function resetDailyLimitsIfExpired(userId) {
    const twentyFourHours = 24 * 60 * 60 * 1000;
    const now = Date.now();

    try {
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${userId}&select=ads_watched_today,spins_today,last_activity`);
        if (!Array.isArray(users) || users.length === 0) {
            return;
        }

        const user = users[0];
        const lastActivity = user.last_activity ? new Date(user.last_activity).getTime() : 0;

        if (now - lastActivity > twentyFourHours) {
            const updatePayload = {};
            if (user.ads_watched_today > 0) {
                updatePayload.ads_watched_today = 0;
            }
            if (user.spins_today > 0) {
                updatePayload.spins_today = 0;
            }

            if (Object.keys(updatePayload).length > 0) {
                console.log(`Resetting limits for user ${userId}.`);
                await supabaseFetch('users', 'PATCH',
                    updatePayload,
                    `?id=eq.${userId}`);
            }
        }
    } catch (error) {
        console.error(`Failed to check/reset daily limits for user ${userId}:`, error.message);
    }
}

/**
 * Rate Limiting Check for Ad/Spin Actions
 */
async function checkRateLimit(userId) {
    try {
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${userId}&select=last_activity`);
        if (!Array.isArray(users) || users.length === 0) {
            return { ok: true };
        }

        const user = users[0];
        const lastActivity = user.last_activity ? new Date(user.last_activity).getTime() : 0;
        const now = Date.now();
        const timeElapsed = now - lastActivity;

        if (timeElapsed < MIN_TIME_BETWEEN_ACTIONS_MS) {
            const remainingTime = MIN_TIME_BETWEEN_ACTIONS_MS - timeElapsed;
            return {
                ok: false,
                message: `Rate limit exceeded. Please wait ${Math.ceil(remainingTime / 1000)} seconds before the next action.`,
                remainingTime: remainingTime
            };
        }

        return { ok: true };
    } catch (error) {
        console.error(`Rate limit check failed for user ${userId}:`, error.message);
        return { ok: true };
    }
}

// ------------------------------------------------------------------
// 🔒 Action ID Security System (Server-Issued ID)
// ------------------------------------------------------------------

/**
 * Generates a strong, random ID for the client to use only once.
 */
function generateStrongId() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * HANDLER: type: "generateActionId"
 * The client requests an action ID before starting a critical action (ad/spin).
 */
async function handleGenerateActionId(req, res, body) {
    const { user_id, action_type } = body;
    const id = parseInt(user_id);
    
    if (!action_type) {
        return sendError(res, 'Missing action_type.', 400);
    }
    
    // Check if the user already has an unexpired ID for this action type
    try {
        const existingIds = await supabaseFetch('temp_actions', 'GET', null, `?user_id=eq.${id}&action_type=eq.${action_type}&select=action_id,created_at`);
        
        if (Array.isArray(existingIds) && existingIds.length > 0) {
            const lastIdTime = new Date(existingIds[0].created_at).getTime();
            if (Date.now() - lastIdTime < ACTION_ID_EXPIRY_MS) {
                 // If the existing ID is still valid, return it to prevent spamming the table
                return sendSuccess(res, { action_id: existingIds[0].action_id });
            } else {
                 // Clean up expired ID before creating a new one
                 await supabaseFetch('temp_actions', 'DELETE', null, `?user_id=eq.${id}&action_type=eq.${action_type}`);
            }
        }
    } catch(e) {
        console.warn('Error checking existing temp_actions:', e.message);
    }
    
    // Generate and save the new ID
    const newActionId = generateStrongId();
    
    try {
        await supabaseFetch('temp_actions', 'POST',
            { user_id: id, action_id: newActionId, action_type: action_type },
            '?select=action_id');
            
        sendSuccess(res, { action_id: newActionId });
    } catch (error) {
        // This catches if the ID was somehow duplicated (highly unlikely with strong ID)
        console.error('Failed to generate and save action ID:', error.message);
        sendError(res, 'Failed to generate security token.', 500);
    }
}


/**
 * Middleware: Checks if the Action ID is valid (exists, not expired, matches user/type) and then deletes it.
 */
async function validateAndUseActionId(res, userId, actionId, actionType) {
    if (!actionId) {
        sendError(res, 'Missing Server Token (Action ID). Request rejected.', 400);
        return false;
    }
    
    try {
        const query = `?user_id=eq.${userId}&action_id=eq.${actionId}&action_type=eq.${actionType}&select=id,created_at`;
        const records = await supabaseFetch('temp_actions', 'GET', null, query);
        
        if (!Array.isArray(records) || records.length === 0) {
            sendError(res, 'Invalid or previously used Server Token (Action ID).', 409); // 409 Conflict
            return false;
        }
        
        const record = records[0];
        const recordTime = new Date(record.created_at).getTime();
        
        // 1. Check Expiration (60 seconds)
        if (Date.now() - recordTime > ACTION_ID_EXPIRY_MS) {
            // Delete the expired token and send error
            await supabaseFetch('temp_actions', 'DELETE', null, `?id=eq.${record.id}`);
            sendError(res, 'Server Token (Action ID) expired. Please try again.', 408); // 408 Request Timeout
            return false;
        }

        // 2. Use the token: Delete it to prevent reuse
        await supabaseFetch('temp_actions', 'DELETE', null, `?id=eq.${record.id}`);

        return true;

    } catch (error) {
        console.error(`Error validating Action ID ${actionId}:`, error.message);
        sendError(res, 'Security validation failed.', 500);
        return false;
    }
}


// ------------------------------------------------------------------
// **initData Security Validation Function**
// ------------------------------------------------------------------
function validateInitData(initData) {
    if (!initData || !BOT_TOKEN) {
        console.warn('Security Check Failed: initData or BOT_TOKEN is missing.');
        return false;
    }

    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get('hash');
    urlParams.delete('hash');

    const dataCheckString = Array.from(urlParams.entries())
        .map(([key, value]) => `${key}=${value}`)
        .sort()
        .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData')
        .update(BOT_TOKEN)
        .digest();

    const calculatedHash = crypto.createHmac('sha256', secretKey)
        .update(dataCheckString)
        .digest('hex');

    if (calculatedHash !== hash) {
        console.warn(`Security Check Failed: Hash mismatch.`);
        return false;
    }

    const authDateParam = urlParams.get('auth_date');
    if (!authDateParam) {
        console.warn('Security Check Failed: auth_date is missing.');
        return false;
    }

    const authDate = parseInt(authDateParam) * 1000;
    const currentTime = Date.now();
    const expirationTime = 1200 * 1000; // 20 minutes limit

    if (currentTime - authDate > expirationTime) {
        console.warn(`Security Check Failed: Data expired.`);
        return false;
    }

    return true;
}

// --- API Handlers ---

/**
 * HANDLER: type: "getUserData"
 */
async function handleGetUserData(req, res, body) {
    const { user_id } = body;
    if (!user_id) {
        return sendError(res, 'Missing user_id for data fetch.');
    }
    const id = parseInt(user_id);

    try {
        // 1. Update last_activity immediately
        await supabaseFetch('users', 'PATCH',
            { last_activity: new Date().toISOString() },
            `?id=eq.${id}&select=id`);

        // 2. Check and reset daily limits (if 24 hours passed)
        await resetDailyLimitsIfExpired(id);

        // 3. Fetch user data
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=balance,ads_watched_today,spins_today,last_activity,is_banned`);

        if (!users || users.length === 0 || users.success) {
            return sendSuccess(res, {
                balance: 0, ads_watched_today: 0, spins_today: 0, referrals_count: 0, withdrawal_history: [], is_banned: false
            });
        }

        const userData = users[0];

        // ⚠️ Banned Check - Exit immediately if banned
        if (userData.is_banned) {
             return sendSuccess(res, { is_banned: true, message: "User is banned from accessing the app." });
        }


        // 4. Fetch referrals count
        const referrals = await supabaseFetch('users', 'GET', null, `?ref_by=eq.${id}&select=id`);
        const referralsCount = Array.isArray(referrals) ? referrals.length : 0;

        // 5. Fetch withdrawal history
        const history = await supabaseFetch('withdrawals', 'GET', null, `?user_id=eq.${id}&select=amount,status,created_at&order=created_at.desc`);
        const withdrawalHistory = Array.isArray(history) ? history : [];

        sendSuccess(res, {
            ...userData,
            referrals_count: referralsCount,
            withdrawal_history: withdrawalHistory
        });

    } catch (error) {
        console.error('GetUserData failed:', error.message);
        sendError(res, `Failed to retrieve user data: ${error.message}`, 500);
    }
}


/**
 * 1) type: "register"
 */
async function handleRegister(req, res, body) {
  const { user_id, ref_by } = body;
  const id = parseInt(user_id);

  try {
    // 1. Check if user exists
    const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=id,is_banned`);

    if (!Array.isArray(users) || users.length === 0) {
      // 2. User does not exist, create new user
      const newUser = {
        id,
        balance: 0,
        ads_watched_today: 0,
        spins_today: 0,
        ref_by: ref_by ? parseInt(ref_by) : null,
        last_activity: new Date().toISOString(), 
        is_banned: false
      };
      await supabaseFetch('users', 'POST', newUser, '?select=id');
    } else {
        // ⚠️ Check if existing user is banned
        if (users[0].is_banned) {
             return sendError(res, 'User is banned.', 403);
        }
    }

    sendSuccess(res, { message: 'User registered or already exists.' });
  } catch (error) {
    console.error('Registration failed:', error.message);
    sendError(res, `Registration failed: ${error.message}`, 500);
  }
}

/**
 * 2) type: "watchAd"
 */
async function handleWatchAd(req, res, body) {
    const { user_id, action_id } = body;
    const id = parseInt(user_id);
    const reward = REWARD_PER_AD;

    // 1. Check and Consume Action ID (Security Check)
    if (!await validateAndUseActionId(res, id, action_id, 'watchAd')) return;

    try {
        // 2. Check and reset daily limits before proceeding
        await resetDailyLimitsIfExpired(id);

        // 3. Fetch current user data
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=balance,ads_watched_today,is_banned`);
        if (!Array.isArray(users) || users.length === 0) {
            return sendError(res, 'User not found.', 404);
        }
        
        const user = users[0];

        // ⚠️ Banned Check
        if (user.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }

        // 4. Rate Limit Check (NEW)
        const rateLimitResult = await checkRateLimit(id);
        if (!rateLimitResult.ok) {
            // Re-insert the action ID if rate limit is hit, so client can retry
            // NOTE: For simplicity, we just send the error and the client will request a new one
            return sendError(res, rateLimitResult.message, 429); 
        }

        // 5. Check maximum ad limit
        if (user.ads_watched_today >= DAILY_MAX_ADS) {
            return sendError(res, `Daily ad limit (${DAILY_MAX_ADS}) reached.`, 403);
        }

        // 6. Calculate new values
        const newBalance = user.balance + reward;
        const newAdsCount = user.ads_watched_today + 1;

        // 7. Update user record: balance, ads_watched_today, and last_activity
        await supabaseFetch('users', 'PATCH',
          {
              balance: newBalance,
              ads_watched_today: newAdsCount,
              last_activity: new Date().toISOString()
          },
          `?id=eq.${id}`);
          
        // 8. Success
        sendSuccess(res, { new_balance: newBalance, actual_reward: reward, new_ads_count: newAdsCount });

    } catch (error) {
        console.error('WatchAd failed:', error.message);
        sendError(res, `Failed to process ad watch: ${error.message}`, 500);
    }
}

/**
 * 3) type: "commission"
 */
async function handleCommission(req, res, body) {
    const { referrer_id, referee_id } = body;

    if (!referrer_id || !referee_id) {
        return sendSuccess(res, { message: 'Invalid commission data received but acknowledged.' });
    }

    const referrerId = parseInt(referrer_id);
    const refereeId = parseInt(referee_id);
    const sourceReward = REWARD_PER_AD;
    const commissionAmount = sourceReward * REFERRAL_COMMISSION_RATE;

    try {
        // 1. Fetch current referrer balance and banned status
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${referrerId}&select=balance,is_banned`);
        if (!Array.isArray(users) || users.length === 0) {
            return sendSuccess(res, { message: 'Referrer not found, commission aborted.' });
        }
        
        // ⚠️ Skip commission if referrer is banned
        if (users[0].is_banned) {
            return sendSuccess(res, { message: 'Referrer is banned, commission aborted.' });
        }

        const newBalance = users[0].balance + commissionAmount;

        // 2. Update referrer balance
        await supabaseFetch('users', 'PATCH', { balance: newBalance }, `?id=eq.${referrerId}`);

        // 3. Add record to commission_history
        await supabaseFetch('commission_history', 'POST',
            { referrer_id: referrerId, referee_id: refereeId, amount: commissionAmount, source_reward: sourceReward },
            '?select=referrer_id');

        sendSuccess(res, { new_referrer_balance: newBalance });

    } catch (error) {
        console.error('Commission failed:', error.message);
        sendError(res, `Commission failed: ${error.message}`, 500);
    }
}

/**
 * 4) type: "spin" (called to register the spin before showing the ad)
 */
async function handleSpin(req, res, body) {
    const { user_id, action_id } = body;
    const id = parseInt(user_id);
    
    // 1. Check and Consume Action ID (Security Check)
    if (!await validateAndUseActionId(res, id, action_id, 'spin')) return;

    try {
        // 2. Check and reset daily limits before proceeding
        await resetDailyLimitsIfExpired(id);

        // 3. Fetch current user data
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=spins_today,is_banned`);
        if (!Array.isArray(users) || users.length === 0) {
            return sendError(res, 'User not found.', 404);
        }
        
        const user = users[0];

        // ⚠️ Banned Check
        if (user.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }
        
        // 4. Rate Limit Check (NEW)
        const rateLimitResult = await checkRateLimit(id);
        if (!rateLimitResult.ok) {
            return sendError(res, rateLimitResult.message, 429); 
        }

        // 5. Check maximum spin limit
        if (user.spins_today >= DAILY_MAX_SPINS) {
            return sendError(res, `Daily spin limit (${DAILY_MAX_SPINS}) reached.`, 403);
        }

        // 6. Calculate new values
        const newSpinsCount = user.spins_today + 1;

        // 7. Update user record: spins_today, and last_activity
        await supabaseFetch('users', 'PATCH',
          { 
              spins_today: newSpinsCount,
              last_activity: new Date().toISOString()
          },
          `?id=eq.${id}`);
          
        // 8. Success
        sendSuccess(res, { new_spins_count: newSpinsCount });

    } catch (error) {
        console.error('Spin failed:', error.message);
        sendError(res, `Failed to process spin: ${error.message}`, 500);
    }
}

/**
 * 5) type: "spinResult" (no Action ID needed here as 'spin' was the critical step)
 */
async function handleSpinResult(req, res, body) {
    const { user_id } = body;
    const id = parseInt(user_id);
    
    // NOTE: The 'spin' action already consumed a unique ID and incremented the spin count.
    // This action only calculates the prize and updates the balance.

    const { prize, prizeIndex } = calculateRandomSpinPrize();

    try {
        // 1. Fetch current user balance and banned status
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=balance,is_banned`);
        if (!Array.isArray(users) || users.length === 0) {
            return sendError(res, 'User not found.', 404);
        }

        // ⚠️ Banned Check
        if (users[0].is_banned) {
            return sendError(res, 'User is banned.', 403);
        }

        const newBalance = users[0].balance + prize;

        // 2. Update user record: balance 
        await supabaseFetch('users', 'PATCH',
          { balance: newBalance },
          `?id=eq.${id}`);

        // 3. Save to spin_results
        await supabaseFetch('spin_results', 'POST',
          { user_id: id, prize },
          '?select=user_id');

        // 4. Return the actual, server-calculated prize and index
        sendSuccess(res, { new_balance: newBalance, actual_prize: prize, prize_index: prizeIndex });

    } catch (error) {
        console.error('Spin result failed:', error.message);
        sendError(res, `Failed to process spin result: ${error.message}`, 500);
    }
}


/**
 * 6) type: "withdraw"
 */
async function handleWithdraw(req, res, body) {
    const { user_id, binanceId, amount, action_id } = body;
    const id = parseInt(user_id);
    const withdrawalAmount = parseFloat(amount);
    const MIN_WITHDRAW = 400;

    // 1. Check and Consume Action ID (Security Check)
    if (!await validateAndUseActionId(res, id, action_id, 'withdraw')) return;

    if (withdrawalAmount < MIN_WITHDRAW) {
        return sendError(res, `Minimum withdrawal amount is ${MIN_WITHDRAW} SHIB.`, 400);
    }

    try {
        // 2. Fetch current user balance and banned status
        const users = await supabaseFetch('users', 'GET', null, `?id=eq.${id}&select=balance,is_banned`);
        if (!Array.isArray(users) || users.length === 0) {
            return sendError(res, 'User not found.', 404);
        }

        const user = users[0];

        // ⚠️ Banned Check
        if (user.is_banned) {
            return sendError(res, 'User is banned.', 403);
        }
        
        // 3. Check sufficient balance
        if (user.balance < withdrawalAmount) {
            return sendError(res, 'Insufficient balance.', 400);
        }

        // 4. Calculate new balance
        const newBalance = user.balance - withdrawalAmount;

        // 5. Update user balance
        await supabaseFetch('users', 'PATCH',
          { balance: newBalance },
          `?id=eq.${id}`);

        // 6. Record the withdrawal request
        await supabaseFetch('withdrawals', 'POST',
          { user_id: id, amount: withdrawalAmount, binance_id: binanceId, status: 'pending' },
          '?select=user_id');

        // 7. Success
        sendSuccess(res, { new_balance: newBalance });

    } catch (error) {
        console.error('Withdrawal failed:', error.message);
        sendError(res, `Withdrawal failed: ${error.message}`, 500);
    }
}


// --- Main Handler for Vercel/Serverless ---
module.exports = async (req, res) => {
  // CORS configuration
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return sendSuccess(res);
  }

  if (req.method !== 'POST') {
    return sendError(res, `Method ${req.method} not allowed. Only POST is supported.`, 405);
  }

  let body;
  try {
    body = await new Promise((resolve, reject) => {
      let data = '';
      req.on('data', chunk => {
        data += chunk.toString();
      });
      req.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error('Invalid JSON payload.'));
        }
      });
      req.on('error', reject);
    });

  } catch (error) {
    return sendError(res, error.message, 400);
  }

  if (!body || !body.type) {
    return sendError(res, 'Missing "type" field in the request body.', 400);
  }

  // ⬅️ initData Security Check
  if (body.type !== 'commission' && (!body.initData || !validateInitData(body.initData))) {
      return sendError(res, 'Invalid or expired initData. Security check failed.', 401);
  }

  if (!body.user_id && body.type !== 'commission') {
      return sendError(res, 'Missing user_id in the request body.', 400);
  }

  // Route the request based on the 'type' field
  switch (body.type) {
    case 'getUserData':
      await handleGetUserData(req, res, body);
      break;
    case 'register':
      await handleRegister(req, res, body);
      break;
    case 'watchAd':
      await handleWatchAd(req, res, body);
      break;
    case 'commission':
      await handleCommission(req, res, body);
      break;
    case 'spin':
      await handleSpin(req, res, body);
      break;
    case 'spinResult':
      await handleSpinResult(req, res, body);
      break;
    case 'withdraw':
      await handleWithdraw(req, res, body);
      break;
    case 'generateActionId': // ⬅️ NEW Handler
      await handleGenerateActionId(req, res, body);
      break;
    default:
      sendError(res, `Unknown request type: ${body.type}`, 400);
      break;
  }
};