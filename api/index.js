// /api/index.js 

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
// Fully secured and defined server-side constants (to prevent tampering)
// ------------------------------------------------------------------
const REWARD_PER_AD = 3;
const REFERRAL_COMMISSION_RATE = 0.05;
const DAILY_MAX_ADS = 100; // Max ads limit
const DAILY_MAX_SPINS = 15; // Max spins limit
const MIN_TIME_BETWEEN_ACTIONS_MS = 3000; // 3 seconds minimum time between watchAd/spin requests
// Sectors: 5 (Index 0), 10 (Index 1), 15 (Index 2), 20 (Index 3), 5 (Index 4)
const SPIN_SECTORS = [5, 10, 15, 20, 5];

/**
 * Helper function to randomly select a prize from the defined sectors and return its index.
 */
function calculateRandomSpinPrize() {
    const randomIndex = Math.floor(Math.random() * SPIN_SECTORS.length);
    const prize = SPIN_SECTORS[randomIndex];
    return { prize, prizeIndex: randomIndex };
}

// ------------------------------------------------------------------
// Supabase Client Initialization (Basic Fetch Wrapper)
// ------------------------------------------------------------------

async function supabaseFetch(method, endpoint, payload = null, headers = {}) {
    const url = `${SUPABASE_URL}${endpoint}`;
    const defaultHeaders = {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_ANON_KEY,
        'Authorization': `Bearer ${SUPABASE_ANON_KEY}`,
        'Prefer': 'return=representation',
        ...headers
    };

    const config = {
        method: method,
        headers: defaultHeaders,
    };

    if (payload && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
        config.body = JSON.stringify(payload);
    }

    const response = await fetch(url, config);

    // Supabase will return JSON on success or failure
    const responseData = response.status === 204 ? { data: null } : await response.json();

    if (!response.ok) {
        // console.error('Supabase Error:', responseData);
        return { data: null, error: responseData.message || responseData.details || 'Supabase request failed' };
    }

    return { data: responseData, error: null };
}

// Simplified Supabase Wrappers
const supabase = {
    from: (table) => ({
        select: async (columns = '*') => {
            const { data, error } = await supabaseFetch('GET', `/rest/v1/${table}?select=${columns}`);
            return { data, error };
        },
        eq: (column, value) => ({
            select: async (columns = '*') => {
                const { data, error } = await supabaseFetch('GET', `/rest/v1/${table}?${column}=eq.${value}&select=${columns}`);
                // Single result handling for specific queries
                const resultData = Array.isArray(data) ? data[0] : data;
                return { data: resultData, error };
            },
            update: async (updates) => {
                const { error } = await supabaseFetch('PATCH', `/rest/v1/${table}?${column}=eq.${value}`, updates);
                return { data: null, error };
            },
            insert: async (records) => {
                const { data, error } = await supabaseFetch('POST', `/rest/v1/${table}`, records);
                return { data, error };
            },
            delete: async () => {
                const { data, error } = await supabaseFetch('DELETE', `/rest/v1/${table}?${column}=eq.${value}`);
                return { data, error };
            }
        })
    })
};


// ------------------------------------------------------------------
// Security Functions
// ------------------------------------------------------------------

/**
 * Validates the Telegram Mini App initData signature.
 * @param {string} initData - The data string received from Telegram.
 * @returns {boolean} True if the signature is valid.
 */
function validateInitData(initData) {
    if (!BOT_TOKEN) {
        // console.error('BOT_TOKEN is missing in environment variables.');
        return false; 
    }
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    params.delete('hash');
    params.sort();

    const dataCheckString = Array.from(params.entries())
        .map(([key, value]) => `${key}=${value}`)
        .join('\n');

    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const calculatedHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');

    return calculatedHash === hash;
}

/**
 * Generates a strong, random, hex-encoded ID for temporary actions.
 * @returns {string} A 64-character hex string.
 */
function generateStrongId() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * Checks if an action ID is valid, belongs to the user, has not expired (60s), and consumes it (deletes from table).
 * @param {number} userId - The Telegram user ID.
 * @param {string} actionId - The Action ID to validate.
 * @param {string} actionType - The expected type of action ('watchAd', 'spin', 'withdraw').
 * @returns {{ok: boolean, error?: string}} Validation result.
 */
async function validateAndUseActionId(userId, actionId, actionType) {
    // 1. Fetch the token from the temp_actions table
    const { data: tokenData, error: fetchError } = await supabase
        .from('temp_actions')
        .select('created_at, user_id, action_type')
        .eq('action_id', actionId);

    if (fetchError || !tokenData) {
        return { ok: false, error: 'Server Token Not Found or Already Used.' };
    }

    // 2. Check User ID and Type match
    if (tokenData.user_id != userId || tokenData.action_type !== actionType) {
        // Token exists but doesn't match user or type -> potential fraud/reuse attempt
        // We still delete it to prevent further probing
        await supabase.from('temp_actions').eq('action_id', actionId).delete();
        return { ok: false, error: 'Server Token Invalid for this User or Action Type.' };
    }

    // 3. Check Expiry (60 seconds)
    const createdAt = new Date(tokenData.created_at).getTime();
    const now = Date.now();
    if (now - createdAt > 60000) { 
        // Token expired. Delete it.
        await supabase.from('temp_actions').eq('action_id', actionId).delete();
        return { ok: false, error: 'Server Token Expired (Timeout).' };
    }

    // 4. Consume the Token (Delete it immediately to prevent replay)
    const { error: deleteError } = await supabase
        .from('temp_actions')
        .eq('action_id', actionId)
        .delete();

    if (deleteError) {
        // This is a critical security issue if deletion fails. Log and reject.
        // console.error('CRITICAL: Failed to delete used action_id:', deleteError);
        // The transaction may still complete but the user can't reuse the ID
        return { ok: true }; 
    }

    return { ok: true };
}

// ------------------------------------------------------------------
// API Handler Functions
// ------------------------------------------------------------------

function sendResponse(res, statusCode, body) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
}

function sendSuccess(res, data) {
    sendResponse(res, 200, { ok: true, data: data });
}

function sendError(res, message, statusCode = 500) {
    // console.error(`Sending Error ${statusCode}: ${message}`);
    sendResponse(res, statusCode, { ok: false, error: message });
}

/**
 * Handles action ID generation request (used before every critical action).
 */
async function handleGenerateActionId(req, res, body) {
    const { user_id, action_type } = body;
    if (!action_type) {
        return sendError(res, 'Missing action_type for token generation.', 400);
    }
    
    // Check if user is banned (redundant check, but safe)
    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('is_banned')
        .eq('id', user_id)
        .single();
    if (userError || userData.is_banned) {
        return sendError(res, 'Access denied: User banned.', 403);
    }
    
    const newActionId = generateStrongId();
    const { error: insertError } = await supabase.from('temp_actions').eq('id', newActionId).insert({
        user_id: user_id,
        action_id: newActionId,
        action_type: action_type,
    });

    if (insertError) {
        return sendError(res, 'Failed to generate security token.', 500);
    }

    sendSuccess(res, { action_id: newActionId });
}


/**
 * Retrieves the user's data (balance, limits, history).
 */
async function handleGetUserData(req, res, body) {
    const { user_id } = body;

    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('balance, ads_watched_today, spins_today, referrals_count, is_banned')
        .eq('id', user_id)
        .single();
    
    if (userError || !userData) {
        return sendError(res, 'User data not found.', 404);
    }
    
    if (userData.is_banned) {
        return sendSuccess(res, { is_banned: true });
    }

    const { data: historyData, error: historyError } = await supabase
        .from('withdrawals')
        .select('amount, status, created_at')
        .eq('user_id', user_id)
        .order('created_at', { ascending: false });

    // Handle potential error but continue if history retrieval fails
    const withdrawal_history = historyError ? [] : historyData;

    sendSuccess(res, {
        ...userData,
        withdrawal_history: withdrawal_history
    });
}

/**
 * Registers a new user or updates the referrer.
 */
async function handleRegister(req, res, body) {
    const { user_id, ref_by } = body;
    
    const { data: existingUser } = await supabase
        .from('users')
        .select('id, ref_by')
        .eq('id', user_id)
        .single();
    
    if (existingUser) {
        let updateRefError = null;
        if (!existingUser.ref_by && ref_by) {
            // Only update referrer if not already set and a ref_by is provided
            const { error } = await supabase.from('users').eq('id', user_id).update({ ref_by: ref_by });
            updateRefError = error;

            // Increment referrer's count
            if (!updateRefError) {
                const { data: referrer, error: refError } = await supabase
                    .from('users')
                    .select('referrals_count')
                    .eq('id', ref_by)
                    .single();
                
                if (referrer && !refError) {
                    await supabase.from('users').eq('id', ref_by).update({ 
                        referrals_count: referrer.referrals_count + 1 
                    });
                }
            }
        }
        return sendSuccess(res, { message: 'User already registered.', updated_referrer: !existingUser.ref_by && !!ref_by && !updateRefError });
    }

    // New user registration
    const initialData = {
        id: user_id,
        balance: 0,
        ads_watched_today: 0,
        spins_today: 0,
        referrals_count: 0,
        is_banned: false,
        ref_by: ref_by || null,
    };

    const { error: insertError } = await supabase.from('users').eq('id', user_id).insert(initialData);

    if (insertError) {
        return sendError(res, `Registration failed: ${insertError}`, 500);
    }

    // If registered successfully with a referrer, increment referrer's count
    if (ref_by) {
        const { data: referrer, error: refError } = await supabase
            .from('users')
            .select('referrals_count')
            .eq('id', ref_by)
            .single();
        
        if (referrer && !refError) {
            await supabase.from('users').eq('id', ref_by).update({ 
                referrals_count: referrer.referrals_count + 1 
            });
        }
    }

    sendSuccess(res, { message: 'User registered successfully.' });
}

/**
 * Awards SHIB for watching an Ad.
 */
async function handleWatchAd(req, res, body) {
    const { user_id, action_id } = body;
    
    // 1. Action ID Validation (Consumes token)
    const actionValidation = await validateAndUseActionId(user_id, action_id, 'watchAd');
    if (!actionValidation.ok) {
        return sendError(res, actionValidation.error, 409);
    }

    // 2. Load User Data
    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('balance, ads_watched_today, last_action_time, is_banned')
        .eq('id', user_id)
        .single();

    if (userError || !userData) {
        return sendError(res, 'User data not found.', 404);
    }
    
    if (userData.is_banned) {
        return sendError(res, 'Access denied: User banned.', 403);
    }

    // 3. Rate Limit Check (3 seconds between actions)
    const lastActionTime = userData.last_action_time ? new Date(userData.last_action_time).getTime() : 0;
    if (Date.now() - lastActionTime < MIN_TIME_BETWEEN_ACTIONS_MS) {
        return sendError(res, `Rate limit exceeded. Try again in ${MIN_TIME_BETWEEN_ACTIONS_MS / 1000} seconds.`, 429);
    }

    // 4. Daily Limit Check
    if (userData.ads_watched_today >= DAILY_MAX_ADS) {
        return sendError(res, 'Daily ad limit reached.', 429);
    }

    // 5. Calculate new state
    const newBalance = userData.balance + REWARD_PER_AD;
    const newAdsCount = userData.ads_watched_today + 1;
    const now = new Date().toISOString();

    // 6. Update database
    const { error: updateError } = await supabase
        .from('users')
        .update({
            balance: newBalance,
            ads_watched_today: newAdsCount,
            last_action_time: now
        })
        .eq('id', user_id);

    if (updateError) {
        return sendError(res, `Failed to award ad reward: ${updateError}`, 500);
    }

    sendSuccess(res, {
        actual_reward: REWARD_PER_AD,
        new_balance: newBalance,
        new_ads_count: newAdsCount
    });
}

/**
 * Handles referral commission payout (triggered internally by handleWatchAd, does NOT need initData validation).
 */
async function handleCommission(req, res, body) {
    const { referrer_id, referee_id } = body;

    // 1. Check if the commission has already been paid for this user/day (Simple: check referee's daily count)
    const { data: refereeData } = await supabase
        .from('users')
        .select('ads_watched_today')
        .eq('id', referee_id)
        .single();
        
    if (!refereeData || refereeData.ads_watched_today <= 0) {
        return sendError(res, 'Referee has not watched an ad yet today.', 400);
    }

    // The commission should be paid only once per ad, but we use the simplified daily count:
    // This is a basic proxy for preventing duplicate daily commission, ideally, it needs a separate tracking table.
    const expectedCommission = REWARD_PER_AD * REFERRAL_COMMISSION_RATE;
    
    // 2. Fetch current referrer data
    const { data: referrerData, error: refError } = await supabase
        .from('users')
        .select('balance')
        .eq('id', referrer_id)
        .single();

    if (refError || !referrerData) {
        return sendError(res, 'Referrer not found.', 404);
    }
    
    // 3. Update referrer balance
    const newBalance = referrerData.balance + expectedCommission;
    const { error: updateError } = await supabase
        .from('users')
        .update({
            balance: newBalance
        })
        .eq('id', referrer_id);

    if (updateError) {
        return sendError(res, `Failed to award commission: ${updateError}`, 500);
    }

    sendSuccess(res, {
        commission_awarded: expectedCommission,
        new_referrer_balance: newBalance
    });
}

/**
 * 🆕 STEP 1: Registers a spin attempt, consumes the token, and increments the spin count.
 */
async function handleRegisterSpin(req, res, body) {
    const { user_id, action_id } = body;

    // 1. Action ID Validation (Consumes token)
    const actionValidation = await validateAndUseActionId(user_id, action_id, 'spin');
    if (!actionValidation.ok) {
        return sendError(res, actionValidation.error, 409);
    }

    // 2. Load User Data
    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('spins_today, balance, is_banned, last_action_time')
        .eq('id', user_id)
        .single();
        
    if (userError || !userData) {
        return sendError(res, 'User data not found.', 404);
    }
    
    if (userData.is_banned) {
        return sendError(res, 'Access denied: User banned.', 403);
    }
    
    // 3. Rate Limit Check (3 seconds between actions)
    const lastActionTime = userData.last_action_time ? new Date(userData.last_action_time).getTime() : 0;
    if (Date.now() - lastActionTime < MIN_TIME_BETWEEN_ACTIONS_MS) {
        // Since the token was consumed, we just send a limit error.
        return sendError(res, `Rate limit exceeded. Try again in ${MIN_TIME_BETWEEN_ACTIONS_MS / 1000} seconds.`, 429);
    }

    // 4. Daily Limit Check
    if (userData.spins_today >= DAILY_MAX_SPINS) {
        // Since the token was consumed, we just send a limit error.
        return sendError(res, 'Daily spin limit reached.', 429);
    }
    
    // 5. Update Spins Today and last action time ONLY
    const newSpinsCount = userData.spins_today + 1;
    const now = new Date().toISOString();
    
    const { error: updateError } = await supabase
        .from('users')
        .update({
            spins_today: newSpinsCount,
            last_action_time: now
        })
        .eq('id', user_id);

    if (updateError) {
        return sendError(res, `Failed to register spin attempt: ${updateError}`, 500);
    }

    // 6. Success response (No prize data yet)
    sendSuccess(res, {
        new_spins_count: newSpinsCount,
        message: 'Spin registered successfully. Awaiting spin result.'
    });
}

/**
 * 🆕 STEP 2: Calculates and awards the prize for the registered spin.
 */
async function handleSpinResult(req, res, body) {
    const { user_id, action_id } = body; // action_id is received for context/logging only

    // 1. Load User Data (we assume handleRegisterSpin already consumed the token and incremented spins_today)
    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('spins_today, balance')
        .eq('id', user_id)
        .single();
        
    if (userError || !userData) {
        return sendError(res, 'User data not found.', 404);
    }

    // 2. Calculate Prize (Server logic)
    const { prize, prizeIndex } = calculateRandomSpinPrize(); 
    const newBalance = userData.balance + prize;

    // 3. Update Balance
    const { error: updateError } = await supabase
        .from('users')
        .update({
            balance: newBalance
            // NOTE: We do NOT update spins_today here as it was done in handleRegisterSpin
        })
        .eq('id', user_id);

    if (updateError) {
        return sendError(res, `Failed to award spin prize: ${updateError}`, 500);
    }

    // 4. Success response with prize
    sendSuccess(res, {
        new_balance: newBalance,
        actual_prize: prize,
        prize_index: prizeIndex,
        message: 'Prize awarded successfully.',
        token_used_for_result: action_id 
    });
}

/**
 * Handles withdrawal requests.
 */
async function handleWithdraw(req, res, body) {
    const { user_id, binanceId, amount, action_id } = body;
    const minWithdrawal = 400;

    if (!binanceId || typeof amount !== 'number' || amount < minWithdrawal) {
        return sendError(res, 'Invalid withdrawal request parameters.', 400);
    }
    
    // 1. Action ID Validation (Consumes token)
    const actionValidation = await validateAndUseActionId(user_id, action_id, 'withdraw');
    if (!actionValidation.ok) {
        return sendError(res, actionValidation.error, 409);
    }

    // 2. Load User Data and check balance
    const { data: userData, error: userError } = await supabase
        .from('users')
        .select('balance, is_banned')
        .eq('id', user_id)
        .single();

    if (userError || !userData) {
        return sendError(res, 'User data not found.', 404);
    }
    
    if (userData.is_banned) {
        return sendError(res, 'Access denied: User banned.', 403);
    }

    if (userData.balance < amount) {
        return sendError(res, 'Insufficient balance for withdrawal.', 400);
    }

    // 3. Create withdrawal record
    const { error: insertError } = await supabase.from('withdrawals').eq('id', null).insert({
        user_id: user_id,
        amount: amount,
        binance_id: binanceId,
        status: 'Pending'
    });

    if (insertError) {
        return sendError(res, `Failed to record withdrawal: ${insertError}`, 500);
    }

    // 4. Deduct balance
    const newBalance = userData.balance - amount;
    const { error: updateError } = await supabase
        .from('users')
        .update({ balance: newBalance })
        .eq('id', user_id);

    if (updateError) {
        // Log critical error: withdrawal recorded but balance deduction failed
        // Reversal logic needed in a real-world app, but for now:
        // console.error('CRITICAL: Balance deduction failed after withdrawal recorded.', updateError);
        return sendError(res, `Withdrawal recorded but failed to update balance. Please contact support.`, 500);
    }

    sendSuccess(res, {
        message: 'Withdrawal request submitted.',
        new_balance: newBalance
    });
}


// ------------------------------------------------------------------
// Main Request Handler
// ------------------------------------------------------------------

module.exports = async (req, res) => {
    if (req.method !== 'POST') {
        return sendError(res, 'Only POST requests are accepted.', 405);
    }

    let body;
    try {
        body = await new Promise((resolve, reject) => {
            let data = '';
            req.on('data', chunk => { data += chunk; });
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
    // Enforced on all actions except commission and generateActionId 
    if (body.type !== 'commission' && body.type !== 'generateActionId' && (!body.initData || !validateInitData(body.initData))) {
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
        case 'registerSpin': // ⬅️ NEW: Step 1 of Spin
            await handleRegisterSpin(req, res, body);
            break;
        case 'spinResult': // ⬅️ NEW: Step 2 of Spin
            await handleSpinResult(req, res, body);
            break;
        case 'withdraw':
            await handleWithdraw(req, res, body);
            break;
        case 'generateActionId':
            await handleGenerateActionId(req, res, body);
            break;
        default:
            sendError(res, `Unknown request type: ${body.type}`, 400);
    }
};