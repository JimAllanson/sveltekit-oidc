import type { LoadOutput } from '@sveltejs/kit';
import type { Locals, OIDCFailureResponse, OIDCResponse, UserDetailsGeneratorFn, GetUserSessionFn, RequestEvent} from '../types';
import { parseCookie } from './cookie';

export const oidcBaseUrl = `${import.meta.env.VITE_OIDC_ISSUER}/protocol/openid-connect`;
export const clientId = `${import.meta.env.VITE_OIDC_CLIENT_ID}`;
let appRedirectUrl = import.meta.env.VITE_OIDC_REDIRECT_URI;

export function isTokenExpired(jwt: string): boolean {
    let data = null;
    if ( !jwt || jwt.length < 10 ) {
        return true;
    }
    const tokenTimeSkew =10;  // 10 seconds before actual token exp
    try {
        data = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64').toString());
    } catch (e) {
        try {
            data = JSON.parse(atob(jwt.split('.')[1]).toString());
        } catch (e) {}
    }
	return data?.exp ? ( new Date().getTime()/1000 > (data.exp - tokenTimeSkew) ) : true;
}

export function initiateFrontChannelOIDCAuth(browser: boolean, oidcBaseUrl: string, clientId: string, client_scopes: string, appRedirectUrl: string, request_path?: string, request_params?: Record<string, string>): LoadOutput {
    const oidcRedirectUrlWithParams = [
        `${oidcBaseUrl}/auth?scope=${browser ? encodeURIComponent(client_scopes) : client_scopes}`,
        `client_id=${clientId}`,
        `redirect_uri=${browser ? encodeURIComponent(appRedirectUrl + (request_path ? request_path : '/') ) : (appRedirectUrl + (request_path ? request_path : '/') )}`,
        'response_type=code',
        'response_mode=query',
    ];
    return {
        redirect: oidcRedirectUrlWithParams.join('&'),
        status: 302
    }
}


export async function initiateBackChannelOIDCAuth(authCode: string, clientId: string, clientSecret: string, oidcBaseUrl: string, appRedirectUrl: string): Promise<OIDCResponse>  {
    let formBody = [
        'code=' + authCode,
        'client_id=' + clientId,
        'client_secret=' + clientSecret,
        'grant_type=authorization_code',
        'redirect_uri=' + encodeURIComponent(appRedirectUrl),
    ];

    if ( !authCode ) {
        const error_data: OIDCResponse = {
            error: 'invalid_code',
            error_description: 'Invalid code',
            access_token: null,
            refresh_token: null,
            id_token: null
        }
        return error_data;
    }

    const res = await fetch(`${oidcBaseUrl}/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formBody.join('&')
    });

    if ( res.ok ) {
        const data: OIDCResponse = await res.json();
        return data;
    } else {
        const data: OIDCResponse = await res.json();
        console.log('response not ok');
        console.log(data);
        console.log(formBody.join('&'));
        return data;
    }
}

export async function initiateBackChannelOIDCLogout(access_token: string, clientId: string, clientSecret: string, oidcBaseUrl: string, refresh_token: string): Promise<OIDCFailureResponse>  {
    let formBody = [
        'client_id=' + clientId,
        'client_secret=' + clientSecret,
        'refresh_token=' + refresh_token
    ];

    if ( !access_token || !refresh_token ) {
        const error_data = {
            error: 'invalid_grant',
            error_description: 'Invalid tokens'
        }
        return error_data;
    }

    const res = await fetch(`${oidcBaseUrl}/logout`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Bearer ${access_token}`
        },
        body: formBody.join('&')
    });

    if ( res.ok ) {
        return {
            error: null,
            error_description: null
        }
    } else {
        const error_data: OIDCResponse = await res.json();
        console.log('logout response not ok');
        console.log(error_data);
        console.log(formBody.join('&'));
        return error_data;
    }
}

export async function renewOIDCToken(refresh_token: string, oidcBaseUrl: string, clientId: string, clientSecret: string): Promise<OIDCResponse>  {
    let formBody = [
        'refresh_token=' + refresh_token,
        'client_id=' + clientId,
        'client_secret=' + clientSecret,
        'grant_type=refresh_token',
    ];

    if ( !refresh_token ) {
        const error_data: OIDCResponse = {
            error: 'invalid_grant',
            error_description: 'Invalid tokens',
            access_token: null,
            refresh_token: null,
            id_token: null
        }
        return error_data;
    }

    const res = await fetch(`${oidcBaseUrl}/token`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formBody.join('&')
    });

    if ( res.ok ) {
        const newToken = await res.json()
        const data: OIDCResponse = {
            ...newToken,
			refresh_token: isTokenExpired(refresh_token) ? newToken.refresh_token : refresh_token
        };
        return data;
    } else {
        const data: OIDCResponse = await res.json();
        console.log('renew response not ok');
        console.log(data);
        return data;
    }
}

export async function introspectOIDCToken(access_token: string, oidcBaseUrl: string, clientId: string, clientSecret: string, username: string): Promise<any>  {
    let formBody = [
        'token=' + access_token,
        'client_id=' + clientId,
        'client_secret=' + clientSecret,
        'username=' + username,
    ];

    if ( !access_token ) {
        const error_data: OIDCResponse = {
            error: 'invalid_grant',
            error_description: 'Invalid tokens',
            access_token: null,
            refresh_token: null,
            id_token: null
        }
        return error_data;
    }

    const res = await fetch(`${oidcBaseUrl}/token/introspect`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: formBody.join('&')
    });

    if ( res.ok ) {
        const tokenIntrospect = await res.json() 
        return tokenIntrospect;
    } else {
        const data: OIDCResponse = await res.json();
        console.log('introspect response not ok');
        console.log(data);
        return data;
    }
}


export const populateRequestLocals = (event: RequestEvent, keyName: string, userInfo, defaultValue) => {
	if ( event.request.headers[keyName] ) {
		event.locals[keyName] = event.request.headers[keyName];
	} else {
		if ( userInfo[keyName] && userInfo[keyName] !== "null" && userInfo[keyName] !== "undefined" ) {
			event.locals[keyName] = userInfo[keyName];
		} else {
			event.locals[keyName] = defaultValue;
		}
	}
	return event;
}

export const populateResponseHeaders = (event: RequestEvent, response: ResponseInit) => {
	if ( event.locals.user ) {
		response.headers['user'] = `${JSON.stringify(event.locals.user)}`;
	}

	if ( event.locals.userid ) {
		response.headers['userid'] = `${event.locals.userid}`;
	}
	
	if ( event.locals.access_token ) {
		response.headers['access_token'] = `${event.locals.access_token}`;
	}
	if ( event.locals.refresh_token ) {
		response.headers['refresh_token'] = `${event.locals.refresh_token}`;
	}
	return response;
}

export const injectCookies = (event: RequestEvent, response: ResponseInit) => {
	let responseCookies = {};
	let serialized_user = null;

	try{
		serialized_user = JSON.stringify(event.locals.user);
	} catch {
		event.locals.user = null;
	}
	responseCookies = {
		userid: `${event.locals.userid}`,
		user: `${serialized_user}`
	};
	responseCookies['refresh_token'] = `${event.locals.refresh_token}`;
	let cookieAtrributes = 'Path=/; HttpOnly; SameSite=Lax;';
	if ( event.locals?.cookieAttributes ) {
		cookieAtrributes = event.locals.cookieAttributes;
	}
	response.headers['set-cookie'] = `userInfo=${JSON.stringify(responseCookies)}; ${cookieAtrributes}`;
	return response;
}

export const parseUser = (event: RequestEvent, userInfo) => {
    let userJsonParseFailed = false;
    try {
		if ( event.request.headers.get('user') ) {
			event.locals.user = JSON.parse(event.request.headers.get('user'));
		} else {
			if ( userInfo?.user && userInfo?.user !== "null" && userInfo?.user !== "undefined") {
				event.locals.user = JSON.parse(userInfo.user);
				if ( !event.locals.user) {
					userJsonParseFailed = true;
				}
			} else {
				throw {
					error: 'invalid_user_object'
				}
			}
		}
	} catch {
		userJsonParseFailed = true;
		event.locals.user = null;
	}
    return userJsonParseFailed;
}

const isAuthInfoInvalid = (obj: Record<string, any>) => {
	return (!obj?.userid || !obj?.access_token || !obj?.refresh_token || !obj?.user );
}

export const userDetailsGenerator: UserDetailsGeneratorFn = async function* (event: RequestEvent, clientSecret: string) {
    console.log('Request path:', event.url.pathname);
	const cookies = event.request.headers.get('cookie') ? parseCookie(event.request.headers.get('cookie') || '') : null;
	// console.log(cookies);
	const userInfo = cookies?.['userInfo'] ? JSON.parse(cookies?.['userInfo']) : {};
    event.locals.retries = 0;
	event.locals.authError = {
		error: null,
		error_description: null
	};


	populateRequestLocals(event, 'userid', userInfo, '');
	populateRequestLocals(event, 'access_token', userInfo, null);
	populateRequestLocals(event, 'refresh_token', userInfo, null);

	let ssr_redirect = false;
	let ssr_redirect_uri = '/';

	// Handling user logout
	if ( event.url.searchParams.get('event') === 'logout' ) {
		await initiateBackChannelOIDCLogout(event.locals.access_token, clientId, clientSecret, oidcBaseUrl, event.locals.refresh_token);
		event.locals.access_token = null;
		event.locals.refresh_token = null;
		event.locals.authError  = {
			error: 'invalid_session',
			error_description: 'Session is no longer active'
		};
		event.locals.user = null;
		ssr_redirect_uri = event.url.pathname;
		let response: ResponseInit =  {
			status: 302,
			headers: {
				'Location': ssr_redirect_uri
			}
		}
		try {
			response = populateResponseHeaders(event, response);
			response = injectCookies(event, response);
		} catch(e) {}
		return response;
	}


	// Parsing user object
	const userJsonParseFailed = parseUser(event, userInfo);
		
	// Backchannel Authorization code flow
	if ( event.url.searchParams.get('code') && (!isAuthInfoInvalid(event.locals) || isTokenExpired(event.locals.access_token)) ) {
		const jwts: OIDCResponse = await initiateBackChannelOIDCAuth(event.url.searchParams.get('code'), clientId, clientSecret, oidcBaseUrl, appRedirectUrl + event.url.pathname);
		if ( jwts.error ) {
			event.locals.authError = {
				error: jwts.error,
				error_description: jwts.error_description
			}
		} else {
			event.locals.access_token = jwts?.access_token;
			event.locals.refresh_token = jwts?.refresh_token;
		}
		ssr_redirect = true;
		ssr_redirect_uri = event.url.pathname;
	}
	
	const tokenExpired = isTokenExpired(event.locals.access_token);
	const beforeAccessToken = event.locals.access_token;

    event = {...event, ...yield};
	
    let response: ResponseInit = {status: 200, headers: {}};
	const afterAccessToken = event.locals.access_token;

	const headersMap = {};
	event.request.headers.forEach((val, key) => {
		headersMap[key] = val;
	})
	if ( ( isAuthInfoInvalid(headersMap) || tokenExpired) ) {
		response = populateResponseHeaders(event, response);
	}
	if ( ( isAuthInfoInvalid(userInfo) || (event.locals?.user && userJsonParseFailed ) || tokenExpired || (beforeAccessToken!==afterAccessToken)) ) {
		// if this is the first time the user has visited this app,
		// set a cookie so that we recognise them when they return
		response = injectCookies(event, response);
	}
	if ( ssr_redirect ) {
		response.status = 302;
		response.headers['Location'] = ssr_redirect_uri;
	}

	return response;
} 



export const getUserSession: GetUserSessionFn = async (event: RequestEvent, clientSecret: string) => {
    try {
		if ( event.locals?.access_token ) {
			if ( event.locals.user && event.locals.userid && !isTokenExpired(event.locals.access_token) ) {
				let isTokenActive = true;
				try {
					const tokenIntrospect = await introspectOIDCToken(event.locals.access_token, oidcBaseUrl, clientId, clientSecret, event.locals.user.preferred_username )
					isTokenActive = Object.keys(tokenIntrospect).includes('active') ? tokenIntrospect.active : false;
					console.log('token active ', isTokenActive);
				} catch(e) {
					isTokenActive = false;
					console.error('Error while fetching introspect details', e);
				}
				if ( isTokenActive ) {
					return {
						user: {...event.locals.user },
						access_token: event.locals.access_token,
						refresh_token: event.locals.refresh_token,
						userid: event.locals.user.sub,
						auth_server_online: true
					}
				}
			}
			try {
				const testAuthServerResponse = await fetch(import.meta.env.VITE_OIDC_ISSUER,{
					headers: {
						'Content-Type': 'application/json'
					}
				});
				if ( !testAuthServerResponse.ok ) {
					throw {
						error: await testAuthServerResponse.json()
					}
				}
			} catch (e) {
				throw {
					error: 'auth_server_conn_error',
					error_description: 'Auth Server Connection Error'
				}
			}
			const res = await fetch(`${oidcBaseUrl}/userinfo`, {
				headers: {
					'Content-Type': 'application/json',
					'Authorization': `Bearer ${event.locals.access_token}`
				}
			});
			if ( res.ok ) {
				const data = await res.json();
                // console.log('userinfo fetched');
				event.locals.userid = data.sub;
				event.locals.user = {...data};
				return {
					user: {
						// only include properties needed client-side —
						// exclude anything else attached to the user
						// like access tokens etc
						...data
					}, 
					access_token: event.locals.access_token,
					refresh_token: event.locals.refresh_token,
					userid: data.sub,
					auth_server_online: true
				}
			} else {
				try {
                	const data = await res.json();
					// console.log(data, import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES);
					if ( data?.error && event.locals?.retries < import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES) {
						console.log('old token expiry', isTokenExpired(event.locals.access_token));
						const newTokenData = await renewOIDCToken(event.locals.refresh_token, oidcBaseUrl, clientId, clientSecret);
						// console.log(newTokenData);
						if ( newTokenData?.error ) {
							throw {
								error: data?.error ? data.error : 'user_info error',
								error_description: data?.error_description ? data.error_description :"Unable to retrieve user Info"
							}
						} else {
							event.locals.access_token = newTokenData.access_token;
							event.locals.retries = event.locals.retries + 1;
							return await getUserSession(event, clientSecret);
						}
					}
					
					throw {
						error: data?.error ? data.error : 'user_info error',
						error_description: data?.error_description ? data.error_description :"Unable to retrieve user Info"
					}
				} catch (e) {
					// console.error('Error while refreshing access_token; access_token is invalid', e);
					throw {
						...e
					}
				}
            }
		} else {
			// console.error('getSession request.locals.access_token ', request.locals.access_token);
			try {
				if ( event.locals?.retries < import.meta.env.VITE_OIDC_TOKEN_REFRESH_MAX_RETRIES) {
					console.log('old token expiry', isTokenExpired(event.locals.access_token));
					const newTokenData = await renewOIDCToken(event.locals.refresh_token, oidcBaseUrl, clientId, clientSecret);
					// console.log(newTokenData);
					if ( newTokenData?.error ) {
						throw {
							error: newTokenData.error,
							error_description: newTokenData.error_description
						}
					} else {
						event.locals.access_token = newTokenData.access_token;
						event.locals.retries = event.locals.retries + 1;
						return await getUserSession(event, clientSecret);
					}
				}
				
			} catch (e) {
				console.error('Error while refreshing access_token; access_token is missing', e);
			}
			try {
				const testAuthServerResponse = await fetch(import.meta.env.VITE_OIDC_ISSUER,{
					headers: {
						'Content-Type': 'application/json'
					}
				});
				if ( !testAuthServerResponse.ok ) {
					throw {
						error: await testAuthServerResponse.json()
					}
				}
			} catch (e) {
				throw {
					error: 'auth_server_conn_error',
					error_description: 'Auth Server Connection Error'
				}
			}
			throw {
				error: 'missing_jwt',
				error_description: 'access token not found or is null'
			}
		}
	} catch (err) {
		event.locals.access_token = '';
		event.locals.refresh_token = '';
		event.locals.userid = '';
		event.locals.user = null;
		if ( err?.error ) {
			event.locals.authError.error = err.error;
		}
		if ( err?.error_description ) {
			event.locals.authError.error_description = err.error_description;
		}
		return {
			user: null,
			access_token: null,
			refresh_token: null,
			userid: null,
            error: (event.locals.authError?.error ? event.locals.authError : null),
			auth_server_online: err.error !== 'auth_server_conn_error' ? true : false
		}
	}
}