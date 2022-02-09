import type { Handle, GetSession } from '@sveltejs/kit';
import { 
	userDetailsGenerator,
	getUserSession
} from '$lib';

import type { Locals, RequestEvent } from '$lib/types';

// const oidcBaseUrl = `${import.meta.env.VITE_OIDC_ISSUER}/protocol/openid-connect`;
// const clientId = `${import.meta.env.VITE_OIDC_CLIENT_ID}`;
// const appRedirectUrl = import.meta.env.VITE_OIDC_REDIRECT_URI;
const clientSecret = process.env.VITE_OIDC_CLIENT_SECRET || import.meta.env.VITE_OIDC_CLIENT_SECRET;

export const handle: Handle  = async ({ event, resolve }) => {
	const eventWithLocals = event as RequestEvent;
	// Initialization part
	const userGen = userDetailsGenerator(eventWithLocals, clientSecret);
	const { value, done } = await userGen.next();
	if ( done ) {
		const response = value;
		return response;
	}
	
	// Set Cookie attributes
	eventWithLocals.locals.cookieAttributes = 'Path=/; HttpOnly; SameSite=Lax;';

	// Your code here -----------
	if (eventWithLocals.url.searchParams.has('_method')) {
		//@ts-ignore request is readonly
		eventWithLocals.request.method = event.url.searchParams.get('_method').toUpperCase();
	}
	// Handle resolve
	const response = await resolve(event);
	const newResponse: ResponseInit = {...response};

	// After your code ends, Populate response headers with Auth Info
	// wrap up response by over-riding headers and status
	if ( newResponse?.status !== 404 ) {
		const extraResponse = (await userGen.next(eventWithLocals)).value;
		const { Location, ...restHeaders } = extraResponse.headers;
		// SSR Redirection
		if ( extraResponse.status === 302 && Location ) {
			newResponse.status = extraResponse.status;
			newResponse.headers = newResponse.headers || {};
			newResponse.headers['Location'] = Location;
		}
		newResponse.headers = {...response.headers, ...restHeaders};

	}
	return new Response(response.body, newResponse);
};


/** @type {import('@sveltejs/kit').GetSession} */
export const getSession: GetSession = async (request: RequestEvent) => {
	const userSession = await getUserSession(request, clientSecret);	
	return userSession;
}