<?php

namespace Idaas\Passport\Http\Controllers;

use Idaas\OpenID\RequestTypes\AuthenticationRequest;
use Idaas\Passport\ClientRepository;
use Idaas\Passport\PassportConfig;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository as LaravelClientRepository;
use Laravel\Passport\Http\Controllers\AuthorizationController as LaravelAuthorizationController;
use Laravel\Passport\Http\Controllers\ConvertsPsrResponses;
use Laravel\Passport\Http\Controllers\RetrievesAuthRequestFromSession;
use Laravel\Passport\TokenRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use Nyholm\Psr7\Response as Psr7Response;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationController extends LaravelAuthorizationController
{
    use ConvertsPsrResponses, RetrievesAuthRequestFromSession;

    public function isApproved(
        AuthorizationRequest $authRequest,
        ?Authenticatable $user,
        Client $client,
        TokenRepository $tokens
    ) {
        if ($user == null) {
            return false;
        }

        $scopes = $this->parseScopes($authRequest);

        $token = $tokens->findValidToken(
            $user,
            $client
        );

        return ($token && $token->scopes === collect($scopes)->pluck('id')->all());
    }

    public function returnError(AuthorizationRequest $authorizationRequest)
    {
        $clientUris = Arr::wrap($authorizationRequest->getClient()->getRedirectUri());

        if (!in_array($uri = $authorizationRequest->getRedirectUri(), $clientUris)) {
            $uri = Arr::first($clientUris);
        }

        if ($authorizationRequest instanceof AuthenticationRequest && $authorizationRequest->getResponseMode() == 'web_message') {
            return (new WebMessageResponse())->setData([
                'redirect_uri' => $uri,
                'error'  => 'access_denied',
                'state' => $authorizationRequest->getState(),
            ])->generateHttpResponse(new Psr7Response);
        } else {
            $separator = $authorizationRequest->getGrantTypeId() === 'implicit' ? '#' : '?';
            return $this->response->redirectTo(
                $uri . $separator . 'error=access_denied&state=' . $authorizationRequest->getState()
            );
        }
    }

    /**
     * In contrast with Laravel Passport, this authorize method can be invoked when the user has not been authenticated
     * This is because the OpenID Connect determines how to user should be authenticated
     */
    public function authorize(
        ServerRequestInterface $psrRequest,
        Request $request,
        LaravelClientRepository $clients,
        TokenRepository $tokens
    ) {

        $authRequest = $this->withErrorHandling(function () use ($psrRequest) {
            return $this->server->validateAuthorizationRequest($psrRequest);
        });

        $scopes = $this->parseScopes($authRequest);

        $token = $tokens->findValidToken(
            $user = $request->user(),
            $client = $clients->find($authRequest->getClient()->getIdentifier())
        );

        if (($token && $token->scopes === collect($scopes)->pluck('id')->all()) ||
            $client->skipsAuthorization()) {
            return $this->approveRequest($authRequest, $user);
        }

        $request->session()->put('authToken', $authToken = Str::random());
        $request->session()->put('authRequest', $authRequest);

        return $this->response->view('passport::authorize', [
            'client' => $client,
            'user' => $user,
            'scopes' => $scopes,
            'request' => $request,
            'authToken' => $authToken,
        ]);
    }

    public function doAuthenticate(ServerRequestInterface $psrRequest, $authorizationRequest)
    {
        return resolve(PassportConfig::class)
            ->doAuthenticationResponse(
                AuthenticationRequest::fromAuthorizationRequest($authorizationRequest)
            );
    }

    /**
     * Approve the authorization request.
     *
     * @param  \League\OAuth2\Server\RequestTypes\AuthorizationRequest  $authRequest
     * @param  \Illuminate\Database\Eloquent\Model  $user
     * @return \Illuminate\Http\Response
     */
    protected function approveRequest($authRequest, $user)
    {
        $authRequest->setUser(new User($user->getAuthIdentifier()));

        $authRequest->setAuthorizationApproved(true);

        return $this->withErrorHandling(function () use ($authRequest) {
            return $this->convertResponse(
                $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
            );
        });
    }

    /**
     * Deny the authorization request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    public function deny(Request $request)
    {
        $this->assertValidAuthToken($request);

        $authRequest = $this->getAuthRequestFromSession($request);

        $clientUris = Arr::wrap($authRequest->getClient()->getRedirectUri());

        if (! in_array($uri = $authRequest->getRedirectUri(), $clientUris)) {
            $uri = Arr::first($clientUris);
        }

        $separator = $authRequest->getGrantTypeId() === 'implicit' ? '#' : (strstr($uri, '?') ? '&' : '?');

        return $this->response->redirectTo(
            $uri.$separator.'error=access_denied&state='.$request->input('state')
        );
    }

    /**
     * Approve the authorization request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function approve(Request $request)
    {
        $this->assertValidAuthToken($request);

        $authRequest = $this->getAuthRequestFromSession($request);

        return $this->convertResponse(
            $this->server->completeAuthorizationRequest($authRequest, new Psr7Response)
        );
    }
}
