-module(oauth2).
-author("Jared Flatow").

%% OAuth 2.0 (RFC 67{49,50})
%%
%% There are 4 basic interactions, not all are used by all flows:
%%  1. obtain an authorization grant                 (user   <-> authorization server)
%%  2. exchange authorization grant for access token (client <-> authorization server)
%%  3. access resource using access token            (client <-> resource)
%%  4. refresh access token using refresh token      (client <-> authorization server)
%%
%% There are 3 builtin endpoints:
%%  1. authorization endpoint (user   -> authorization server)
%%  2. token endpoint         (client -> authorization server)
%%  3. redirection endpoint   (authorization server -> client)
%%
%% The spec defines 4 flows, plus a refresh, and an extension mechanism:
%%  1. authorization code
%%     authorization endpoint -> redirection endpoint -> token endpoint -> access token
%%  2. implicit
%%     authorization endpoint -> redirection endpoint -> access token
%%  3. resource owner password credentials
%%     token endpoint -> access token
%%  4. client credentials
%%     token endpoint -> access token
%%  5. refresh token
%%     token endpoint -> access token
%%  6. extension URI
%%     token endpoint -> access token

-export([initiate_authorization/3,
         complete_authorization/3,
         retrieve_resource/3]).

-export([authorization_request/2,
         authorization_request_and_state/2,
         token_request/2,
         token_from_authorization_code/2,
         token_from_password/2,
         token_from_client_credentials/2,
         token_from_refresh_token/2]).

-export([authorized_request/3,
         authorized_request/4]).

-export([http_request/4]).

-spec initiate_authorization(Conf, Params, StateValue) -> eauth:step() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"response_type">> => binary(), %% optional
        %% <<"scope">> => binary()          %% optional
       },
      StateValue :: term().

-spec complete_authorization(Conf, Params, StateToken) -> eauth:step() when
      Conf :: eauth:conf(),
      Params :: #{},
      StateToken :: binary().

-spec authorization_request(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"response_type">> => binary()  %% required
       }.

-spec authorization_request_and_state(Conf, Params) -> {eauth:request(), binary()} when
      Conf :: eauth:conf(),
      Params :: #{}.

-spec token_request(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"grant_type">> => binary()     %% required
       }.

-spec token_from_authorization_code(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"code">> => binary()           %% required
       }.

-spec token_from_password(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"username">> => binary(),      %% required
        %% <<"password">> => binary(),      %% required
        %% <<"scope">> => binary()          %% optional
       }.

-spec token_from_client_credentials(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"scope">> => binary()          %% optional
       }.

-spec token_from_refresh_token(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"refresh_token">> => binary(), %% required
        %% <<"scope">> => binary()          %% optional
       }.

initiate_authorization(Conf, Params, StateValue) ->
    Defaults = #{
      <<"response_type">> => <<"code">>,
      <<"client_id">> => util:get(Conf, client_id),
      <<"redirect_uri">> => util:get(Conf, redirect_uri),
      <<"state">> => eauth:state_token(StateValue)
     },
    {'user-agent',
     authorization_request_and_state(Conf, util:update(Defaults, Params)),
     fun complete_authorization/3}.

complete_authorization(Conf, Params, StateToken) ->
    %% The state token must match, for CSRF protection
    case util:get(Params, <<"state">>, <<>>) of
        StateToken ->
            complete_authorization(Conf, Params, StateToken, eauth:state_value(StateToken));
        _ ->
            {error, bad_state}
    end.

complete_authorization(Conf, Params, _, StateValue) ->
    case util:get(Params, <<"code">>) of
        undefined ->
            {error, {Params, StateValue}};
        Code ->
            {'client', {token_from_authorization_code(Conf, #{<<"code">> => Code}), StateValue}, nil}
    end.

retrieve_resource(Conf, Descriptor, TokenInfo) ->
    {'client', {authorized_request(Conf, Descriptor, TokenInfo), TokenInfo}, nil}.

authorization_request(Conf, Params) ->
    %% NB: auth endpoint *must* support GET and *may* support POST
    %%     although e.g. openid requires both GET and POST support
    http_request(util:get(Conf, authorization_method, get),
                 util:get(Conf, authorization_uri),
                 util:get(Conf, authorization_headers, []), Params).

authorization_request_and_state(Conf, Params) ->
    %% The state both stores continuation data and protects against CSRF
    %% e.g. on redirect we should also set a cookie containing the state
    {authorization_request(Conf, Params), util:get(Params, <<"state">>)}.

token_request(Conf, Params) ->
    %% Token requests *must* use POST and *must* authenticate the client
    token_request(Conf, Params, util:get(Conf, client_authentication, request_body)).

token_request(Conf, Params, http_basic) ->
    Credentials = base64:encode(util:bin([util:get(Conf, client_id), ":",
                                          util:get(Conf, client_secret)])),
    AuthHeaders = [{"Authorization", <<"Basic ", Credentials/binary>>}],
    http_request(post, util:get(Conf, token_uri), AuthHeaders, Params);
token_request(Conf, Params, request_body) ->
    AuthParams = #{
      <<"client_id">> => util:get(Conf, client_id),
      <<"client_secret">> => util:get(Conf, client_secret)
     },
    http_request(post, util:get(Conf, token_uri), [], util:update(Params, AuthParams));
token_request(Conf, Params, ClientAuth) when is_function(ClientAuth) ->
    %% NB: custom client auth must return a fully-formed post request
    %%     e.g. in case it needs to sign the whole thing, or whatever
    ClientAuth(Conf, Params).

token_from_authorization_code(Conf, Params) ->
    Defaults = #{
      <<"grant_type">> => <<"authorization_code">>,
      <<"redirect_uri">> => util:get(Conf, redirect_uri)
     },
    token_request(Conf, util:update(Defaults, Params)).

token_from_password(Conf, Params) ->
    Defaults = #{
      <<"grant_type">> => <<"password">>
     },
    token_request(Conf, util:update(Defaults, Params)).

token_from_client_credentials(Conf, Params) ->
    Defaults = #{
      <<"grant_type">> => <<"client_credentials">>
     },
    token_request(Conf, util:update(Defaults, Params)).

token_from_refresh_token(Conf, Params) ->
    Defaults = #{
      <<"grant_type">> => <<"refresh_token">>
     },
    token_request(Conf, util:update(Defaults, Params)).

authorized_request(Conf, Descriptor, TokenInfo) ->
    Type = str:lower(util:get(TokenInfo, <<"token_type">>)),
    authorized_request(Conf, Descriptor, TokenInfo, Type).

authorized_request(Conf, Descriptor, TokenInfo, undefined) ->
    Type = util:get(Conf, token_type, {bearer, header}),
    authorized_request(Conf, Descriptor, TokenInfo, Type);
authorized_request(Conf, Descriptor, TokenInfo, <<"bearer">>) ->
    authorized_request(Conf, Descriptor, TokenInfo, {bearer, header});

authorized_request(_Conf, {Method, URL, Headers, Params}, TokenInfo, {bearer, header}) ->
    Token = util:get(TokenInfo, <<"access_token">>),
    Headers1 = [{"Authorization", <<"Bearer ", Token/binary>>}|Headers],
    http_request(Method, URL, Headers1, Params);
authorized_request(_Conf, {Method, URL, Headers, Params}, TokenInfo, {bearer, param, Name}) ->
    Token = util:get(TokenInfo, <<"access_token">>),
    Params1 = util:modify(Params, Name, Token),
    http_request(Method, URL, Headers, Params1).

http_request(get, URL, Headers, Params) ->
    {http, {get, url:qu(URL, Params), Headers, []}};
http_request(post, URL, Headers, Params) ->
    {http, {post, URL, [{"Content-Type", "application/x-www-form-urlencoded"}|Headers], url:enc(Params)}}.
