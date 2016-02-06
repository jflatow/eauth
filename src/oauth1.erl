-module(oauth1).
-author("Jared Flatow").

%% OAuth 1.0a (RFC 5849)
%%
%% There are 3 steps to authorization:
%%  1. request temporary credentials  (client <-> server)
%%  2. authorize the resource owner   (user   <-> server)
%%  3. request token credentials      (client <-> server)

-export([initiate_authorization/3,
         continue_authorization/3,
         complete_authorization/3,
         retrieve_resource/3]).

-export([temporary_credentials_request/2,
         authorization_request/2,
         token_request/3]).

-export([authorized_request/3,
         authorized_request/4]).

-export([alg_oauth/1,
         oauth_alg/1]).

-import(oauth2, [http_request/4]).

-spec temporary_credentials_request(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{
        %% <<"oauth_callback">> => binary()  %% required
       }.

-spec authorization_request(Conf, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      Params :: #{}.

-spec token_request(Conf, TemporaryCredentials, Params) -> eauth:request() when
      Conf :: eauth:conf(),
      TemporaryCredentials :: #{
        %% <<"oauth_token">> => binary(),    %% required
       },
      Params :: #{
        %% <<"oauth_verifier">> => binary()  %% required
       }.

initiate_authorization(Conf, Params, StateValue) ->
    %% Unlike oauth2, if one overrides the callback, the state token won't make sense
    StateToken = eauth:state_token(StateValue),
    Defaults = #{
      <<"oauth_callback">> =>
          url:qu(util:get(Conf, redirect_uri), #{state => StateToken})
     },
    {'client',
     {temporary_credentials_request(Conf, util:update(Defaults, Params)), StateToken},
     fun continue_authorization/3}.

continue_authorization(Conf, Params, StateToken) ->
    {'user-agent',
     {authorization_request(Conf, Params), StateToken},
     fun complete_authorization/3}.

complete_authorization(Conf, Params, StateToken) ->
    %% The state token must match, if not its the caller's fault
    StateToken = util:get(Params, <<"state">>, <<>>),
    StateValue = eauth:state_value(StateToken),
    Temp = util:select(Params, [<<"oauth_token">>, <<"oauth_token_secret">>]),
    Params1 = util:except(Params, [<<"oauth_token">>, <<"oauth_token_secret">>]),
    {'client', {token_request(Conf, Temp, Params1), StateValue}, nil}.

retrieve_resource(Conf, Descriptor, TokenInfo) ->
    {'client', {authorized_request(Conf, Descriptor, TokenInfo), TokenInfo}, nil}.

temporary_credentials_request(Conf, Params) ->
    Descriptor = {util:get(Conf, temporary_credentials_method, post),
                  util:get(Conf, temporary_credentials_uri),
                  util:get(Conf, temporary_credentials_headers, []), Params},
    authorized_request(Conf, Descriptor, #{}).

authorization_request(Conf, Params) ->
    http_request(get,
                 util:get(Conf, authorization_uri),
                 util:get(Conf, authorization_headers, []), Params).

token_request(Conf, TemporaryCredentials, Params) ->
    Descriptor = {util:get(Conf, token_method, post),
                  util:get(Conf, token_uri),
                  util:get(Conf, token_headers, []), Params},
    authorized_request(Conf, Descriptor, TemporaryCredentials).

authorized_request(Conf, Descriptor, TokenInfo) ->
    authorized_request(Conf, Descriptor, TokenInfo, util:get(Conf, signature_type)).

authorized_request(Conf, Descriptor = {Method, URL, _, Params}, TokenInfo, SignType) ->
    Auth = oauth_params(Conf, TokenInfo, {Method, URL, Params}),
    authorized_request(Conf, Descriptor, TokenInfo, SignType, Auth).

authorized_request(Conf, Descriptor, TokenInfo, undefined, Auth) ->
    authorized_request(Conf, Descriptor, TokenInfo, header, Auth);

authorized_request(_Conf, {Method, URL, Headers, Params}, _TokenInfo, header, Auth) ->
    Value = util:join([[url:esc(K), "=\"", url:esc(V), "\""] || {K, V} <- util:iter(Auth)], ","),
    Headers1 = [{"Authorization", ["OAuth ", Value]}|Headers],
    http_request(Method, URL, Headers1, Params);
authorized_request(_Conf, {Method, URL, Headers, Params}, _TokenInfo, _, Auth) ->
    http_request(Method, URL, Headers, util:update(Params, Auth)).

oauth_params(Conf, TokenInfo, Raw) ->
    Base = #{<<"oauth_consumer_key">> => util:get(Conf, client_id)},
    Base1 = util:update(Base, util:select(TokenInfo, [<<"oauth_token">>])),
    oauth_params(Conf, TokenInfo, Raw, Base1).

oauth_params(Conf, TokenInfo, Raw, Base) ->
    oauth_params(Conf, TokenInfo, Raw, Base, util:get(Conf, signature_alg)).

oauth_params(Conf, TokenInfo, Raw, Base, undefined) ->
    oauth_params(Conf, TokenInfo, Raw, Base, {hmac, sha});

oauth_params(Conf, TokenInfo, _, Base, plaintext) ->
    Base#{
      <<"oauth_signature_method">> => <<"PLAINTEXT">>,
      <<"oauth_signature">> =>
          [util:get(Conf, client_secret), "&",
           util:get(TokenInfo, <<"oauth_token_secret">>, <<>>)]
     };
oauth_params(Conf, TokenInfo, Raw, Base, {hmac, sha}) ->
    sign_oauth_params(Raw, Base, {hmac, sha},
                      [util:get(Conf, client_secret), "&",
                       util:get(TokenInfo, <<"oauth_token_secret">>, <<>>)]);
oauth_params(Conf, _, Raw, Base, {rsa, sha}) ->
    sign_oauth_params(Raw, Base, {rsa, sha}, util:get(Conf, client_key)).

sign_oauth_params(Raw, Base, Alg, Key) ->
    Pre = Base#{
            <<"oauth_signature_method">> => alg_oauth(Alg),
            <<"oauth_timestamp">> => util:bin(time:unix()),
            <<"oauth_nonce">> => base64:encode(crypto:rand_bytes(24))
           },
    Pre#{<<"oauth_signature">> => signature(Raw, Pre, Alg, Key)}.

signature(Raw, Auth, Alg, Key) ->
    base64:encode(cipher:sign(Alg, Key, signature_base_string(Raw, Auth))).

signature_base_string({Method, URL, Params}) ->
    util:bin([normalized_method(Method), "&",
              normalized_uri(URL), "&",
              normalized_params(Params)]).

signature_base_string({Method, URL, Params}, Auth) ->
    signature_base_string({Method, URL, util:update(Params, Auth)}).

normalized_method(Method) ->
    url:esc(str:upper(util:str(Method))).

normalized_uri(URL) when not is_map(URL) ->
    normalized_uri(url:parse(URL));
normalized_uri(URL = #{query := Q}) when Q =/= undefined ->
    normalized_uri(URL#{query => undefined});
normalized_uri(URL = #{fragment := F}) when F =/= undefined ->
    normalized_uri(URL#{fragment => undefined});
normalized_uri(URL) ->
    %% NB: assumes scheme, host, port, path are already normalized
    url:esc(url:format(URL)).

normalized_params(Params) ->
    Itered = util:iter(Params),
    Sorted = lists:sort([[url:esc(K), "=", url:esc(V)] || {K, V} <- Itered]),
    url:esc(str:join(Sorted, "&")).

alg_oauth({hmac, sha}) -> <<"HMAC-SHA1">>;
alg_oauth({rsa, sha})  -> <<"RSA-SHA1">>.

oauth_alg(<<"HMAC-SHA1">>) -> {hmac, sha};
oauth_alg(<<"RSA-SHA1">>)  -> {rsa, sha}.
