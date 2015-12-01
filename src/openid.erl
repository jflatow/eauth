-module(openid).
-author("Jared Flatow").

%% OpenID Connect 1.0 (https://openid.net/specs/openid-connect-core-1_0.html)
%% OpenID Discovery 1.0 (https://openid.net/specs/openid-connect-discovery-1_0.html)

-export([configuration_request/1]).

configuration_request(Issuer) ->
    Path =
        case url:rd(path, Issuer) of
            [] ->
                ["/", ".well-known", "openid-configuration"];
            P ->
                P ++ [".well-known", "openid-configuration"]
        end,
    {http, {get, url:pz(Issuer, Path), [], []}}.
