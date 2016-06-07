-module(eauth_hub).
-author("Jared Flatow").

-export([prefs/0,
         dispatch/5]).

-export([initiate_login/4,
         complete_login/4,
         retrieve_userinfo/4,
         initiate_authorization/4,
         complete_authorization/4,
         refresh_authorization/4,
         retrieve_resource/4]).

-callback dispatch(Prefs, Provider, Conf, What, Opts) -> {function(), term()} when
      Prefs :: eauth:prefs(),
      Provider :: eauth:provider(),
      Conf :: eauth:conf(),
      What :: atom(),
      Opts :: #{}.

prefs() ->
    #{
       <<"dropbox">> => #{
           authorization_uri =>
               <<"https://www.dropbox.com/1/oauth2/authorize">>,
           token_uri =>
               <<"https://api.dropboxapi.com/1/oauth2/token">>,
           userinfo_uri =>
               <<"https://api.dropboxapi.com/1/account/info">>
          },

       <<"facebook">> => #{
           authorization_uri =>
               <<"https://www.facebook.com/dialog/oauth">>,
           token_uri =>
               <<"https://graph.facebook.com/v2.5/oauth/access_token">>,
           userinfo_uri =>
               <<"https://graph.facebook.com/me">>
          },

       <<"google">> => #{
           schema => openid,
           authorization_uri =>
               <<"https://accounts.google.com/o/oauth2/v2/auth">>,
           token_uri =>
               <<"https://www.googleapis.com/oauth2/v4/token">>,
           userinfo_uri =>
               <<"https://www.googleapis.com/oauth2/v3/userinfo">>
          },

       <<"github">> => #{
           authorization_uri =>
               <<"https://github.com/login/oauth/authorize">>,
           token_uri =>
               <<"https://github.com/login/oauth/access_token">>,
           userinfo_uri =>
               <<"https://api.github.com/user">>
          },

       <<"linkedin">> => #{
           authorization_uri =>
               <<"https://www.linkedin.com/uas/oauth2/authorization">>,
           token_uri =>
               <<"https://www.linkedin.com/uas/oauth2/accessToken">>,
           userinfo_uri =>
               <<"https://api.linkedin.com/v1/people/~">>
          },

       <<"slack">> => #{
           authorization_uri =>
               <<"https://slack.com/oauth/authorize">>,
           token_uri =>
               <<"https://slack.com/api/oauth.access">>,
           userinfo_uri =>
               <<"https://slack.com/api/auth.test">>,
           token_type =>
               {bearer, param, <<"token">>}
          },

       <<"twitter">> => #{
           schema => oauth1,
           temporary_credentials_uri =>
               <<"https://api.twitter.com/oauth/request_token">>,
           authorization_uri =>
               <<"https://api.twitter.com/oauth/authenticate">>,
           token_uri =>
               <<"https://api.twitter.com/oauth/access_token">>,
           userinfo_uri =>
               <<"https://api.twitter.com/1.1/account/verify_credentials.json">>
          }
     }.

dispatch(_Prefs, Provider, Conf, What, Opts) ->
    ?MODULE:What(Provider, util:get(Conf, schema, oauth2), Conf, Opts).

initiate_login(Provider = <<"slack">>, oauth2, Conf, Opts) ->
    Opts1 = util:accrue(Opts, [scopes], {addnew, ["identify"]}),
    initiate_authorization(Provider, oauth2, Conf, Opts1);
initiate_login(Provider, openid, Conf, Opts) ->
    Opts1 = util:accrue(Opts, [scopes], {addnew, ["openid", "profile"]}),
    initiate_authorization(Provider, oauth2, Conf, Opts1);
initiate_login(Provider, Schema, Conf, Opts) ->
    initiate_authorization(Provider, Schema, Conf, Opts).

complete_login(Provider, Schema, Conf, Opts) ->
    complete_authorization(Provider, Schema, Conf, Opts).

retrieve_userinfo(Provider = <<"facebook">>, oauth2, Conf, Opts) ->
    URL = util:get(Conf, userinfo_uri),
    FieldStr =
        case util:either([{Opts, [fields]}, {Conf, [userinfo_fields]}], []) of
            [] ->
                [];
            Fields ->
                str:join(Fields, $,)
        end,
    Query = #{fields => FieldStr},
    Descriptor = {get, URL, [], Query},
    retrieve_resource(Provider, oauth2, Conf, util:set(Opts, descriptor, Descriptor));
retrieve_userinfo(Provider = <<"linkedin">>, oauth2, Conf, Opts) ->
    URL = util:get(Conf, userinfo_uri),
    FieldStr =
        case util:either([{Opts, [fields]}, {Conf, [userinfo_fields]}], []) of
            [] ->
                [];
            Fields ->
                [":(", str:join(Fields, $,), ")"]
        end,
    Query = #{format => util:get(Opts, format, json)},
    Descriptor = {get, [URL, FieldStr], [], Query},
    retrieve_resource(Provider, oauth2, Conf, util:set(Opts, descriptor, Descriptor));
retrieve_userinfo(Provider, Schema, Conf, Opts) ->
    Descriptor = {util:get(Conf, userinfo_method, get),
                  util:get(Conf, userinfo_uri), [], []},
    retrieve_resource(Provider, Schema, Conf, util:set(Opts, descriptor, Descriptor)).

initiate_authorization(_Provider, Schema, _Conf, Opts) when Schema =:= oauth2;
                                                            Schema =:= openid ->
    Scopes = util:get(Opts, scopes, []),
    Params = util:modify(util:get(Opts, params, []), [<<"scope">>],
                         fun (undefined) ->
                                 str:join(Scopes, " ");
                             (Scope) ->
                                 str:join([Scope|Scopes], " ")
                         end),
    {fun oauth2:initiate_authorization/3, Params};
initiate_authorization(_Provider, oauth1, _Conf, Opts) ->
    {fun oauth1:initiate_authorization/3, util:get(Opts, params, [])}.

complete_authorization(_Provider, Schema, _Conf, Opts) when Schema =:= oauth2;
                                                            Schema =:= openid ->
    {fun oauth2:complete_authorization/3, util:get(Opts, params, [])};
complete_authorization(_Provider, oauth1, _Conf, Opts) ->
    {fun oauth1:complete_authorization/3, util:get(Opts, params, [])}.

refresh_authorization(_Provider, Schema, _Conf, Opts) when Schema =:= oauth2;
                                                           Schema =:= openid ->
    {fun oauth2:refresh_authorization/3, util:get(Opts, params, [])}.

retrieve_resource(_Provider, Schema, _Conf, Opts) when Schema =:= oauth2;
                                                       Schema =:= openid ->
    {fun oauth2:retrieve_resource/3, util:get(Opts, descriptor)};
retrieve_resource(_Provider, oauth1, _Conf, Opts) ->
    {fun oauth1:retrieve_resource/3, util:get(Opts, descriptor)}.
