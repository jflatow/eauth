-module(eauth).
-author("Jared Flatow").

-export([prefs/1,
         prefs/2,
         initiate_login/4,
         complete_login/4,
         retrieve_userinfo/4,
         initiate_authorization/4,
         complete_authorization/4,
         retrieve_resource/4]).

-export([dispatch/5,
         dispatch/6,
         dispatch/7,
         drive/6,
         execute_request/2]).

-export_type([prefs/0,
              provider/0,
              conf/0,
              request/0,
              step/0]).

-type prefs() :: #{
              hub => module(),
              http_fun => function(),
              http_parse => function(),
              provider() => conf()
             }.
-type provider() :: binary().
-type conf() :: map().
-type request() :: {http, {get | post, url:raw(), list(), iodata()}}.
-type step() :: {'client' | 'user-agent', {request(), term()}, function() | nil} | {error, term()}.

prefs(Overrides) ->
    prefs(eauth_hub:prefs(), Overrides).

prefs(Defaults, Overrides) ->
    util:fold(fun ({Provider, Conf}, Acc) ->
                      util:swap(Acc, Provider, fun (D) -> util:update(D, Conf) end)
              end, Defaults, Overrides).

initiate_login(Prefs, Provider, Opts, StateValue) ->
    dispatch(Prefs, Provider, initiate_login, Opts, StateValue).

complete_login(Prefs, Provider, Opts, StateToken) ->
    dispatch(Prefs, Provider, complete_login, Opts, StateToken).

retrieve_userinfo(Prefs, Provider, Opts, TokenInfo) ->
    dispatch(Prefs, Provider, retrieve_userinfo, Opts, TokenInfo).

initiate_authorization(Prefs, Provider, Opts, StateValue) ->
    dispatch(Prefs, Provider, initiate_authorization, Opts, StateValue).

complete_authorization(Prefs, Provider, Opts, StateToken) ->
    dispatch(Prefs, Provider, complete_authorization, Opts, StateToken).

retrieve_resource(Prefs, Provider, Opts, TokenInfo) ->
    dispatch(Prefs, Provider, retrieve_resource, Opts, TokenInfo).

dispatch(Prefs, Provider, What, Opts, State) ->
    dispatch(Prefs, Provider, util:get(Prefs, hub), What, Opts, State).

dispatch(Prefs, Provider, undefined, What, Opts, State) ->
    dispatch(Prefs, Provider, eauth_hub, What, Opts, State);
dispatch(Prefs, Provider, Hub, What, Opts, State) ->
    dispatch(Prefs, Provider, util:get(Prefs, Provider), Hub, What, Opts, State).

dispatch(_, _, undefined, _, _, _, _) ->
    {error, configuration};
dispatch(Prefs, Provider, Conf, Hub, What, Opts, State) ->
    case Hub:dispatch(Prefs, Provider, Conf, What, Opts) of
        {Fun, Arg} ->
            drive(Prefs, Provider, Conf, Fun, Arg, State)
    end.

drive(Prefs, Provider, Conf, Fun, Arg, State) ->
    case Fun(Conf, Arg, State) of
        {'client', {Request, State1}, Continue} ->
            case execute_request(Prefs, Request) of
                {ok, Arg1} when Continue =/= nil ->
                    drive(Prefs, Provider, Conf, Continue, Arg1, State1);
                {ok, Arg1} ->
                    {ok, {Arg1, State1}};
                Other ->
                    Other
            end;
        Other ->
            Other
    end.

execute_request(Prefs, {http, Req}) ->
    eauth_http:eval(Req, util:get(Prefs, http_fun), util:get(Prefs, http_parse)).
