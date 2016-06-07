-module(eauth_http).

-export([eval/3,
         parse/1,
         hackney/1,
         lhttpc/1,
         lhttpc/2]).

eval(Request, undefined, Parse) ->
    eval(Request, fun lhttpc/1, Parse);
eval(Request, Fetch, undefined) ->
    eval(Request, Fetch, fun parse/1);
eval(Request, Fetch, Parse) ->
    case Fetch(Request) of
        {ok, C, Headers, Body} when C >= 200, C < 300 ->
            {ok, Parse({Headers, Body})};
        {ok, C, Headers, Body} when C >= 300, C < 400 ->
            {redirect, {Headers, Body}};
        {ok, C, Headers, Body} when C >= 400->
            {error, Parse({Headers, Body})};
        {error, Reason} ->
            {error, Reason}
    end.

parse({Headers, Body}) ->
    case mime:content_type(Headers) of
        {"text/html", _} -> %% NB: twitter hack
            url:decode(Body);
        {"text/javascript", _} ->
            json:decode(Body);
        ContentType ->
            mimetype:decode(ContentType, Body)
    end.

hackney({Method, URL, Headers, Body}) -> %% NB: breaks linkedin
    case hackney:request(Method, URL, Headers, Body) of
        {ok, StatusCode, ResponseHeaders, ClientRef} ->
            {ok, ResponseBody} = hackney:body(ClientRef),
            {ok, StatusCode, ResponseHeaders, ResponseBody};
        {error, Reason} ->
            {error, Reason}
    end.

lhttpc(Request) ->
    lhttpc(Request, 8000).

lhttpc({Method, URL, Headers, Body}, Timeout) ->
    URL1 = util:str(URL),
    Headers1 = util:create(Headers, ['User-Agent'], lhttpc),
    case lhttpc:request(URL1, Method, Headers1, Body, Timeout) of
        {ok, {{StatusCode, _}, ResponseHeaders, ResponseBody}} ->
            {ok, StatusCode, ResponseHeaders, ResponseBody};
        {error, Reason} ->
            {error, Reason}
    end.
