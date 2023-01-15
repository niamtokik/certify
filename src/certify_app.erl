%%%-------------------------------------------------------------------
%% @doc certify public API
%% @end
%%%-------------------------------------------------------------------

-module(certify_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_StartType, _StartArgs) ->
    certify_sup:start_link().

stop(_State) ->
    ok.

%% internal functions
