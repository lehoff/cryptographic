%% @copyright 2009, Group Hula
%% @author Nicholas Gunder <nicholasgunder@yahoo.com>
%% Created : Jul 1, 2009

-module(entropy).

-behaviour(gen_server).
%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------

%% --------------------------------------------------------------------
%% External exports
-export([start_link/0, start_link/1, entropy/1, stop/0, test/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, 
         terminate/2, code_change/3]).

-record(state, {port, cur_req_num = 0, requests = gb_trees:empty()}).

-define(DEFAULT_ENTROPY_LOC, "security/bin/entropy.exe").
%% ====================================================================
%% External functions
%% ====================================================================
start_link() ->
    gen_server:start_link({global, ?MODULE}, ?MODULE,
                          [?DEFAULT_ENTROPY_LOC], []).
start_link(CProg) ->
    gen_server:start_link({global, ?MODULE}, ?MODULE,
                          [CProg], []).

%% @spec entropy(NumOfBytes::int()) -> Bytes::list()
%%
%% @doc Return a random binary. Can also be changed to return a random list of numbers.
%% The function will start the server if it is not already started.
entropy(NumOfBytes) ->
    Pid = check_and_restart(),
    gen_server:call(Pid, {entropy, NumOfBytes}).

%% @spec stop() -> ok
stop() ->
    gen_server:cast({global, ?MODULE}, stop).

%% ====================================================================
%% Server functions
%% ====================================================================

%% --------------------------------------------------------------------
%% Function: init/1
%% Description: Initiates the server
%% Returns: {ok, State}          |
%%          {ok, State, Timeout} |
%%          ignore               |
%%          {stop, Reason}
%% --------------------------------------------------------------------
init([CProg]) ->
    Port = erlang:open_port({spawn, CProg}, [{packet, 2}, binary, 
					     exit_status]),
    {ok, #state{port = Port, cur_req_num = 1, requests = gb_trees:empty()}}.

%% --------------------------------------------------------------------
%% Function: handle_call/3
%% Description: Handling call messages
%% Returns: {reply, Reply, State}          |
%%          {reply, Reply, State, Timeout} |
%%          {noreply, State}               |
%%          {noreply, State, Timeout}      |
%%          {stop, Reason, Reply, State}   | (terminate/2 is called)
%%          {stop, Reason, State}            (terminate/2 is called)
%% --------------------------------------------------------------------
handle_call({entropy, NumOfBytes}, From, State = #state{cur_req_num = CrN,
														 requests = ReqTree}) ->
	CrN2 = case CrN of
			   16#FFFFFFFF ->
				   0;
			   CrN ->
                   CrN + 1
           end,
	ReqTree2 = gb_trees:enter(CrN2, From, ReqTree),
    Msg = {entropy_gen, NumOfBytes, CrN2},
    erlang:port_command(State#state.port, term_to_binary(Msg)),
    {noreply, State#state{cur_req_num = CrN2, requests = ReqTree2}};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%% --------------------------------------------------------------------
%% Function: handle_cast/2
%% Description: Handling cast messages
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%% --------------------------------------------------------------------
handle_cast(stop, State) ->
    {stop, normal, State};
handle_cast(_Msg, State) ->
    {noreply, State}.

%% --------------------------------------------------------------------
%% Function: handle_info/2
%% Description: Handling all non call/cast messages
%% Returns: {noreply, State}          |
%%          {noreply, State, Timeout} |
%%          {stop, Reason, State}            (terminate/2 is called)
%% --------------------------------------------------------------------
handle_info({_Port, {data, Bin}}, State = #state{requests = ReqTree}) ->
    {ok_entropy, Nums, ReqNumber} = binary_to_term(Bin),
    From = gb_trees:get(ReqNumber, ReqTree),
    ReqTree2 = gb_trees:delete(ReqNumber, ReqTree),
	gen_server:reply(From, list_to_binary(Nums)),
	{noreply, State#state{requests = ReqTree2}};
handle_info(Info, State) ->
    io:format("Unknown Info ~w~n", [Info]),
    {noreply, State}.

%% --------------------------------------------------------------------
%% Function: terminate/2
%% Description: Shutdown the server
%% Returns: any (ignored by gen_server)
%% --------------------------------------------------------------------
terminate(_Reason, State) ->
    erlang:port_close(State#state.port),
    ok.

%% --------------------------------------------------------------------
%% Func: code_change/3
%% Purpose: Convert process state when code is changed
%% Returns: {ok, NewState}
%% --------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% --------------------------------------------------------------------
%%% Internal functions
%% --------------------------------------------------------------------
check_and_restart() ->
    case global:whereis_name(?MODULE) of
        undefined ->
            case start_link() of
                {error, {already_started, Pid}} ->
                    Pid;
                {ok, Pid} ->
                    Pid
            end;
        Pid ->
            Pid
    end.


test(1) ->
	entropy:start_link("h:/hula/security/bin/entropy.exe"),
	entropy:entropy(10).


