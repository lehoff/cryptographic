%%%-------------------------------------------------------------------
%%% File    : hash_random.erl
%%% Author  : Torben Hoffmann <torben.lehoff@gmail.com>
%%% Description : implementation of a DRBG based on a hash function as per 
%%%               NIST Special Publication 800-90
%%% Created : 29 Jun 2009 by Torben Hoffmann <torben.lehoff@gmail.com>
%%%-------------------------------------------------------------------
-module(hash_random).

-behaviour(gen_server).

-compile(export_all).

%% API
-export([start_link/1]).

-export([get_bits/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-export([test_entropy/1,test/1]).

-import(cg_math,
	[ceiling/1,
	 pow/2
	]).

-define(SECURITY_STRENGTH,256). %% sha512
-define(SEEDLEN,888).
-define(OUTLEN_SHA512,512).
-define(RESEED_INTERVAL, 4294967296).
%%		int_pow(2,32)). %% < 2^48 so could be higher than 2^32.

-record(state, 
	{'V',
	 'C',
	 reseed_counter,  %% Integer()
	 entropy_input,   %% {M,F} called as M:F(NoOfBits)
	 %%additional_input,%% Binary(). NOT SUPPORTED YET.	
	 hash={{sha2,hexdigest512},?OUTLEN_SHA512}
	 %% {{M,F},Outlen::Integer()} called as M:F(Bitstring())
	}).


%%====================================================================
%% API
%%====================================================================
%%--------------------------------------------------------------------
%% Function: start_link() -> {ok,Pid} | ignore | {error,Error}
%% Description: Starts the server
%%--------------------------------------------------------------------
start_link(Props) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Props, []).

%% @spec get_bits(NoBits) -> Integer
%%
%% @doc get_bits(NoBits) returns a random number which is NoBits in size.
get_bits(NoBits) ->
	gen_server:call(?MODULE, {get_bits,NoBits}).


%%====================================================================
%% gen_server callbacks
%%====================================================================

%%--------------------------------------------------------------------
%% Function: init(Args) -> {ok, State} |
%%                         {ok, State, Timeout} |
%%                         ignore               |
%%                         {stop, Reason}
%% Description: Initiates the server
%%--------------------------------------------------------------------
init(Props) ->
	InitState = lists:foldl(fun process_option/2,#state{},Props),
	State = instantiate(InitState),
    {ok, State}.

default_hash() ->
	{{sha2,hexdigest512},?OUTLEN_SHA512}.

process_option({entropy_input,MF},State) ->
    State#state{entropy_input=MF};
process_option({hash,_Hash},State) ->
	DefaultHash = default_hash(),
	State#state{hash=DefaultHash}.

%%--------------------------------------------------------------------
%% Function: %% handle_call(Request, From, State) -> {reply, Reply, State} |
%%                                      {reply, Reply, State, Timeout} |
%%                                      {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, Reply, State} |
%%                                      {stop, Reason, State}
%% Description: Handling call messages
%%--------------------------------------------------------------------
handle_call({get_bits,NoBits}, _From, State) ->
   	{Reply,NewState} = generate(State,NoBits),
    {reply, Reply, NewState}.

%%--------------------------------------------------------------------
%% Function: handle_cast(Msg, State) -> {noreply, State} |
%%                                      {noreply, State, Timeout} |
%%                                      {stop, Reason, State}
%% Description: Handling cast messages
%%--------------------------------------------------------------------
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: handle_info(Info, State) -> {noreply, State} |
%%                                       {noreply, State, Timeout} |
%%                                       {stop, Reason, State}
%% Description: Handling all non call/cast messages
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% Function: terminate(Reason, State) -> void()
%% Description: This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any necessary
%% cleaning up. When it returns, the gen_server terminates with Reason.
%% The return value is ignored.
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% Func: code_change(OldVsn, State, Extra) -> {ok, NewState}
%% Description: Convert process state when code is changed
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

%% @spec hash_df(InputString,Integer(),Hash) -> Bitstring()
hash_df(InputString,NoBits,Hash) when is_list(InputString) ->
	hash_df(list_to_binary(InputString),NoBits,Hash);
hash_df(InputBin,NoBits,{{M,F},Outlen}) ->
    Len = ceiling( NoBits / Outlen),
    Temp= lists:foldl(fun (Counter,Acc) ->
			      << Acc/binary,
				 (M:F(<<Counter:8,
					NoBits:32,
					InputBin/binary>>))/binary>>
		      end, 
		      <<>>, 
		      lists:seq(1, Len)),
    <<Leftmost:NoBits,_/binary>> = Temp,
    <<Leftmost:NoBits>>.

	

%% @spec instantiate(State) -> State
instantiate(#state{entropy_input={M,F},
				   hash=Hash}=State) ->
	SeedAndNonce = M:F(2*?SECURITY_STRENGTH),
	SeedMaterial = SeedAndNonce, %% personalization input should be added here.
	Seed = hash_df(SeedMaterial,?SEEDLEN,Hash),
	<<V:?SEEDLEN>> = Seed,
	<<C:?SEEDLEN>> = hash_df(<<0:8,Seed/binary>>,?SEEDLEN,Hash),
	State#state{'V'=V,
				'C'=C,
				reseed_counter=1
				}.

%% @spec generate(State, NoBits) -> {Bits,State}
 generate(#state{reseed_counter=ReseedCounter}=State, NoBits) 
  	when (ReseedCounter > ?RESEED_INTERVAL) ->
	NewState = reseed(State),
	generate(NewState,NoBits);
generate(#state{'V'=V, 'C'=C, hash={{M,F},_}=Hash, reseed_counter=ReseedCounter}=State,
		 NoBits) ->
	SeedlenMod = pow(2,?SEEDLEN),
	W = binary_to_integer(M:F(<<2:8,V:?SEEDLEN>>)),
	V2 = (W+V) rem SeedlenMod,
	Bits = hashgen(NoBits,V2,Hash),
	H = binary_to_integer(M:F(<<3:8,V2:?SEEDLEN>>)),
	NewV = (V2+H+C+ReseedCounter) rem SeedlenMod,
	{Bits,State#state{'V'=NewV, reseed_counter=ReseedCounter+1}}.

%% @spec hashgen(NoBits,V,Hash) -> NoBitsNumber
hashgen(NoBits,V,{{Mod,F},Outlen}) ->
	SeedlenMod = pow(2,?SEEDLEN),
	M = ceiling(NoBits/Outlen),
	W =lists:foldl(fun (Data,AccW) ->
							Wi = Mod:F(Data),
							<<AccW/bitstring,Wi/bitstring>>
				   end,
				   <<>>,
				   [ <<(X rem SeedlenMod):?SEEDLEN>> || X <- lists:seq(V, V+M)]),
	<<Leftmost:NoBits,_/bitstring>> = W,
	Leftmost.

%% @spec reseed(State) -> State
reseed(#state{'V'=V,entropy_input={M,F},hash=Hash}=State) ->
	SeedAndNonce = M:F(2*?SECURITY_STRENGTH),
	SeedMaterial = << 1:8, V/binary, SeedAndNonce/binary >>,
	Seed = hash_df(SeedMaterial,?SEEDLEN,Hash),
	NewC = hash_df(<<0:8,Seed/binary>>,?SEEDLEN,Hash),
	State#state{'V'=Seed,'C'=NewC,reseed_counter=1}.


%% @spec binary_to_integer(Binary|Bitstring) -> Integer
binary_to_integer(Bin) ->
	Size = bit_size(Bin),
 	<<Val:Size>> = Bin,
	Val.	

%% @spec test_entropy(NoBits) -> Bits
test_entropy(NoBits) when NoBits >512 ->
	First = test_entropy(512),
	Rest = test_entropy(NoBits-512),
	<<First/bitstring,Rest/bitstring>>;
test_entropy(NoBits) ->
    random:seed(now()),
	N = pow(2,NoBits),
	<<(random:uniform(N)):NoBits>>.

test(1) ->
	[{entropy_input,{?MODULE,test_entropy}}];
test(2) ->
	start_link(test(1));
test(3) ->
	[get_bits(4) || _ <- lists:seq(1,pow(2,4)*100)].
	

