%%%-------------------------------------------------------------------
%%% @author Martin Logan <martinjlogan@sixfoe>
%%% @copyright (C) 2008, Erlware
%%% @doc
%%%  Mathematical functions needed for cryptograpic functions but not supplied by Erlang standard libs.
%%% @end
%%% Created : 25 Mar 2008 by Martin Logan <martinjlogan@sixfoe>
%%%-------------------------------------------------------------------
-module(cg_math).

-compile(export_all).

%% API
-export([
	 primes/1, 
	 prime/1, 
	 is_prime/1, 
	 coprime/2,
	 small_coprime/1,
	 floor/1,
	 exp_mod/3,
	 gcd/2,
	 extended_gcd/2
	]).

-export([
	 rsa_primes/2
	]).

-export([ceiling/1,
	 pow/2
	 ]).

%% Needed for spawning.
-export([
	 numbers/2,
	 numbers/4,
	 filter/3,
	 filter/4,
	 wheel_is_prime/1,
	 filter_primes/2,
	 wheel_array/1
	 ]).

-export([test/1]).

-define(SMALL_PRIMES, [2,3,5,7,11,13,17,19,23,29,31,37,41,43, 47,53,59,61,67,71,73,79,83,89,97]).
-define(SMALL_E,2).
-define(BIG_E,4).
%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Returns all prime numbers from the first prime number to N
%% @spec primes(N) -> [integer()]
%% @end
%%--------------------------------------------------------------------
primes(N) when N < 2 ->
    [];
primes(2) ->
    [2];
primes(N) ->
    S         = lists:seq(3, N, 2),
    MRoot     = math:sqrt(N),
    Half      = length(S),
    primeit(S, MRoot, Half).

primeit(S, MRoot, Half) ->
    primeit(3, 0, array:from_list(S, 0), MRoot, Half).

primeit(M, _I, S, MRoot, _Half) when M > MRoot ->
    [2|array:sparse_to_list(S)];
primeit(M, I, S, MRoot, Half) ->
    NewI = I + 1,
    case array:get(I, S) of
	0 ->
	    primeit(2 * NewI + 3, NewI, S, MRoot, Half);
	_Int ->
	    J    = floor((M * M - 3) / 2),
	    NS   = vacumeit(array:set(J, 0, S), M, J, Half),
	    primeit(2 * NewI + 3, NewI, NS, MRoot, Half)
    end.
	    
vacumeit(S, _M, J, Half) when J >= Half ->
    S;
vacumeit(S, M, J, Half) ->
    vacumeit(array:set(J, 0, S), M, J + M, Half).

%%--------------------------------------------------------------------
%% @doc Generate a prime of requiring N number of bytes to represent or that is N decimal digits long.
%% @spec prime(N::integer(), Type) -> integer()
%% where
%%  Type = digits | bytes
%% @end
%%--------------------------------------------------------------------
prime(N, Type) ->
    TestPrime = random_odd_integer(N, Type),
    prime1(TestPrime).

%% @doc Generate a random provable prime following the guidelines of Appendix B.3.2.1 of FIPS 186-3.
%%
%% @spec rsa_primes(Nlen::Integer(), PublicE::integer()) -> {success,Integer(),Integer()} | failure
rsa_primes(Nlen,E) 
  when Nlen == 2048 orelse Nlen==3072, 
       E > ?SMALL_E, E < ?BIG_E, E rem 2 == 1 ->
    case seed_for_prime_gen(Nlen) of
	failure ->
	    failure;
	{success,Seed} -> %% This seed is guaranteed to have the right length.
	    try
		L = Nlen/2, N1=1, N2=1,
		{success,P,_P1,_P2,Pseed} = provable_prime_construction(L,N1,N2,Seed,E),
		{success,Q} = find_q_from_p(P,L,N1,N2,Pseed,E),	
		{success,P,Q}
	    catch
		_:_ -> failure
	    end	    
    end;
rsa_primes(_,_) -> failure.


%% @doc provable_prime_construction/5 implements the procedure in C.10 of FIPS 186-3-1
%% @todo get the -spec to work.
%-spec(provable_prime_construction(L::Integer(),N1::Integer(),N2::Integer(),FirstSeed::Integer(),E::Integer()) ->
%	     {success,P::Integer(),N1::Integer(),N2::Integer(),Pseed::Integer()} | failure ).
provable_prime_construction(L,N1,N2,FirstSeed,E) ->
    %% Step 2. and 3.
    {P1,P2seed} = 
	case N1 of
	    1 -> 
		{1,FirstSeed};
	    _ ->
		{success,Prime,PrimeSeed,_} = st_random_prime(N1,FirstSeed),
		{Prime,PrimeSeed}
	end,
    %% Step 4. and 5.
    {P2,P0seed} =
	case N2 of
	    1 -> 
		{1,P2seed};
	    _ ->
		{success,Prime2,PrimeSeed2,_} = st_random_prime(N1,P2seed),
		{Prime2,PrimeSeed2}
	end,
    %% Step 6.
    {success,P0,Pseed,_} = st_random_prime(ceiling(L/2)+1,P0seed),
    %% Step 7.
    Outlen = 512, %% @todo this is the outlen for hash512. 
    Hash = fun(X) ->
		   sha2:hexdigest512(X)
	   end,
    %% Should get this value based on the current hash function.
    %% Ask the hash_random server about this.
    Iterations = ceiling(L/Outlen) - 1, 
    %% Step 8.
    PgenCounter=0,
    %% Step 9. omitted
    %% Step 10. Initial X value.
    I = bogus,
    Power = pow(2,I*Outlen),
    X0 = xinit(Hash,Pseed,Power,Iterations),
    %% Step 11.
    PseedB=Pseed+Iterations+1,
    %% Step 12.
    %% Helpers.
    Pow2Lminus1 = pow(2,L-1),
    Pow2L = Pow2Lminus1 * 2,
    F = floor(math:sqrt(2)*Pow2Lminus1),
    X = F + X0 rem (Pow2L - F),
    %% Step 13.
    true = (1 /= gcd(P0*P1,P2)),
    %% Step 14.
    Y = st_compute_y(P0,P1,P2),
    %% Helpers
    P0P1 = P0 * P1,
    T0 = ceiling(2),
    T = case true of
	    true ->
		1;
	    false ->
		2
	end,
    %% More helpers
    P0P1P2 = P0P1 * P2,
    ModifyT = fun(OldT) when ((2*(OldT*P2-Y)*P0P1+1) > Pow2L) ->
		      ceiling(((2*Y*P0P1)+F)/(2*P0P1P2));
		 (OldT) ->
		      OldT
	      end,
    
    st_iterate_step_16_22(T,ModifyT,PgenCounter),
    ok.
		

st_iterate_step_16_22(_,_,_) ->  
    ok.

st_compute_y(P0,P1,P2) ->
    ok.

xinit(Hash,Pseed,Power,Iterations) ->
    xinit_iter(0,Hash,Pseed,Power,Iterations,0).

xinit_iter(X,Hash,Pseed,Power,Iterations,I) 
  when I =< Iterations ->
    NextX = X + Hash(Pseed+I) * Power,
    xinit_iter(NextX,Hash,Pseed,Power,Iterations,I+1);
xinit_iter(X,_,_,_,_,_) ->
    X.

%% @doc st_random_prime/2 implements the Shawe-Taylor random prime routine.
%%      See FIPS 186-3-1 C.6 p. 76.
% -spec(st_random_prime(Length::Integer(), InputSeed::Integer()) ->
%         failure | {success,Prime::Integer,PrimeSeed::Integer(),PrimeGenCounter::Integer()}).
st_random_prime(Length, InputSeed) ->
    Prime = 0,
    PrimeSeed=0,
    PrimeGenCounter=0,
    {success,Prime,PrimeSeed,PrimeGenCounter}.






%% @doc find_q_from_p is the looping in step 7-8 on pp 54-55 of FIPS 186-3-1.
find_q_from_p(P,L,N1,N2,Seed,E) ->
    {success,Q,_Q1,_Q2,Qseed} = provable_prime_construction(L,N1,N2,Seed,E),
    case math:abs(P-Q) =< hash_random:pow(2,L-100) of
	true ->
	    find_q_from_p(P,L,N1,N2,Qseed,E);
	false ->
	    {success,Q}
    end.


%% @doc seed_for_prime_gen/1 creates a seed of the necessary length
%% with regards to the security strength required for the bit length
%% of the prime that will be generated.

%-spec(seed_for_prime_gen(Nlen::Integer()) -> failure | {success,Seed::Integer()} ).
%-spec(seed_for_prime_gen(Integer()) -> failure | {success,Integer()}).
	      

seed_for_prime_gen(Nlen) when Nlen == 1024;
			      Nlen == 2048;
			      Nlen == 3072 ->
    SecurityStrength = security_strength_required(Nlen),
    Seed = hash_random:get_bits(2*SecurityStrength),
    %% hash_random uses SHA512 which has security strength 256, so it
    %% can be used here since 3072 requires 128 bits of security.
    {success,Seed};
seed_for_prime_gen(_) -> failure.


%% @spec security_strength_required(Nlen::Integer()) -> SecurityStrength::Integer
%-spec(security_strength_required(Nlen::Integer()) -> SecurityStrength::Integer() ). 
%%
%% @doc As per SP 800-57, Part 1 (2 Mar 2007). See Table 2 on page 63.
security_strength_required(1024) -> 80;
security_strength_required(2048) -> 112;
security_strength_required(3072) -> 128.
     


%% @spec prime(N::integer()) -> integer()
%% @equiv prime(N, digits)
prime(N) ->
    prime(N, digits).

prime1(PrimeCandidate) ->
    case is_prime(PrimeCandidate) of
	true  -> PrimeCandidate;
	false -> prime1(PrimeCandidate + 2)
    end.

%%--------------------------------------------------------------------
%% @doc Returns the highest integer less than or equal to the number N.
%% @spec floor(N) -> [integer()]
%% @end
%%--------------------------------------------------------------------
-spec( floor(float()) -> integer() ).	     
floor(N) ->
    case round(N) of
	RN when RN =< N -> RN;
	RN -> RN - 1
    end.
	    
%%--------------------------------------------------------------------
%% @doc Find the smallest coprime number less than N.
%% @spec small_coprime(N) -> integer()
%% @end
%%--------------------------------------------------------------------
small_coprime(N) ->    
    coprime(N, 2).    
			
%%--------------------------------------------------------------------
%% @doc Find a coprime number less than N and greater than E.
%% @spec coprime(N, E) -> integer()
%% @end
%%--------------------------------------------------------------------
coprime(N, E) ->    
    case gcd(N, E) of
	1 -> E;
	_ -> coprime(N, E + 1)
    end.

%%--------------------------------------------------------------------
%% @doc Expoentiation modulus; Msg ^ P mod N.
%% @spec exp_mod(Msg, N, P) -> integer()
%% where
%%  Msg = integer()
%%  N = integer()
%%  P = integer()
%% @end
%%--------------------------------------------------------------------
exp_mod(Msg, N, P) ->
    exp_mod1(Msg, N, P) rem N.

exp_mod1(Msg, _N, 1) ->
    Msg;
exp_mod1(Msg, N, P) ->
    case P rem 2 of
	0 -> exp_mod1((Msg * Msg) rem N, N, P div 2);
	1 -> Msg * exp_mod1(Msg, N, P - 1)
    end.

%%--------------------------------------------------------------------
%% @doc Find the greatest common divisor of two numbers A an B
%% @spec gcd(A, B) -> integer()
%% @end
%%--------------------------------------------------------------------
gcd(A, B) when A < B ->
    gcd(B, A);
gcd(A, 0) -> 
    A;
gcd(A, B) ->
    gcd(B, A rem B).

%%--------------------------------------------------------------------
%% @doc Find numbers X and Y such that AX + BY = gcd(A, B)
%% @spec extended_gcd(A::integer(), B::integer()) -> {X::integer(), Y::integer()}
%% @end
%%--------------------------------------------------------------------
extended_gcd(A, B) ->
    case A rem B of 
       0 ->
	    {0, 1};
       N ->
	    {X, Y} = extended_gcd(B, N),
	    {Y, X-Y*(A div B)}
    end.

%% %%--------------------------------------------------------------------
%% %% @doc Determine if a number is prime
%% %% See http://en.wikipedia.org/wiki/Fermat%27s_little_theorem for explanation of this algorithm
%% %% @spec is_prime(N::integer()) -> bool()
%% %% @end
%% %%--------------------------------------------------------------------
%% is_prime(D) when D > 9, D < 100 ->
%%     lists:member(D, lists:nthtail(4, ?SMALL_PRIMES));
%% is_prime(D) when D < 10 ->
%%     lists:member(D, [2,3,5,7]);
%% is_prime(D) ->
%%     is_prime(D, 50).

%% is_prime(D, I) ->
%%     {A1,A2,A3} = now(),
%%     random:seed(A1, A2, A3),
%%     Digits = length(integer_to_list(D)) -1,
%%     is_prime(D, I, Digits).

%% is_prime(_, 0, _) ->
%%     true;
%% is_prime(N, I, Digits) ->
%%     case random_odd_integer(random:uniform(Digits), digits) of
%% 	CoPrime when CoPrime < N ->
%% 	    case exp_mod(CoPrime,N,N) of
%% 		CoPrime -> is_prime(N, I - 1, Digits);
%% 		_       -> false
%% 	    end;
%% 	_ ->
%% 	    is_prime(N, I, Digits)
%%     end.


%% @doc home-made is_prime based on Eratosthenes' sieve.
-spec is_prime(N::integer()) -> boolean().		      
is_prime(C) when C rem 2 == 0 ->
    false;
is_prime(C) when C rem 3 == 0 ->
    false;
is_prime(C) ->
   %% process_flag(trap_exit,true),
    SqrtC = trunc(math:sqrt(C)),
    Self = self(),
    Loop = spawn (fun () -> loop_is_prime(Self) end),
    Head = spawn (?MODULE,filter,[5,C,Loop]),
    Nums = spawn(?MODULE, numbers, [SqrtC,Head]),
    receive 
	Res ->
	    exit(Nums,kill),
%%	    io:format("back in is_prime/1~n",[]),
	    Res 
    end.

loop_is_prime(ReplyTo) ->
%%    Nums ! start,
    receive
	%% {'EXIT',_Pid,{is_prime,true}} ->
	%%     io:format("IS PRIME!~n",[]),
	%%     true;
	%% {'EXIT',_Pid,{factor,_N}} ->
	%%     false;
	%% {'EXIT',_Pid,normal} ->
	%%     loop_is_prime(spawn(fun () -> ok end));
	is_prime ->
%%	    io:format("loop_is_prime: is_prime!~n",[]),
	    ReplyTo ! true,
	    ok;
%%	    exit(done);
	{factor,N} ->
%%	    io:format("loop_is_prime: factor ~p~n",[N]),
	    ReplyTo ! false,
	    ok;
%%	    exit(done);
	M ->
	    io:format("Not expected: ~p~n",[M])
    end.


%% this is the (current) last filter process in the chain.
filter(P,C,ReplyTo) ->
%%    io:format("filter ~p (~p) starting ~n",[P,C]),
    link(ReplyTo),
    receive
	N when N rem P == 0 ->
%%	    io:format("filter ~p is removing ~p~n",[P,N]),
	    filter(P,C,ReplyTo);
	N when is_integer(N) ->
	    case C rem N of 
		0 ->
%%		    io:format("filter ~p found factor ~p of ~p~n",[P,N,C]),
		    ReplyTo ! {factor,N};
		    %%exit({factor,N});
		_ ->
%%		    io:format("filter ~p spawns the next filter ~p~n",[P,N]),
		    Next = spawn_link (?MODULE,filter,[N,C,ReplyTo]),
		    filter(P,C,ReplyTo,Next)
	    end;
	done -> 
%%	    io:format("filter ~p as last declares prime~n",[P]),
	    ReplyTo ! is_prime
%%	    exit({is_prime,true})
    end.

filter(P,C,ReplyTo,Next) ->
    receive
	N when N rem P == 0 ->
	    filter(P,C,ReplyTo,Next);
	N when is_integer(N) ->
	    Next ! N,
	    filter(P,C,ReplyTo,Next);
	done ->
%%	    io:format("filter ~p done~n",[P]),
	    Next ! done
    end.



%% @doc starting simple to allow process linking
numbers(SqrtC,To) ->
    %% process_flag(trap_exit,true),
    link(To),
    %% receive 
    %% 	start ->
%%	    io:format("numbers starting~n",[]),
	    numbers(1,-1,SqrtC,To).
    %% end.

%% @doc Only send out numbers 6*K+/-1 as that is a good pre-filter for the sieve.
numbers(K,One,Max,To) when 6*K+One > Max ->
%%    io:format("numbers done~n",[]),
    timer:sleep(50),
    To ! done;
numbers(K,-1,Max,To) ->
%%    io:format("from numbers ~p to ~p~n",[6*K-1,To]),
    To ! (6*K-1),
    numbers(K,1,Max,To);
numbers(K,1,Max,To) ->
 %%   io:format("from numbers ~p to ~p~n",[6*K+1,To]),
    To ! (6*K+1),
    numbers(K+1,-1,Max,To).

ceiling(X) ->
    T = trunc(X),
    case X - T == 0 of
        true -> T;
        false -> T + 1
    end.

pow(X,N) when is_integer(N),N>=0 ->
	pow(X,N,1).

pow(_X,0,P) ->
	P;
pow(X,N,A) when N rem 2 =:= 0 ->
	pow(X*X,N div 2,A);
pow(X,N,A) ->
	pow(X,N-1,A*X).


%%%===================================================================
%%% Internal functions
%%%===================================================================
random_odd_integer(Digits, digits) ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    list_to_integer(random_odd_integer_digits(Digits));
random_odd_integer(Bytes, bytes) ->
    Bits = Bytes * 8,
    <<Int:Bits>> = random_odd_binary(Bytes),
    Int.

random_odd_integer_digits(0) ->
    integer_to_list(random:uniform(5) * 2 - 1);
random_odd_integer_digits(Digits) ->
    lists:flatten([integer_to_list(random:uniform(9))|random_odd_integer_digits(Digits - 1)]).

random_odd_binary(Bytes) ->
    {A1,A2,A3} = now(),
    random:seed(A1, A2, A3),
    random_odd_binary(Bytes, <<255>>).

random_odd_binary(1, <<255>>) ->
    <<255>>;
random_odd_binary(2, Acc) ->
    <<Acc/binary, 1>>;
random_odd_binary(Bytes, Acc) ->
    random_odd_binary(Bytes - 1, <<Acc/binary, (random:uniform(255))>>).
    
%%%===================================================================
%%% Test functions
%%%===================================================================
%is_prime_test() ->
%?assertMatch(true, is_prime(671998030559713968361666935769)),
%?assertMatch(false, is_prime(671998030559713968361666935763)).

wheel_is_prime(C) when C rem 2 == 0 -> false;
wheel_is_prime(C) when C rem 3 == 0 -> false;
wheel_is_prime(C) when C rem 5 == 0 -> false;
wheel_is_prime(C) ->
    SqrtC = trunc(math:sqrt(C)),
    A = array:from_list([1,7,11,13,17,19,23,29]),
    wheel_loop(0,30,1,A,array:size(A),SqrtC,C).

%% wheel_loop(K,M,I,A,N,SqrtC,C) when K*M > SqrtC -> true;
%% wheel_loop(K,M,I,A,N,SqrtC,C) ->
%%     case C rem (M*K + array:get(I,A)) of
%% 	0 -> 
%% 	    false;
%% 	_ -> 
%% 	    I1 = I+1,
%% 	    wheel_loop(K+(I1 div N),M,I1 rem N,A,N,SqrtC,C)
    %% end.
	
wheel_loop(K,M,I,A,N,SqrtC,C) when K*M > SqrtC -> true;
wheel_loop(K,M,N,A,N,SqrtC,C) ->
    wheel_loop(K+1,M,0,A,N,SqrtC,C);
wheel_loop(K,M,I,A,N,SqrtC,C) ->
    case C rem (M*K + array:get(I,A)) of
	0 -> 
	    false;
	_ -> 
	    wheel_loop(K,M,I+1,A,N,SqrtC,C)
    end.
 
wl2(B,I,A,SqrtC,C) when B > SqrtC ->
    true;
wl2(B,7,A,SqrtC,C) ->
    case C rem (B+array:get(7,A)) of
	0 ->
	    false;
	_ ->
	    wl2(B+30,0,A,SqrtC,C)
    end;
wl2(B,I,A,SqrtC,C) ->
    case C rem (B+array:get(I,A)) of
	0 ->
	    false;
	_ ->
	    wl2(B,I+1,A,SqrtC,C)
    end.

wt2(C) ->
    Primes =  lists:sublist(?SMALL_PRIMES,3),
    case lists:any(fun(M) -> C rem M == 0 end, Primes) of
	true -> 
	    false;
	false ->
	    SqrtC = trunc(math:sqrt(C)),
	    A = array:from_list([1,7,11,13,17,19,23,29]),
	    {Time,Res} = timer:tc(?MODULE,
				  wl2,
				  [0,1,A,SqrtC,C]),
	    {Time/1000000,Res}
    end.

wl3(B,_,_,_,SqrtC,_) when B>SqrtC -> true;
wl3(B,M,[H],L,SqrtC,C) ->
    case C rem (B+H) of
	0 ->
	    false;
	_ ->
	    wl3(B+M,M,[H|L],[],SqrtC,C)
    end;
wl3(B,M,[H|Hs],L,SqrtC,C) ->
    case C rem (B+H) of
	0 ->
	    false;
	_ ->
	    wl3(B,M,Hs,[H|L],SqrtC,C)
    end.

wt3(C,N) ->
    Primes =  lists:sublist(?SMALL_PRIMES,N),
    case lists:any(fun(M) -> C rem M == 0 end, Primes) of
	true -> 
	    false;
	false ->
	    SqrtC = trunc(math:sqrt(C)),
	    {M,A} = wheel_array(N),
	    L = array:to_list(A),
	    {Time,Res} = timer:tc(?MODULE,
				  wl3,
				  [0,M,tl(L),[hd(L)],SqrtC,C]),
	    {Time/1000000,Res}
    end.   


wheel_test(C,N) ->
    Primes =  lists:sublist(?SMALL_PRIMES,N),
    case lists:any(fun(M) -> C rem M == 0 end, Primes) of
	true -> 
	    false;
	false ->
	    SqrtC = trunc(math:sqrt(C)),
	    {M,A} = wheel_array(N),
	    {Time,Res} = timer:tc(?MODULE,
				  wheel_loop,
				  [0,M,1,A,array:size(A),SqrtC,C]),
	    {Time/1000000,Res}
    end.

product(Xs) ->			   
    lists:foldl(fun(X, Prod) -> X * Prod end, 1, Xs).
 

-spec wheel_array(N::integer()) ->  {integer(),tuple()}.%%#array{}.	
wheel_array(N) ->
    Primes = lists:sublist(?SMALL_PRIMES,N),
    M = product(Primes),
    L = lists:seq(1,M-1),
    Spokes = filter_primes(Primes,L),
    {M,array:from_list(Spokes)}.

filter_primes([],L) -> L;
filter_primes([P|Ps],L) ->
    filter_primes(Ps,
		  [ N || N <- L, N rem P /= 0]).
    

test(1) ->
    {Time,true} = timer:tc(?MODULE,is_prime,[5915587277]),
    Time / 1000000;
test(2) ->
    {Time,true} = timer:tc(?MODULE,wheel_is_prime,[5915587277]),
    Time / 1000000;
test(3) ->
    [1, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 121, 127, 131, 137, 139, 143, 149, 151, 157, 163, 167, 169, 173, 179, 181, 187, 191, 193, 197, 199, 209];
test(4) ->
         [5915587277
      ,1500450271
      , 3267000013
      , 5754853343
      , 4093082899
      , 9576890767
      , 3628273133
      , 2860486313
      , 5463458053
      , 3367900313
      ,1000000007
      ,1000000009
      ,1000000021];
    
test(5) ->
     [5915587277
      ,1500450271
      , 3267000013
      , 5754853343
      , 4093082899
      , 9576890767
      , 3628273133
      , 2860486313
      , 5463458053
      , 3367900313
      ,1000000007
      ,1000000009
      ,1000000021
      ,1000000033
      ,1000000087
      ,1000000093
      ,1000000097
      ,1000000103
      ,1000000123
      ,1000000181
      ,1000000207
      ,1000000223
      ,1000000241
      ,1000000271
      ,1000000289
      ,1000000297
      ,1000000321
      ,1000000349
      ,1000000363
      ,1000000403
      ,1000000409
      ,1000000411
      ,1000000427
      ,1000000433
      ,1000000439
      ,1000000447
      ,1000000453
      ,1000000459
      ,1000000483
,1500000001
,1500000041
,1500000043
,1500000059
,1500000077
,1500000079
,1500000101
,1500000107
,1500000113
,1500000167
,1500000233
,1500000283
,1500000301
,1500000373
,1500000377
,1500000409
,1500000419
,1500000427
,1500000449
,1500000473
     ]; 
test(6) ->
    Ps = test(4),
    Res = [ wt3(P,7) || P <-Ps ],
    sum_res(Res);
test({7,F}) ->
    Ps = test(5),
    M = length(Ps),
    L =[ run_test(F,N,Ps) || N <- lists:seq(3,6) ],
    [ {N, T / M} ||
	{N,T} <- lists:sort(fun({_,T1},{_,T2}) -> T1 < T2 end,L)];
test(list) ->
    test({7,fun wt3/2});	  
test(array) ->
    test({7,fun wheel_test/2}).

sum_res(Res) ->
    {Times,Trues} = lists:unzip(Res),
    {lists:sum(Times),lists:all(fun(X) -> X end,Trues)}.
					
run_wt3(N,Ps) ->
    Res = [ wt3(P,N) || P <-Ps ],
    {Total,true} = sum_res(Res),
    {N,Total}.

run_test(F,N,Ps) ->
    Res = [ F(P,N) || P <-Ps ],
    {Total,true} = sum_res(Res),
    {N,Total}.
