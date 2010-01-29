%%%-------------------------------------------------------------------
%%% @author Martin Logan <martinjlogan@Macintosh.local>
%%% @copyright (C) 2008, Erlware
%%% @doc
%%%  A pure Erlang version of the RSA public key cryptography algorithm.
%%% @end
%%% Created : 25 Mar 2008 by Martin Logan <martinjlogan@Macintosh.local>
%%%-------------------------------------------------------------------
-module(cg_rsa).

%% API
-export([
	 keygen/0,
	 keygen/1,
	 keygen/2,
	 encrypt/3,
	 padded_encrypt/3,
	 decrypt/3,
	 padded_decrypt/3
	 ]).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Generate rsa public and private keys. The primes chose to do the generation should be of a length
%%      specified by Digits. 
%% @spec keygen(Digits) -> {ok, {{public_key, {N, E}}, {private_key, {N, D}}, {max_message_size, Bytes}}}
%% @end
%%--------------------------------------------------------------------
keygen(Digits) ->
    P = cg_math:prime(Digits),
    Q = cg_math:prime(Digits),
    case keygen(P, Q) of
	{error, {negative_private_key_exponent, _}} -> keygen(Digits);
	Keys                                        -> Keys
    end.

%% @spec keygen() -> {ok, {{public_key, {N, E}}, {private_key, {N, D}}, {max_message_size, Bytes}}} 
%% @equiv keygen(64)
keygen() ->
    keygen(64).

%%--------------------------------------------------------------------
%% @doc Generate rsa public and private keys. Key gen needs as input two prime numbers P and Q
%% @spec keygen(P, Q) -> {ok, {{public_key, {N, E}}, {private_key, {N, D}}, {max_message_size, Bytes}}} | {error, Reason}
%% @end
%%--------------------------------------------------------------------
keygen(P, Q) ->
    N = P * Q,
    % Compute the Eulers Totient of two primes
    TN = (P - 1) * (Q - 1),
    E = cg_math:small_coprime(TN),
    case cg_math:extended_gcd(E, TN) of
	{D, _} when D < 0 ->
	    %% @todo Find out if this can be prevented. Is there a better way to pick primes. What about Rabin-Miller?
	    {error, {negative_private_key_exponent,
		     "the primes chosen produced a negative value for d - please pick new primes"}};
	{D, _} ->
	    {ok, {{public_key, {N, E}}, {private_key, {N, D}}, {max_message_size, lists:min([P, Q])}}}
    end.
    
%%--------------------------------------------------------------------
%% @doc Encrypt a number. 
%% @spec encrypt(Msg, N, E) -> integer()
%% where
%%  Msg = integer()
%%  N = integer()
%%  E = integer()
%% @end
%%--------------------------------------------------------------------
encrypt(Msg, N, E) ->
    cg_math:exp_mod(Msg, N, E).

%%--------------------------------------------------------------------
%% @doc A convenience function to encrypt a number with padding.
%% @spec padded_encrypt(Msg, N, E) -> integer()
%% where
%%  Msg = integer()
%%  N = integer()
%%  E = integer()
%% @end
%%--------------------------------------------------------------------
padded_encrypt(RawMsg, N, E) ->
    Pad = 9 + random:uniform(90),
    Msg = list_to_integer(lists:flatten([integer_to_list(RawMsg), integer_to_list(Pad)])),
    cg_math:exp_mod(Msg, N, E).
    
%%--------------------------------------------------------------------
%% @doc Decrypt a number. 
%% @spec decrypt(Msg, N, D) -> integer()
%% where
%%  Msg = integer()
%%  N = integer()
%%  D = integer()
%% @end
%%--------------------------------------------------------------------
decrypt(Msg, N, D) ->
    cg_math:exp_mod(Msg, N, D). 

%%--------------------------------------------------------------------
%% @doc A convenience function to decrypt a number that has been padded by the function padded_encrypt. 
%% @spec padded_decrypt(Msg, N, D) -> integer()
%% where
%%  Msg = integer()
%%  N = integer()
%%  D = integer()
%% @end
%%--------------------------------------------------------------------
padded_decrypt(Msg, N, D) ->
    PaddingLength = 2,
    list_to_integer(
      lists:reverse(
	lop_off(
	  lists:reverse(integer_to_list(cg_math:exp_mod(Msg, N, D))),
	  PaddingLength
	 ))).

lop_off(List, 0) ->
    List;
lop_off([_|T], Count) ->
    lop_off(T, Count - 1).

    
%%%===================================================================
%%% Test functions
%%%===================================================================
%decrypt_test() ->
    %Code = cg_rsa:encrypt(4, 6097, 7).
    %?assertMatch(4, cg_rsa:decrypt(Code, 6097, 4243)).

%full_padded_rsa_test() ->
%    {ok, {{_, {N, E}}, {_, {N, D}}, _}} = cg_rsa:keygen(1000),
%    Code = cg_rsa:padded_encrypt(1, N, E),
%    ?assertMatch(1, cg_rsa:padded_decrypt(Code, N, D)).


%full_rsa_test() ->
%    {ok, {{_, {N, E}}, {_, {N, D}}, _}} = cg_rsa:keygen(500),
%    Code = cg_rsa:encrypt(1, N, E),
%    ?assertMatch(1, cg_rsa:decrypt(Code, N, D)).
