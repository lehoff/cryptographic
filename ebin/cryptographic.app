%%% -*- mode:erlang -*-
{application, cryptographic,
 [
  % A quick description of the application.
  {description, "Provides cryptographic functionality written in pure Erlang i.e no dependency on non-erlang code."},

  % The version of the applicaton
  {vsn, "0.2.2"},

  % All modules used by the application.
  {modules,
   [
    cg_rsa,
    cg_math,
    entropy,
    hash_random,
    rijndael,
    sha2
   ]},

  % All of the registered names the application uses.
  {registered, [hash_random]},

  {applications,
   [
    kernel, 
    stdlib,
    sasl
   ]},

  {included_applications, []},

  % configuration parameters
  {env, []}

 ]
}.

