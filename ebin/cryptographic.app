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
    cg_math
   ]},

  % All of the registered names the application uses.
  {registered, []},

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

