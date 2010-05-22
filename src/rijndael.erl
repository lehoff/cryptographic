-module(rijndael).

-compile(export_all).

encode(OrgData, OrgKey) ->
    %% @TODO
    %% We could encapsulate this function call with a time regulator to ensure
    %% that the time required is constant. This would prevent timing attacks.

    %% Need to transpose the Data and the Key, as most inputs are in
    %% vector form

    Data = transpose(OrgData),
    Key = transpose(OrgKey),

    Round = 1,
    NewData = xor_lists(Key, Data),
    {FinalKey, DataAfter9Rounds} = 
        do_rounds(Round, NewData, make_key_schedule({encode, Key})),

    Converted = convert_bytes(DataAfter9Rounds),

%    io:format("After SubBytes: ", []),
%    print_dec_list(Converted),
%    io:format("~n", []),
    
    Shifted = shift_rows(Converted),
%    io:format("After ShiftRows: ", []),
%    print_dec_list(Shifted),
%    io:format("~n", []),
    
    Result = xor_lists(FinalKey, Shifted),
    io:format("Final Result: ", []),
    print_dec_list(transpose(Result)), 
    io:format("~n~n", []),
    transpose(Result).

decode(EncodedData, OrgKey) ->
    %% @TODO
    %% We could encapsulate this function call with a time regulator to ensure
    %% that the time required is constant. This would prevent timing attacks.

    Data = transpose(EncodedData),
    Key = transpose(OrgKey),
    DataBefore = 
        do_inv(Data, make_key_schedule({decode, Key})),
    transpose(xor_lists(Key, DataBefore)).

make_key_schedule({encode, OrgKey}) ->
    {Keys, _} = lists:mapfoldl(fun(Num, RunningKey) ->
                                       NewKey = key_schedule(RunningKey, Num),
                                       {NewKey, NewKey}
                               end, OrgKey, lists:seq(1, 10)),
    Keys;
make_key_schedule({decode, OrgKey}) ->
    lists:reverse(make_key_schedule({encode, OrgKey})).



do_rounds(10, Data, [LastKey]) ->
    {LastKey, Data};
do_rounds(RoundNum, Data, [CurrentKey|KeysRest]) ->
    Converted = convert_bytes(Data),
    Shifted = shift_rows(Converted),
    Mixed = mix_columns(Shifted),
    do_rounds(RoundNum+1, xor_lists(CurrentKey, Mixed), KeysRest).
un_round(10, Data, []) ->
    Data;
un_round(Num, Data, [CurrentKey|KeysRest]) ->

    UnKeyd = xor_lists(CurrentKey, Data),

    
    UnMixed = inv_mix_columns(UnKeyd),


    UnShifted = inv_shift_rows(UnMixed),

    
    UnConverted = inv_convert_bytes(UnShifted),

    
    un_round(Num+1, UnConverted, KeysRest).

do_inv(Data, [FinalKey|Keys]) ->
    UnKeyd = xor_lists(FinalKey, Data),


    UnShifted = inv_shift_rows(UnKeyd),


    UnConverted = inv_convert_bytes(UnShifted),


    un_round(1, UnConverted, Keys).
    
key_schedule(OldKeyMatrix, RotationNum) ->
    [K3, K7, K11, K15] = row_pull(OldKeyMatrix, 3),
    Adder = xor_lists(convert_bytes([K7, K11, K15, K3]),
                      [lists:nth(RotationNum, rcon()), 0, 0, 0]),
    FinalRow1 = xor_lists(row_pull(OldKeyMatrix, 0), Adder),
    FinalRow2 = xor_lists(row_pull(OldKeyMatrix, 1), FinalRow1),
    FinalRow3 = xor_lists(row_pull(OldKeyMatrix, 2), FinalRow2),
    FinalRow4 = xor_lists(row_pull(OldKeyMatrix, 3), FinalRow3),
    build_final_key(FinalRow1, FinalRow2, FinalRow3, FinalRow4,
                    []).

build_final_key([], [], [], [], Acc) ->
    Acc;
build_final_key([H1|T1], [H2|T2], [H3|T3], [H4|T4], Acc) ->
    build_final_key(T1, T2, T3, T4,
                    lists:flatten([Acc, H1, H2, H3, H4])).

%%% Rotation map for 10 rotations starting at rcon(4).
rcon() ->
    [16#01,16#02,16#04,16#08,16#10,16#20,16#40,16#80,16#1b,16#36].

inv_rcon() ->
    [16#36,16#1b,16#80,16#40,16#20,16#10,16#08,16#04,16#02,16#01].

row_pull(Matrix, Row) when length(Matrix) == 16 ->
    [lists:nth(Row + 1, Matrix),
     lists:nth(Row + 5, Matrix),
     lists:nth(Row + 9, Matrix),
     lists:nth(Row + 13, Matrix)].

xor_lists(List1, List2) ->
    lists:zipwith(fun(X, Y) ->
                          byte(X bxor Y)
                  end, List1, List2).

%% ADD ROUND KEY
add_lists(List1, List2) ->
    lists:zipwith(fun(X, Y) ->
                          byte(X bxor Y)
                  end, List1, List2).

%%% STEP 3 ->
mix_columns(ARow) when length(ARow) == 4 ->
    BValRows = lists:foldl(fun galois_field_fun/2, [], ARow),
    gen_r(BValRows, ARow);
mix_columns(Matrix) ->
    [NB0, NB4, NB8, NB12] = mix_columns(row_pull(Matrix, 0)),
    [NB1, NB5, NB9, NB13] = mix_columns(row_pull(Matrix, 1)),
    [NB2, NB6, NB10, NB14] = mix_columns(row_pull(Matrix, 2)),
    [NB3, NB7, NB11, NB15] = mix_columns(row_pull(Matrix, 3)),
    [NB0, NB1, NB2, NB3, NB4, NB5, NB6, NB7, NB8, NB9, NB10, NB11, NB12, NB13,
     NB14, NB15].

inv_mix_columns([A0, A1, A2, A3]) ->
    R0 = gmul(A0, 14) bxor gmul(A3, 9) bxor gmul(A2, 13) bxor gmul(A1, 11),
    R1 = gmul(A1, 14) bxor gmul(A0, 9) bxor gmul(A3, 13) bxor gmul(A2, 11),
    R2 = gmul(A2, 14) bxor gmul(A1, 9) bxor gmul(A0, 13) bxor gmul(A3, 11),
    R3 = gmul(A3, 14) bxor gmul(A2, 9) bxor gmul(A1, 13) bxor gmul(A0, 11),
    [R0, R1, R2, R3];
inv_mix_columns(Matrix) ->
    [NB0, NB4, NB8, NB12] = inv_mix_columns(row_pull(Matrix, 0)),
    [NB1, NB5, NB9, NB13] = inv_mix_columns(row_pull(Matrix, 1)),
    [NB2, NB6, NB10, NB14] = inv_mix_columns(row_pull(Matrix, 2)),
    [NB3, NB7, NB11, NB15] = inv_mix_columns(row_pull(Matrix, 3)),
    [NB0, NB1, NB2, NB3, NB4, NB5, NB6, NB7, NB8, NB9, NB10, NB11, NB12, NB13,
     NB14, NB15].

galois_field_fun(RVal, Results) ->
    BVal = 
        case RVal band 16#80 of
            16#80 ->
                (RVal bsl 1) bxor 16#1B;
            _Any ->
                RVal bsl 1
        end,
    lists:flatten([Results, BVal]).

gen_r([B0, B1, B2, B3], [A0, A1, A2, A3]) ->
    R0 = B0 bxor A3 bxor A2 bxor B1 bxor A1,
    R1 = B1 bxor A0 bxor A3 bxor B2 bxor A2,
    R2 = B2 bxor A1 bxor A0 bxor B3 bxor A3,
    R3 = B3 bxor A2 bxor A1 bxor B0 bxor A0,
    adjust_range([R0, R1, R2, R3], []).
    
adjust_range([], Acc) ->
    Acc;
adjust_range([H|T], Acc) ->
    adjust_range(T, lists:flatten([Acc, byte(H)])).

%%% STEP 1 ->
convert_bytes(List) when is_list(List) ->
    lists:foldl(fun sub_byte/2, [], List).
inv_convert_bytes(List) when is_list(List) ->

    lists:foldl(fun inv_sub_byte/2, [], List).

sub_byte(Byte, Acc) when is_integer(Byte) ->
    lists:flatten([Acc, lists:nth(Byte+1, s_box())]).
inv_sub_byte(Byte, Acc) when is_integer(Byte) ->
    lists:flatten([Acc, lists:nth(Byte+1, inv_s_box())]).

%%% STEP 2 ->
shift_rows([B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, 
            B15]) ->
    [B0, B1, B2, B3, B5,  B6,  B7, B4, B10, B11, B8, B9, B15, B12, B13, B14 ].

inv_shift_rows([B0, B1, B2, B3, B5,  B6,  B7, B4, B10, B11, B8, B9, B15, 
                B12, B13, B14 ]) ->
    [B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15].

print_dec_list(DecList) ->
    lists:foreach(fun convert_dec_to_hex/1, DecList).

convert_dec_to_hex(Dec) when Dec < 16#10 ->
    io:fwrite("0~.16B ", [Dec]);
convert_dec_to_hex(Dec) ->
    io:fwrite("~.16B ", [Dec]).

transpose([A1, A2, A3, A4,
           A5, A6, A7, A8,
           A9, A10, A11, A12,
           A13, A14, A15, A16]) ->
    [A1, A5, A9, A13,
     A2, A6, A10, A14,
     A3, A7, A11, A15,
     A4, A8, A12, A16].

gmul(Byte1, Byte2) ->
    gmul(0, 0, Byte1, Byte2).
gmul(8, Product, _Byte1, _Byte2) ->
    Product;
gmul(Count, Product, Byte1, Byte2) ->
    NewProduct =
        case Byte2 band 1 of
            1 ->
                Product bxor Byte1;
            _ ->
                Product
        end,

    FinalByte1 = 
        case Byte1 band 16#80 of
            16#80 ->
                byte(Byte1 bsl 1) bxor 16#1b;
            _ ->
                byte(Byte1 bsl 1)
        end,
    gmul(Count+1, NewProduct, FinalByte1, Byte2 bsr 1).

byte(Val) when Val > 255 ->
    byte(Val - 16#100);
byte(Val) ->
    Val.

s_box() ->
    [16#63,16#7c,16#77,16#7b,16#f2,16#6b,16#6f,16#c5,16#30,16#01,16#67,16#2b,16#fe,16#d7,16#ab,16#76,16#ca,16#82,16#c9,16#7d,16#fa,16#59,16#47,16#f0,16#ad,16#d4,16#a2,16#af,16#9c,16#a4,16#72,16#c0,16#b7,16#fd,16#93,16#26,16#36,16#3f,16#f7,16#cc,16#34,16#a5,16#e5,16#f1,16#71,16#d8,16#31,16#15,16#04,16#c7,16#23,16#c3,16#18,16#96,16#05,16#9a,16#07,16#12,16#80,16#e2,16#eb,16#27,16#b2,16#75,16#09,16#83,16#2c,16#1a,16#1b,16#6e,16#5a,16#a0,16#52,16#3b,16#d6,16#b3,16#29,16#e3,16#2f,16#84,16#53,16#d1,16#00,16#ed,16#20,16#fc,16#b1,16#5b,16#6a,16#cb,16#be,16#39,16#4a,16#4c,16#58,16#cf,16#d0,16#ef,16#aa,16#fb,16#43,16#4d,16#33,16#85,16#45,16#f9,16#02,16#7f,16#50,16#3c,16#9f,16#a8,16#51,16#a3,16#40,16#8f,16#92,16#9d,16#38,16#f5,16#bc,16#b6,16#da,16#21,16#10,16#ff,16#f3,16#d2,16#cd,16#0c,16#13,16#ec,16#5f,16#97,16#44,16#17,16#c4,16#a7,16#7e,16#3d,16#64,16#5d,16#19,16#73,16#60,16#81,16#4f,16#dc,16#22,16#2a,16#90,16#88,16#46,16#ee,16#b8,16#14,16#de,16#5e,16#0b,16#db,16#e0,16#32,16#3a,16#0a,16#49,16#06,16#24,16#5c,16#c2,16#d3,16#ac,16#62,16#91,16#95,16#e4,16#79,16#e7,16#c8,16#37,16#6d,16#8d,16#d5,16#4e,16#a9,16#6c,16#56,16#f4,16#ea,16#65,16#7a,16#ae,16#08,16#ba,16#78,16#25,16#2e,16#1c,16#a6,16#b4,16#c6,16#e8,16#dd,16#74,16#1f,16#4b,16#bd,16#8b,16#8a,16#70,16#3e,16#b5,16#66,16#48,16#03,16#f6,16#0e,16#61,16#35,16#57,16#b9,16#86,16#c1,16#1d,16#9e,16#e1,16#f8,16#98,16#11,16#69,16#d9,16#8e,16#94,16#9b,16#1e,16#87,16#e9,16#ce,16#55,16#28,16#df,16#8c,16#a1,16#89,16#0d,16#bf,16#e6,16#42,16#68,16#41,16#99,16#2d,16#0f,16#b0,16#54,16#bb,16#16].

inv_s_box() ->
    [16#52,16#09,16#6a,16#d5,16#30,16#36,16#a5,16#38,16#bf,16#40,16#a3,16#9e,16#81,16#f3,16#d7,16#fb,16#7c,16#e3,16#39,16#82,16#9b,16#2f,16#ff,16#87,16#34,16#8e,16#43,16#44,16#c4,16#de,16#e9,16#cb,16#54,16#7b,16#94,16#32,16#a6,16#c2,16#23,16#3d,16#ee,16#4c,16#95,16#0b,16#42,16#fa,16#c3,16#4e,16#08,16#2e,16#a1,16#66,16#28,16#d9,16#24,16#b2,16#76,16#5b,16#a2,16#49,16#6d,16#8b,16#d1,16#25,16#72,16#f8,16#f6,16#64,16#86,16#68,16#98,16#16,16#d4,16#a4,16#5c,16#cc,16#5d,16#65,16#b6,16#92,16#6c,16#70,16#48,16#50,16#fd,16#ed,16#b9,16#da,16#5e,16#15,16#46,16#57,16#a7,16#8d,16#9d,16#84,16#90,16#d8,16#ab,16#00,16#8c,16#bc,16#d3,16#0a,16#f7,16#e4,16#58,16#05,16#b8,16#b3,16#45,16#06,16#d0,16#2c,16#1e,16#8f,16#ca,16#3f,16#0f,16#02,16#c1,16#af,16#bd,16#03,16#01,16#13,16#8a,16#6b,16#3a,16#91,16#11,16#41,16#4f,16#67,16#dc,16#ea,16#97,16#f2,16#cf,16#ce,16#f0,16#b4,16#e6,16#73,16#96,16#ac,16#74,16#22,16#e7,16#ad,16#35,16#85,16#e2,16#f9,16#37,16#e8,16#1c,16#75,16#df,16#6e,16#47,16#f1,16#1a,16#71,16#1d,16#29,16#c5,16#89,16#6f,16#b7,16#62,16#0e,16#aa,16#18,16#be,16#1b,16#fc,16#56,16#3e,16#4b,16#c6,16#d2,16#79,16#20,16#9a,16#db,16#c0,16#fe,16#78,16#cd,16#5a,16#f4,16#1f,16#dd,16#a8,16#33,16#88,16#07,16#c7,16#31,16#b1,16#12,16#10,16#59,16#27,16#80,16#ec,16#5f,16#60,16#51,16#7f,16#a9,16#19,16#b5,16#4a,16#0d,16#2d,16#e5,16#7a,16#9f,16#93,16#c9,16#9c,16#ef,16#a0,16#e0,16#3b,16#4d,16#ae,16#2a,16#f5,16#b0,16#c8,16#eb,16#bb,16#3c,16#83,16#53,16#99,16#61,16#17,16#2b,16#04,16#7e,16#ba,16#77,16#d6,16#26,16#e1,16#69,16#14,16#63,16#55,16#21,16#0c,16#7d].
