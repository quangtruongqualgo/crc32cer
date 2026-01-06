%% @doc CRC32C (Castagnoli) checksum calculation library for Erlang.
%%
%% This module provides high-performance CRC32C checksum calculation functions
%% using native C implementations (NIFs). CRC32C is optimized for modern CPUs
%% and is commonly used in storage systems, networking protocols, and data
%% integrity verification.
%%
%% The module offers two main approaches:
%% <ul>
%% <li><b>Standard approach</b> (`nif`/`nif_d`): Uses VM-optimized iolist processing
%%     for general-purpose checksum calculation. Best for most use cases.</li>
%% <li><b>Iolist optimized</b> (`nif_iolist_d`): Uses stack-based
%%     processing optimized for large binary chunks. Best for processing batch of large
%%     binaries without creating temporary binaries.</li>
%% </ul>
%%
%% == Performance Characteristics ==
%%
%% <ul>
%% <li><b>Standard approach</b>: Best for general iolist processing, small to medium data</li>
%% <li><b>Iolist optimized</b>: Up to 28x faster for batches of large binary chunks (>100KB)</li>
%% <li><b>Pre-converted binary</b>: Fastest overall when data is already a binary</li>
%% </ul>
%%
%% == Examples ==
%%
%% ```
%% %% Basic usage
%% Crc1 = crc32cer:nif(<<"hello world">>),
%% Crc2 = crc32cer:nif(0, <<"hello world">>),
%%
%% %% Iolist processing
%% IoList = [<<"hello">>, " ", <<"world">>],
%% Crc3 = crc32cer:nif(IoList),
%%
%% %% Batch of large binary optimization
%% LargeChunks = [binary:copy(<<"chunk">>, 100000) || _ <- lists:seq(1, 5)],
%% Crc4 = crc32cer:nif_iolist_d(0, LargeChunks),
%% ```
%%
%% @see <a href="https://en.wikipedia.org/wiki/Cyclic_redundancy_check#CRC-32C">CRC-32C on Wikipedia</a>
%% @see <a href="https://tools.ietf.org/html/rfc3720#section-12.1">RFC 3720 - CRC32C</a>
-module(crc32cer).

-on_load(init/0).

-export([crc32/1, crc32/2, nif_d/2, nif/1, nif/2, nif_iolist/1, nif_iolist/2, nif_iolist_d/1, nif_iolist_d/2]).

-define(LIBNAME, "libcrc32cer_nif").

-define(CRC32C_POLY,   16#82F63B78).
-define(CRC32C_INIT,   16#FFFFFFFF).
-define(CRC32C_XOROUT, 16#FFFFFFFF).

init() ->
    case erlang:load_nif(?LIBNAME, 0) of
        ok ->
            ok;
        {error, Reason} ->
            error_logger:warning_msg(
              "crc32cer: failed to load NIF (~p), using pure Erlang fallback~n",
              [Reason]),
            ok
    end.

-spec nif(iodata()) -> non_neg_integer().
nif(Data) ->
    crc32(Data).

-spec nif(non_neg_integer(), iodata()) -> non_neg_integer().
nif(Acc, Data) ->
    crc32(Acc, Data).

-spec nif_d(non_neg_integer(), iodata()) -> non_neg_integer().
nif_d(Acc, Data) ->
    crc32(Acc, Data).

-spec nif_iolist(iodata()) -> non_neg_integer().
nif_iolist(Data) ->
    crc32(Data).

-spec nif_iolist(non_neg_integer(), iodata()) -> non_neg_integer().
nif_iolist(Acc, Data) ->
    crc32(Acc, Data).

-spec nif_iolist_d(iodata()) -> non_neg_integer().
nif_iolist_d(Data) ->
    crc32(Data).

-spec nif_iolist_d(non_neg_integer(), iodata()) -> non_neg_integer().
nif_iolist_d(Acc, Data) ->
    crc32(Acc, Data).

-spec crc32(iodata()) -> non_neg_integer().
crc32(Data) ->
    crc32(?CRC32C_INIT, Data).

-spec crc32(non_neg_integer(), iodata()) -> non_neg_integer().
crc32(Acc, Data) when is_binary(Data) ->
    crc32c_binary(Data, Acc);
crc32(Acc, Data) when is_list(Data) ->
    crc32(Acc, list_to_binary(Data)).

-spec crc32c_binary(binary(), non_neg_integer()) -> non_neg_integer().
crc32c_binary(Bin, Acc0) ->
    Acc1 = crc32c_binary_loop(Bin, Acc0 band 16#FFFFFFFF),
    (Acc1 bxor ?CRC32C_XOROUT) band 16#FFFFFFFF.

crc32c_binary_loop(<<>>, Acc) ->
    Acc;
crc32c_binary_loop(<<Byte, Rest/binary>>, Acc) ->
    Acc1 = (Acc bxor Byte) band 16#FFFFFFFF,
    crc32c_binary_loop(Rest, crc32c_step8(Acc1)).

-spec crc32c_step8(non_neg_integer()) -> non_neg_integer().
crc32c_step8(Crc0) ->
    crc32c_step8(Crc0, 8).

crc32c_step8(Crc, 0) ->
    Crc band 16#FFFFFFFF;
crc32c_step8(Crc, N) ->
    Crc1 =
        case Crc band 1 of
            1 -> ((Crc bsr 1) bxor ?CRC32C_POLY);
            0 -> (Crc bsr 1)
        end,
    crc32c_step8(Crc1 band 16#FFFFFFFF, N - 1).
