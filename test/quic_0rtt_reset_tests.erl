%%% -*- erlang -*-
%%%
%%% RFC 9001 §4.6.2: when the server rejects 0-RTT, the client MUST
%%% reset stream state for every stream that carried 0-RTT data.

-module(quic_0rtt_reset_tests).

-include_lib("eunit/include/eunit.hrl").
-include("quic.hrl").

reset_zero_rtt_streams_removes_named_streams_test() ->
    Streams = #{0 => stream0, 4 => stream4, 8 => stream8},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        self(), Streams, [0, 4]
    ),
    State1 = quic_connection:test_reset_zero_rtt_streams([0, 4], State0),
    Info = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([8], lists:sort(maps:keys(maps:get(streams, Info)))),
    ?assertEqual([], maps:get(zero_rtt_stream_ids, Info)),
    flush_owner_messages().

reset_zero_rtt_streams_notifies_owner_test() ->
    Self = self(),
    Streams = #{0 => stream0, 4 => stream4},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        Self, Streams, [0, 4]
    ),
    _State1 = quic_connection:test_reset_zero_rtt_streams([0, 4], State0),
    receive
        {quic, Pid, {early_data_rejected, Ids}} when Pid =:= Self ->
            ?assertEqual([0, 4], lists:sort(Ids))
    after 100 ->
        ?assert(false)
    end.

reset_zero_rtt_streams_clears_tracking_set_test() ->
    Streams = #{0 => stream0},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        self(), Streams, [0]
    ),
    Info0 = quic_connection:test_zero_rtt_reset_info(State0),
    ?assertEqual([0], lists:sort(maps:get(zero_rtt_stream_ids, Info0))),
    State1 = quic_connection:test_reset_zero_rtt_streams([0], State0),
    Info1 = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([], maps:get(zero_rtt_stream_ids, Info1)),
    flush_owner_messages().

reset_zero_rtt_streams_empty_list_is_noop_test() ->
    Streams = #{0 => stream0},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        self(), Streams, []
    ),
    State1 = quic_connection:test_reset_zero_rtt_streams([], State0),
    Info1 = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([0], lists:sort(maps:keys(maps:get(streams, Info1)))),
    receive
        {quic, _, {early_data_rejected, _}} -> ?assert(false)
    after 50 -> ok
    end.

handshake_completion_with_rejected_early_data_resets_streams_test() ->
    Self = self(),
    Streams = #{0 => stream0, 4 => stream4},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        Self, Streams, [0, 4]
    ),
    State1 = quic_connection:test_finalize_zero_rtt_handshake(State0, false),
    Info = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([], maps:get(zero_rtt_stream_ids, Info)),
    ?assertEqual([], maps:keys(maps:get(streams, Info))),
    receive
        {quic, Pid, {early_data_rejected, Ids}} when Pid =:= Self ->
            ?assertEqual([0, 4], lists:sort(Ids))
    after 100 ->
        ?assert(false)
    end.

handshake_completion_with_accepted_early_data_keeps_streams_test() ->
    Self = self(),
    Streams = #{0 => stream0, 4 => stream4},
    State0 = quic_connection:test_state_for_zero_rtt_reset(
        Self, Streams, [0, 4]
    ),
    State1 = quic_connection:test_finalize_zero_rtt_handshake(State0, true),
    Info = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([0, 4], lists:sort(maps:keys(maps:get(streams, Info)))),
    ?assertEqual([0, 4], lists:sort(maps:get(zero_rtt_stream_ids, Info))),
    receive
        {quic, _, {early_data_rejected, _}} ->
            ?assert(false)
    after 50 ->
        ok
    end.

handshake_completion_with_no_zero_rtt_streams_emits_no_event_test() ->
    Self = self(),
    State0 = quic_connection:test_state_for_zero_rtt_reset(Self, #{}, []),
    _State1 = quic_connection:test_finalize_zero_rtt_handshake(State0, false),
    receive
        {quic, _, {early_data_rejected, _}} ->
            ?assert(false)
    after 50 ->
        ok
    end.

%% Drive the client-side EncryptedExtensions handler directly with an EE
%% body that omits the early_data extension. RFC 9001 §4.6.2: when the
%% client offered 0-RTT (early_keys =/= undefined) and the server's EE
%% does not advertise acceptance, the client MUST reset stream state for
%% every stream that carried 0-RTT data.
client_ee_without_early_data_resets_zero_rtt_streams_test() ->
    Self = self(),
    Streams = #{0 => stream0, 4 => stream4},
    EEBody = build_ee_body(#{alpn => <<"h3">>, transport_params => #{}}),
    State0 = quic_connection:test_client_state_for_ee(
        Self, Streams, [0, 4], _OfferedZeroRtt = true
    ),
    State1 = quic_connection:test_process_encrypted_extensions(State0, EEBody),
    Info = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([], maps:get(zero_rtt_stream_ids, Info)),
    ?assertEqual([], lists:sort(maps:keys(maps:get(streams, Info)))),
    receive
        {quic, Pid, {early_data_rejected, Ids}} when Pid =:= Self ->
            ?assertEqual([0, 4], lists:sort(Ids))
    after 100 ->
        ?assert(false)
    end.

%% When the EE carries the early_data extension and the client offered
%% 0-RTT, the streams MUST be preserved and no rejection event emitted.
client_ee_with_early_data_keeps_zero_rtt_streams_test() ->
    Self = self(),
    Streams = #{0 => stream0, 4 => stream4},
    EEBody = build_ee_body(#{
        alpn => <<"h3">>, transport_params => #{}, early_data => true
    }),
    State0 = quic_connection:test_client_state_for_ee(
        Self, Streams, [0, 4], _OfferedZeroRtt = true
    ),
    State1 = quic_connection:test_process_encrypted_extensions(State0, EEBody),
    Info = quic_connection:test_zero_rtt_reset_info(State1),
    ?assertEqual([0, 4], lists:sort(maps:get(zero_rtt_stream_ids, Info))),
    ?assertEqual([0, 4], lists:sort(maps:keys(maps:get(streams, Info)))),
    receive
        {quic, _, {early_data_rejected, _}} ->
            ?assert(false)
    after 50 ->
        ok
    end.

%% When the client never offered 0-RTT, the EE-handler MUST leave
%% `early_data_accepted' false and emit no rejection event. The invariant
%% that `zero_rtt_stream_ids' is only populated by `do_send_zero_rtt_data/4'
%% (which requires `early_keys =/= undefined') guarantees the set is
%% empty here.
client_ee_no_offer_emits_no_event_test() ->
    Self = self(),
    Streams = #{},
    EEBody = build_ee_body(#{alpn => <<"h3">>, transport_params => #{}}),
    State0 = quic_connection:test_client_state_for_ee(
        Self, Streams, [], _OfferedZeroRtt = false
    ),
    _State1 = quic_connection:test_process_encrypted_extensions(State0, EEBody),
    receive
        {quic, _, {early_data_rejected, _}} ->
            ?assert(false)
    after 50 ->
        ok
    end.

%% Build the body that the EE-handler expects (extensions vector only,
%% not including the outer handshake-message type/length header).
build_ee_body(Opts) ->
    Full = quic_tls:build_encrypted_extensions(Opts),
    {ok, {?TLS_ENCRYPTED_EXTENSIONS, Body}, _Rest} =
        quic_tls:decode_handshake_message(Full),
    Body.

flush_owner_messages() ->
    receive
        {quic, _, _} -> flush_owner_messages()
    after 0 -> ok
    end.
