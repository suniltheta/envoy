#include <openssl/x509_vfy.h>

#include <cstddef>

#include "envoy/config/bootstrap/v3/bootstrap.pb.h"
#include "envoy/config/overload/v3/overload.pb.h"
#include "envoy/extensions/filters/network/http_connection_manager/v3/http_connection_manager.pb.h"
#include "envoy/extensions/transport_sockets/quic/v3/quic_transport.pb.h"

#include "test/config/utility.h"
#include "test/integration/http_integration.h"
#include "test/test_common/test_runtime.h"
#include "test/test_common/utility.h"

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Winvalid-offsetof"
#endif

#include "quiche/quic/core/http/quic_client_push_promise_index.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/quic_session_peer.h"

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "common/quic/client_connection_factory_impl.h"
#include "common/quic/envoy_quic_client_session.h"
#include "common/quic/envoy_quic_client_connection.h"
#include "common/quic/envoy_quic_proof_verifier.h"
#include "common/quic/envoy_quic_connection_helper.h"
#include "common/quic/envoy_quic_alarm_factory.h"
#include "common/quic/envoy_quic_packet_writer.h"
#include "common/quic/envoy_quic_utils.h"
#include "common/quic/quic_transport_socket_factory.h"
#include "test/common/quic/test_utils.h"
#include "test/config/integration/certs/clientcert_hash.h"
#include "extensions/transport_sockets/tls/context_config_impl.h"

#if defined(ENVOY_CONFIG_COVERAGE)
#define DISABLE_UNDER_COVERAGE return
#else
#define DISABLE_UNDER_COVERAGE                                                                     \
  do {                                                                                             \
  } while (0)
#endif

namespace Envoy {
namespace Quic {

class CodecClientCallbacksForTest : public Http::CodecClientCallbacks {
public:
  void onStreamDestroy() override {}

  void onStreamReset(Http::StreamResetReason reason) override {
    last_stream_reset_reason_ = reason;
  }

  Http::StreamResetReason last_stream_reset_reason_{Http::StreamResetReason::LocalReset};
};

void updateResource(AtomicFileUpdater& updater, double pressure) {
  updater.update(absl::StrCat(pressure));
}

// A test that sets up its own client connection with customized quic version and connection ID.
class QuicHttpIntegrationTest : public HttpIntegrationTest, public QuicMultiVersionTest {
public:
  QuicHttpIntegrationTest()
      : HttpIntegrationTest(Http::CodecType::HTTP3, GetParam().first,
                            ConfigHelper::quicHttpProxyConfig()),
        supported_versions_([]() {
          if (GetParam().second == QuicVersionType::GquicQuicCrypto) {
            return quic::CurrentSupportedVersionsWithQuicCrypto();
          }
          bool use_http3 = GetParam().second == QuicVersionType::Iquic;
          SetQuicReloadableFlag(quic_disable_version_draft_29, !use_http3);
          return quic::CurrentSupportedVersions();
        }()),
        conn_helper_(*dispatcher_), alarm_factory_(*dispatcher_, *conn_helper_.GetClock()),
        injected_resource_filename_1_(TestEnvironment::temporaryPath("injected_resource_1")),
        injected_resource_filename_2_(TestEnvironment::temporaryPath("injected_resource_2")),
        file_updater_1_(injected_resource_filename_1_),
        file_updater_2_(injected_resource_filename_2_) {}

  ~QuicHttpIntegrationTest() override {
    cleanupUpstreamAndDownstream();
    // Release the client before destroying |conn_helper_|. No such need once |conn_helper_| is
    // moved into a client connection factory in the base test class.
    codec_client_.reset();
  }

  Network::ClientConnectionPtr makeClientConnectionWithOptions(
      uint32_t port, const Network::ConnectionSocket::OptionsSharedPtr& options) override {
    // Setting socket options is not supported.
    ASSERT(!options);
    server_addr_ = Network::Utility::resolveUrl(
        fmt::format("udp://{}:{}", Network::Test::getLoopbackAddressUrlString(version_), port));
    Network::Address::InstanceConstSharedPtr local_addr =
        Network::Test::getCanonicalLoopbackAddress(version_);
    // Initiate a QUIC connection with the highest supported version. If not
    // supported by server, this connection will fail.
    // TODO(danzh) Implement retry upon version mismatch and modify test frame work to specify a
    // different version set on server side to test that.
    auto connection = std::make_unique<EnvoyQuicClientConnection>(
        getNextConnectionId(), server_addr_, conn_helper_, alarm_factory_,
        quic::ParsedQuicVersionVector{supported_versions_[0]}, local_addr, *dispatcher_, nullptr);
    quic_connection_ = connection.get();
    ASSERT(quic_connection_persistent_info_ != nullptr);
    auto& persistent_info = static_cast<PersistentQuicInfoImpl&>(*quic_connection_persistent_info_);
    auto session = std::make_unique<EnvoyQuicClientSession>(
        persistent_info.quic_config_, supported_versions_, std::move(connection),
        persistent_info.server_id_, persistent_info.cryptoConfig(), &push_promise_index_,
        *dispatcher_,
        // Use smaller window than the default one to have test coverage of client codec buffer
        // exceeding high watermark.
        /*send_buffer_limit=*/2 * Http2::Utility::OptionsLimits::MIN_INITIAL_STREAM_WINDOW_SIZE);
    return session;
  }

  IntegrationCodecClientPtr makeRawHttpConnection(
      Network::ClientConnectionPtr&& conn,
      absl::optional<envoy::config::core::v3::Http2ProtocolOptions> http2_options) override {
    IntegrationCodecClientPtr codec =
        HttpIntegrationTest::makeRawHttpConnection(std::move(conn), http2_options);
    if (!codec->disconnected()) {
      codec->setCodecClientCallbacks(client_codec_callback_);
      EXPECT_EQ(transport_socket_factory_->clientContextConfig().serverNameIndication(),
                codec->connection()->requestedServerName());
    }
    return codec;
  }

  quic::QuicConnectionId getNextConnectionId() {
    if (designated_connection_ids_.empty()) {
      return quic::QuicUtils::CreateRandomConnectionId();
    }
    quic::QuicConnectionId cid = designated_connection_ids_.front();
    designated_connection_ids_.pop_front();
    return cid;
  }

  void initialize() override {
    config_helper_.addConfigModifier([this](envoy::config::bootstrap::v3::Bootstrap& bootstrap) {
      const std::string overload_config =
          fmt::format(R"EOF(
        refresh_interval:
          seconds: 0
          nanos: 1000000
        resource_monitors:
          - name: "envoy.resource_monitors.injected_resource_1"
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.resource_monitors.injected_resource.v3.InjectedResourceConfig
              filename: "{}"
          - name: "envoy.resource_monitors.injected_resource_2"
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.resource_monitors.injected_resource.v3.InjectedResourceConfig
              filename: "{}"
        actions:
          - name: "envoy.overload_actions.stop_accepting_requests"
            triggers:
              - name: "envoy.resource_monitors.injected_resource_1"
                threshold:
                  value: 0.95
          - name: "envoy.overload_actions.stop_accepting_connections"
            triggers:
              - name: "envoy.resource_monitors.injected_resource_1"
                threshold:
                  value: 0.9
          - name: "envoy.overload_actions.disable_http_keepalive"
            triggers:
              - name: "envoy.resource_monitors.injected_resource_2"
                threshold:
                  value: 0.8
      )EOF",
                      injected_resource_filename_1_, injected_resource_filename_2_);
      *bootstrap.mutable_overload_manager() =
          TestUtility::parseYaml<envoy::config::overload::v3::OverloadManager>(overload_config);
    });
    config_helper_.addConfigModifier(
        [](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
               hcm) {
          hcm.mutable_drain_timeout()->clear_seconds();
          hcm.mutable_drain_timeout()->set_nanos(500 * 1000 * 1000);
          EXPECT_EQ(hcm.codec_type(), envoy::extensions::filters::network::http_connection_manager::
                                          v3::HttpConnectionManager::HTTP3);
        });

    updateResource(file_updater_1_, 0);
    updateResource(file_updater_2_, 0);
    HttpIntegrationTest::initialize();
    // Latch quic_transport_socket_factory_ which is instantiated in initialize().
    transport_socket_factory_ =
        static_cast<QuicClientTransportSocketFactory*>(quic_transport_socket_factory_.get());
    registerTestServerPorts({"http"});

    ASSERT(&transport_socket_factory_->clientContextConfig());
  }

  void testMultipleQuicConnections() {
    concurrency_ = 8;
    set_reuse_port_ = true;
    initialize();
    std::vector<IntegrationCodecClientPtr> codec_clients;
    for (size_t i = 1; i <= concurrency_; ++i) {
      // The BPF filter and ActiveQuicListener::destination() look at the 1st word of connection id
      // in the packet header. And currently all QUIC versions support >= 8 bytes connection id. So
      // create connections with the first 4 bytes of connection id different from each
      // other so they should be evenly distributed.
      designated_connection_ids_.push_back(quic::test::TestConnectionId(i << 32));
      // TODO(sunjayBhatia,wrowe): deserialize this, establishing all connections in parallel
      // (Expected to save ~14s each across 6 tests on Windows)
      codec_clients.push_back(makeHttpConnection(lookupPort("http")));
    }
    constexpr auto timeout_first = std::chrono::seconds(15);
    constexpr auto timeout_subsequent = std::chrono::milliseconds(10);
    if (GetParam().first == Network::Address::IpVersion::v4) {
      test_server_->waitForCounterEq("listener.127.0.0.1_0.downstream_cx_total", 8u, timeout_first);
    } else {
      test_server_->waitForCounterEq("listener.[__1]_0.downstream_cx_total", 8u, timeout_first);
    }
    for (size_t i = 0; i < concurrency_; ++i) {
      if (GetParam().first == Network::Address::IpVersion::v4) {
        test_server_->waitForGaugeEq(
            fmt::format("listener.127.0.0.1_0.worker_{}.downstream_cx_active", i), 1u,
            timeout_subsequent);
        test_server_->waitForCounterEq(
            fmt::format("listener.127.0.0.1_0.worker_{}.downstream_cx_total", i), 1u,
            timeout_subsequent);
      } else {
        test_server_->waitForGaugeEq(
            fmt::format("listener.[__1]_0.worker_{}.downstream_cx_active", i), 1u,
            timeout_subsequent);
        test_server_->waitForCounterEq(
            fmt::format("listener.[__1]_0.worker_{}.downstream_cx_total", i), 1u,
            timeout_subsequent);
      }
    }
    for (size_t i = 0; i < concurrency_; ++i) {
      fake_upstream_connection_ = nullptr;
      upstream_request_ = nullptr;
      auto encoder_decoder =
          codec_clients[i]->startRequest(Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                                                        {":path", "/test/long/url"},
                                                                        {":scheme", "http"},
                                                                        {":authority", "host"}});
      auto& request_encoder = encoder_decoder.first;
      auto response = std::move(encoder_decoder.second);
      codec_clients[i]->sendData(request_encoder, 0, true);
      waitForNextUpstreamRequest();
      upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "200"},
                                                                       {"set-cookie", "foo"},
                                                                       {"set-cookie", "bar"}},
                                       true);

      ASSERT_TRUE(response->waitForEndStream());
      EXPECT_TRUE(response->complete());
      codec_clients[i]->close();
    }
  }

protected:
  quic::QuicClientPushPromiseIndex push_promise_index_;
  quic::ParsedQuicVersionVector supported_versions_;
  EnvoyQuicConnectionHelper conn_helper_;
  EnvoyQuicAlarmFactory alarm_factory_;
  CodecClientCallbacksForTest client_codec_callback_;
  Network::Address::InstanceConstSharedPtr server_addr_;
  EnvoyQuicClientConnection* quic_connection_{nullptr};
  const std::string injected_resource_filename_1_;
  const std::string injected_resource_filename_2_;
  AtomicFileUpdater file_updater_1_;
  AtomicFileUpdater file_updater_2_;
  std::list<quic::QuicConnectionId> designated_connection_ids_;
  Quic::QuicClientTransportSocketFactory* transport_socket_factory_{nullptr};
};

INSTANTIATE_TEST_SUITE_P(QuicHttpIntegrationTests, QuicHttpIntegrationTest,
                         testing::ValuesIn(generateTestParam()), testParamsToString);

TEST_P(QuicHttpIntegrationTest, GetRequestAndEmptyResponse) {
  testRouterHeaderOnlyRequestAndResponse();
}

TEST_P(QuicHttpIntegrationTest, ZeroRtt) {
  // Make sure both connections use the same PersistentQuicInfoImpl.
  concurrency_ = 1;
  initialize();
  // Start the first connection.
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  // Send a complete request on the first connection.
  auto response1 = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  waitForNextUpstreamRequest(0);
  upstream_request_->encodeHeaders(default_response_headers_, true);
  ASSERT_TRUE(response1->waitForEndStream());
  // Close the first connection.
  codec_client_->close();
  // Start a second connection.
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  // Send a complete request on the second connection.
  auto response2 = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  waitForNextUpstreamRequest(0);
  upstream_request_->encodeHeaders(default_response_headers_, true);
  ASSERT_TRUE(response2->waitForEndStream());
  // Ensure 0-RTT was used by second connection.
  EnvoyQuicClientSession* quic_session =
      static_cast<EnvoyQuicClientSession*>(codec_client_->connection());
  EXPECT_TRUE(static_cast<quic::QuicCryptoClientStream*>(
                  quic::test::QuicSessionPeer::GetMutableCryptoStream(quic_session))
                  ->EarlyDataAccepted());
  // Close the second connection.
  codec_client_->close();
}

// Ensure multiple quic connections work, regardless of platform BPF support
TEST_P(QuicHttpIntegrationTest, MultipleQuicConnectionsDefaultMode) {
  testMultipleQuicConnections();
}

TEST_P(QuicHttpIntegrationTest, MultipleQuicConnectionsNoBPF) {
  // Note: This runtime override is a no-op on platforms without BPF
  config_helper_.addRuntimeOverride(
      "envoy.reloadable_features.prefer_quic_kernel_bpf_packet_routing", "false");

  testMultipleQuicConnections();
}

// Tests that the packets from a connection with CID longer than 8 bytes are routed to the same
// worker.
TEST_P(QuicHttpIntegrationTest, MultiWorkerWithLongConnectionId) {
  concurrency_ = 8;
  set_reuse_port_ = true;
  initialize();
  // Setup 9-byte CID for the next connection.
  designated_connection_ids_.push_back(quic::test::TestConnectionIdNineBytesLong(2u));
  testRouterHeaderOnlyRequestAndResponse();
}

TEST_P(QuicHttpIntegrationTest, PortMigration) {
  concurrency_ = 2;
  set_reuse_port_ = true;
  initialize();
  uint32_t old_port = lookupPort("http");
  codec_client_ = makeHttpConnection(old_port);
  auto encoder_decoder =
      codec_client_->startRequest(Http::TestRequestHeaderMapImpl{{":method", "POST"},
                                                                 {":path", "/test/long/url"},
                                                                 {":scheme", "http"},
                                                                 {":authority", "host"}});
  request_encoder_ = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  codec_client_->sendData(*request_encoder_, 1024u, false);

  // Change to a new port by switching socket, and connection should still continue.
  Network::Address::InstanceConstSharedPtr local_addr =
      Network::Test::getCanonicalLoopbackAddress(version_);
  quic_connection_->switchConnectionSocket(
      createConnectionSocket(server_addr_, local_addr, nullptr));
  EXPECT_NE(old_port, local_addr->ip()->port());
  // Send the rest data.
  codec_client_->sendData(*request_encoder_, 1024u, true);
  waitForNextUpstreamRequest(0, TestUtility::DefaultTimeout);
  // Send response headers, and end_stream if there is no response body.
  const Http::TestResponseHeaderMapImpl response_headers{{":status", "200"}};
  size_t response_size{5u};
  upstream_request_->encodeHeaders(response_headers, false);
  upstream_request_->encodeData(response_size, true);
  ASSERT_TRUE(response->waitForEndStream());
  verifyResponse(std::move(response), "200", response_headers, std::string(response_size, 'a'));

  EXPECT_TRUE(upstream_request_->complete());
  EXPECT_EQ(1024u * 2, upstream_request_->bodyLength());
  cleanupUpstreamAndDownstream();
}

TEST_P(QuicHttpIntegrationTest, StopAcceptingConnectionsWhenOverloaded) {
  initialize();

  // Put envoy in overloaded state and check that it doesn't accept the new client connection.
  updateResource(file_updater_1_, 0.9);
  test_server_->waitForGaugeEq("overload.envoy.overload_actions.stop_accepting_connections.active",
                               1);
  codec_client_ = makeRawHttpConnection(makeClientConnection((lookupPort("http"))), absl::nullopt);
  EXPECT_TRUE(codec_client_->disconnected());

  // Reduce load a little to allow the connection to be accepted connection.
  updateResource(file_updater_1_, 0.8);
  test_server_->waitForGaugeEq("overload.envoy.overload_actions.stop_accepting_connections.active",
                               0);
  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));
  auto response = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  waitForNextUpstreamRequest(0);
  // Send response headers, but hold response body for now.
  upstream_request_->encodeHeaders(default_response_headers_, /*end_stream=*/false);

  updateResource(file_updater_1_, 0.95);
  test_server_->waitForGaugeEq("overload.envoy.overload_actions.stop_accepting_requests.active", 1);
  // Existing request should be able to finish.
  upstream_request_->encodeData(10, true);
  ASSERT_TRUE(response->waitForEndStream());
  EXPECT_TRUE(response->complete());
  EXPECT_EQ("200", response->headers().getStatusValue());

  // New request should be rejected.
  auto response2 = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  ASSERT_TRUE(response2->waitForEndStream());
  EXPECT_EQ("503", response2->headers().getStatusValue());
  EXPECT_EQ("envoy overloaded", response2->body());
  codec_client_->close();

  EXPECT_TRUE(makeRawHttpConnection(makeClientConnection((lookupPort("http"))), absl::nullopt)
                  ->disconnected());
}

TEST_P(QuicHttpIntegrationTest, NoNewStreamsWhenOverloaded) {
  initialize();
  updateResource(file_updater_1_, 0.7);

  codec_client_ = makeHttpConnection(makeClientConnection((lookupPort("http"))));

  // Send a complete request and start a second.
  auto response = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  waitForNextUpstreamRequest(0);
  upstream_request_->encodeHeaders(default_response_headers_, true);
  ASSERT_TRUE(response->waitForEndStream());

  auto response2 = codec_client_->makeHeaderOnlyRequest(default_request_headers_);
  waitForNextUpstreamRequest(0);

  // Enable the disable-keepalive overload action. This should send a shutdown notice before
  // encoding the headers.
  updateResource(file_updater_2_, 0.9);
  test_server_->waitForGaugeEq("overload.envoy.overload_actions.disable_http_keepalive.active", 1);

  upstream_request_->encodeHeaders(default_response_headers_, /*end_stream=*/false);
  upstream_request_->encodeData(10, true);

  response2->waitForHeaders();
  EXPECT_TRUE(codec_client_->waitForDisconnect());

  EXPECT_TRUE(codec_client_->sawGoAway());
  codec_client_->close();
}

TEST_P(QuicHttpIntegrationTest, AdminDrainDrainsListeners) {
  testAdminDrain(Http::CodecType::HTTP1);
}

TEST_P(QuicHttpIntegrationTest, CertVerificationFailure) {
  san_to_match_ = "www.random_domain.com";
  initialize();
  codec_client_ = makeRawHttpConnection(makeClientConnection((lookupPort("http"))), absl::nullopt);
  EXPECT_FALSE(codec_client_->connected());
  std::string failure_reason =
      GetParam().second == QuicVersionType::GquicQuicCrypto
          ? "QUIC_PROOF_INVALID with details: Proof invalid: X509_verify_cert: certificate "
            "verification error at depth 0: ok"
          : "QUIC_TLS_CERTIFICATE_UNKNOWN with details: TLS handshake failure "
            "(ENCRYPTION_HANDSHAKE) 46: "
            "certificate unknown";
  EXPECT_EQ(failure_reason, codec_client_->connection()->transportFailureReason());
}

// HTTP3 doesn't support 101 SwitchProtocol response code, the client should
// reset the request.
TEST_P(QuicHttpIntegrationTest, Reset101SwitchProtocolResponse) {
  config_helper_.addConfigModifier(
      [&](envoy::extensions::filters::network::http_connection_manager::v3::HttpConnectionManager&
              hcm) -> void { hcm.set_proxy_100_continue(true); });
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder =
      codec_client_->startRequest(Http::TestRequestHeaderMapImpl{{":method", "GET"},
                                                                 {":path", "/dynamo/url"},
                                                                 {":scheme", "http"},
                                                                 {":authority", "host"},
                                                                 {"expect", "100-continue"}});
  request_encoder_ = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  // Wait for the request headers to be received upstream.
  ASSERT_TRUE(fake_upstreams_[0]->waitForHttpConnection(*dispatcher_, fake_upstream_connection_));
  ASSERT_TRUE(fake_upstream_connection_->waitForNewStream(*dispatcher_, upstream_request_));

  upstream_request_->encodeHeaders(Http::TestResponseHeaderMapImpl{{":status", "101"}}, false);
  ASSERT_TRUE(response->waitForReset());
  codec_client_->close();
  EXPECT_FALSE(response->complete());
}

TEST_P(QuicHttpIntegrationTest, ResetRequestWithoutAuthorityHeader) {
  initialize();

  codec_client_ = makeHttpConnection(lookupPort("http"));
  auto encoder_decoder = codec_client_->startRequest(Http::TestRequestHeaderMapImpl{
      {":method", "GET"}, {":path", "/dynamo/url"}, {":scheme", "http"}});
  request_encoder_ = &encoder_decoder.first;
  auto response = std::move(encoder_decoder.second);

  ASSERT_TRUE(response->waitForEndStream());
  codec_client_->close();
  ASSERT_TRUE(response->complete());
  EXPECT_EQ("400", response->headers().getStatusValue());
}

} // namespace Quic
} // namespace Envoy
