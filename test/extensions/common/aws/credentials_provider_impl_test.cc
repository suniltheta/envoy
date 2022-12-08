#include <cstddef>
#include <string>

#include "source/extensions/common/aws/credentials_provider_impl.h"
#include "source/extensions/common/aws/metadata_fetcher.h"

#include "test/extensions/common/aws/mocks.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/event/mocks.h"
#include "test/mocks/server/factory_context.h"
#include "test/test_common/environment.h"
#include "test/test_common/simulated_time_system.h"
#include "test/test_common/test_runtime.h"

using Envoy::Extensions::Common::Aws::MetadataFetcher;
using Envoy::Extensions::Common::Aws::MetadataFetcherPtr;
using Envoy::Extensions::Common::Aws::MockMetadataFetcher;
using testing::_;
using testing::InSequence;
using testing::NiceMock;
using testing::Ref;
using testing::Return;
using testing::Throw;

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

MATCHER_P(WithName, expectedName, "") { return arg.name() == expectedName; }

MATCHER_P(WithAttribute, expectedCluster, "") {
  const auto argSocketAddress =
      arg.load_assignment().endpoints()[0].lb_endpoints()[0].endpoint().address().socket_address();
  const auto expectedSocketAddress = expectedCluster.load_assignment()
                                         .endpoints()[0]
                                         .lb_endpoints()[0]
                                         .endpoint()
                                         .address()
                                         .socket_address();
  return arg.name() == expectedCluster.name() &&
         argSocketAddress.address() == expectedSocketAddress.address() &&
         argSocketAddress.port_value() == expectedSocketAddress.port_value();
}

class EvironmentCredentialsProviderTest : public testing::Test {
public:
  ~EvironmentCredentialsProviderTest() override {
    TestEnvironment::unsetEnvVar("AWS_ACCESS_KEY_ID");
    TestEnvironment::unsetEnvVar("AWS_SECRET_ACCESS_KEY");
    TestEnvironment::unsetEnvVar("AWS_SESSION_TOKEN");
  }

  EnvironmentCredentialsProvider provider_;
};

TEST_F(EvironmentCredentialsProviderTest, AllEnvironmentVars) {
  TestEnvironment::setEnvVar("AWS_ACCESS_KEY_ID", "akid", 1);
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  TestEnvironment::setEnvVar("AWS_SESSION_TOKEN", "token", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
}

TEST_F(EvironmentCredentialsProviderTest, NoEnvironmentVars) {
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(EvironmentCredentialsProviderTest, MissingAccessKeyId) {
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(EvironmentCredentialsProviderTest, NoSessionToken) {
  TestEnvironment::setEnvVar("AWS_ACCESS_KEY_ID", "akid", 1);
  TestEnvironment::setEnvVar("AWS_SECRET_ACCESS_KEY", "secret", 1);
  const auto credentials = provider_.getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

class MessageMatcher : public testing::MatcherInterface<Http::RequestMessage&> {
public:
  explicit MessageMatcher(const Http::TestRequestHeaderMapImpl& expected_headers)
      : expected_headers_(expected_headers) {}

  bool MatchAndExplain(Http::RequestMessage& message,
                       testing::MatchResultListener* result_listener) const override {
    const bool equal = TestUtility::headerMapEqualIgnoreOrder(message.headers(), expected_headers_);
    if (!equal) {
      *result_listener << "\n"
                       << TestUtility::addLeftAndRightPadding("Expected header map:") << "\n"
                       << expected_headers_
                       << TestUtility::addLeftAndRightPadding("is not equal to actual header map:")
                       << "\n"
                       << message.headers()
                       << TestUtility::addLeftAndRightPadding("") // line full of padding
                       << "\n";
    }
    return equal;
  }

  void DescribeTo(::std::ostream* os) const override { *os << "Message matches"; }

  void DescribeNegationTo(::std::ostream* os) const override { *os << "Message does not match"; }

private:
  const Http::TestRequestHeaderMapImpl expected_headers_;
};

testing::Matcher<Http::RequestMessage&>
messageMatches(const Http::TestRequestHeaderMapImpl& expected_headers) {
  return testing::MakeMatcher(new MessageMatcher(expected_headers));
}

class InstanceProfileCredentialsProviderTest : public testing::Test {
public:
  InstanceProfileCredentialsProviderTest()
      : api_(Api::createApiForTest(time_system_)), raw_metadata_fetcher_(new MockMetadataFetcher) {}

  void setupProvider() {
    provider_ = std::make_shared<InstanceProfileCredentialsProvider>(
        *api_, context_, cluster_manager_,
        [this](Http::RequestMessage& message) -> absl::optional<std::string> {
          return this->fetch_metadata_.fetch(message);
        },
        [this](Upstream::ClusterManager&, absl::string_view) {
          metadata_fetcher_.reset(raw_metadata_fetcher_);
          return std::move(metadata_fetcher_);
        },
        "credentials_provider_cluster");
  }

  void setupProviderWithNullContext() {
    provider_ = std::make_shared<InstanceProfileCredentialsProvider>(
        *api_, absl::nullopt, cluster_manager_,
        [this](Http::RequestMessage& message) -> absl::optional<std::string> {
          return this->fetch_metadata_.fetch(message);
        },
        [this](Upstream::ClusterManager&, absl::string_view) {
          metadata_fetcher_.reset(raw_metadata_fetcher_);
          return std::move(metadata_fetcher_);
        },
        "credentials_provider_cluster");
  }

  void setupProviderWithContext() {
    EXPECT_CALL(context_.init_manager_, add(_)).WillOnce(Invoke([this](const Init::Target& target) {
      init_target_handle_ = target.createHandle("test");
    }));

    setupProvider();
    expected_duration_ = provider_->getCacheDuration();
    init_target_handle_->initialize(init_watcher_);
  }

  void setupProviderWithLibcurl() {
    scoped_runtime.mergeValues(
        {{"envoy.reloadable_features.use_libcurl_to_fetch_aws_credentials", "true"}});
    setupProvider();
  }

  void expectCredentialListingCurl(const absl::optional<std::string>& listing) {
    Http::TestRequestHeaderMapImpl headers{{":path", "/latest/meta-data/iam/security-credentials"},
                                           {":authority", "169.254.169.254:80"},
                                           {":scheme", "http"},
                                           {":method", "GET"}};
    EXPECT_CALL(fetch_metadata_, fetch(messageMatches(headers))).WillOnce(Return(listing));
  }

  void expectCredentialListingHttpAsync(const std::string&& instance_role) {
    Http::TestRequestHeaderMapImpl headers{{":path", "/latest/meta-data/iam/security-credentials"},
                                           {":authority", "169.254.169.254:80"},
                                           {":scheme", "http"},
                                           {":method", "GET"}};
    EXPECT_CALL(*raw_metadata_fetcher_, fetch(messageMatches(headers), _, _))
        .WillRepeatedly(Invoke([this, instance_role = std::move(instance_role)](
                                   Http::RequestMessage&, Tracing::Span&,
                                   MetadataFetcher::MetadataReceiver& receiver) {
          receiver.onMetadataSuccess(std::move(instance_role));
        }));
  }

  void expectDocumentCurl(const absl::optional<std::string>& document) {
    Http::TestRequestHeaderMapImpl headers{
        {":path", "/latest/meta-data/iam/security-credentials/doc1"},
        {":authority", "169.254.169.254:80"},
        {":scheme", "http"},
        {":method", "GET"}};
    EXPECT_CALL(fetch_metadata_, fetch(messageMatches(headers))).WillOnce(Return(document));
  }

  void expectDocumentHttpAsync(const std::string&& credential_document_value) {
    Http::TestRequestHeaderMapImpl headers{
        {":path", "/latest/meta-data/iam/security-credentials/doc1"},
        {":authority", "169.254.169.254:80"},
        {":scheme", "http"},
        {":method", "GET"}};
    EXPECT_CALL(*raw_metadata_fetcher_, fetch(messageMatches(headers), _, _))
        .WillRepeatedly(
            Invoke([this, credential_document_value = std::move(credential_document_value)](
                       Http::RequestMessage&, Tracing::Span&,
                       MetadataFetcher::MetadataReceiver& receiver) {
              receiver.onMetadataSuccess(std::move(credential_document_value));
            }));
  }

  TestScopedRuntime scoped_runtime;
  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockFetchMetadata> fetch_metadata_;
  MockMetadataFetcher* raw_metadata_fetcher_;
  MetadataFetcherPtr metadata_fetcher_;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  InstanceProfileCredentialsProviderPtr provider_;
  Init::TargetHandlePtr init_target_handle_;
  NiceMock<Init::ExpectableWatcherImpl> init_watcher_;
  Event::MockTimer* timer_{};
  std::chrono::milliseconds expected_duration_;
};

// Begin unit test for new option via Http Async
TEST_F(InstanceProfileCredentialsProviderTest, TestAddMissingCluster) {
  // Setup without thread local cluster yet
  envoy::config::cluster::v3::Cluster expected_cluster;
  constexpr static const char* kStaticCluster = R"EOF(
name: credentials_provider_cluster
type: static
connectTimeout: 2s
lb_policy: ROUND_ROBIN
loadAssignment:
  clusterName: credentials_provider_cluster
  endpoints:
  - lbEndpoints:
    - endpoint:
        address:
          socketAddress:
            address: "169.254.169.254"
            portValue: 80
typed_extension_protocol_options:
  envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
    "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
    explicit_http_config:
      http_protocol_options:
        accept_http_10: true
  )EOF";
  MessageUtil::loadFromYaml(kStaticCluster, expected_cluster,
                            ProtobufMessage::getNullValidationVisitor());

  EXPECT_CALL(cluster_manager_, getThreadLocalCluster(_)).WillOnce(Return(nullptr));
  EXPECT_CALL(cluster_manager_, addOrUpdateCluster(WithAttribute(expected_cluster), _))
      .WillOnce(Return(true));

  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF"));

  setupProviderWithContext();
}

TEST_F(InstanceProfileCredentialsProviderTest, TestClusterMissingExpectEnvoyException) {
  // Setup without thread local cluster
  Http::RequestMessageImpl message;

  EXPECT_CALL(cluster_manager_, getThreadLocalCluster(_)).WillOnce(Return(nullptr));
  EXPECT_CALL(cluster_manager_, addOrUpdateCluster(WithName("credentials_provider_cluster"), _))
      .WillOnce(Throw(EnvoyException("exeption message")));
  EXPECT_THROW_WITH_MESSAGE(
      setupProvider(), EnvoyException,
      fmt::format("Failed to add [STATIC cluster = credentials_provider_cluster with "
                  "address = {}] or cluster not found",
                  EC2_METADATA_HOST));
}

TEST_F(InstanceProfileCredentialsProviderTest, FailedCredentialListing) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string()));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();
  // Cancel is called once for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyCredentialListing) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("")));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();
  // Cancel is called once for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MissingDocument) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("doc1\ndoc2\ndoc3")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(std::string()));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();
  // Cancel is called twice for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(2);
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MalformedDocument) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 not json
 )EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();
  // Cancel is called twice for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(2);
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyValues) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "",
   "SecretAccessKey": "",
   "Token": ""
 }
 )EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();
  // Cancel is not called again as we don't expect any more call to fetch until timeout.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, FullCachedCredentials) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // Cancel is not called again as we don't expect any more call to fetch until timeout.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // We don't expect any more call to fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(InstanceProfileCredentialsProviderTest, FullCachedCredentialsWithNullContext) {
  // refresh() will be called on initialization.
  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF"));

  setupProviderWithNullContext();

  // Cancel won't be called again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  // We don't expect any more call to fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(InstanceProfileCredentialsProviderTest, RefreshOnCredentialExpiration) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  // Cancel will be called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // Cancel is not called again as we don't expect any more call to fetch until timeout.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  expectCredentialListingHttpAsync(std::move(std::string("doc1")));
  expectDocumentHttpAsync(std::move(R"EOF(
 {
   "AccessKeyId": "new_akid",
   "SecretAccessKey": "new_secret",
   "Token": "new_token1"
 }
 )EOF"));

  // Expect timer to have expired but we would re-start the timer eventually after refresh.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  // Cancel will be called twice back to back.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(2);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  time_system_.advanceTimeWait(std::chrono::minutes(61));
  timer_->invokeCallback();

  // We don't expect timer to be reset again for new fetch.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // Similary we won't call fetch or cancel on metadata fetcher.
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);

  const auto new_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", new_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", new_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token1", new_credentials.sessionToken().value());
}
// End unit test for new option via Http Async

// Begin unit test for deprecated option Libcurl
TEST_F(InstanceProfileCredentialsProviderTest, FailedCredentialListingCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl(absl::optional<std::string>());
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyCredentialListingCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl("");
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MissingDocumentCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl("doc1\ndoc2\ndoc3");
  expectDocumentCurl(absl::optional<std::string>());
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, MalformedDocumentCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl("doc1");
  expectDocumentCurl(R"EOF(
 not json
 )EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, EmptyValuesCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl("doc1");
  expectDocumentCurl(R"EOF(
 {
   "AccessKeyId": "",
   "SecretAccessKey": "",
   "Token": ""
 }
 )EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(InstanceProfileCredentialsProviderTest, FullCachedCredentialsCurl) {
  setupProviderWithLibcurl();
  expectCredentialListingCurl("doc1");
  expectDocumentCurl(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(InstanceProfileCredentialsProviderTest, CredentialExpirationCurl) {
  setupProviderWithLibcurl();
  InSequence sequence;
  expectCredentialListingCurl("doc1");
  expectDocumentCurl(R"EOF(
 {
   "AccessKeyId": "akid",
   "SecretAccessKey": "secret",
   "Token": "token"
 }
 )EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  time_system_.advanceTimeWait(std::chrono::hours(2));
  expectCredentialListingCurl("doc1");
  expectDocumentCurl(R"EOF(
 {
   "AccessKeyId": "new_akid",
   "SecretAccessKey": "new_secret",
   "Token": "new_token"
 }
 )EOF");
  const auto new_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", new_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", new_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", new_credentials.sessionToken().value());
}
// End unit test for deprecated option Libcurl

class TaskRoleCredentialsProviderTest : public testing::Test {
public:
  TaskRoleCredentialsProviderTest()
      : api_(Api::createApiForTest(time_system_)), raw_metadata_fetcher_(new MockMetadataFetcher) {
    // Tue Jan  2 03:04:05 UTC 2018
    time_system_.setSystemTime(std::chrono::milliseconds(1514862245000));
  }

  void setupProvider() {
    provider_ = std::make_shared<TaskRoleCredentialsProvider>(
        *api_, context_, cluster_manager_,
        [this](Http::RequestMessage& message) -> absl::optional<std::string> {
          return this->fetch_metadata_.fetch(message);
        },
        [this](Upstream::ClusterManager&, absl::string_view) {
          metadata_fetcher_.reset(raw_metadata_fetcher_);
          return std::move(metadata_fetcher_);
        },
        "169.254.170.2:80/path/to/doc", "auth_token", "credentials_provider_cluster");
  }

  void setupProviderWithNullContext() {
    provider_ = std::make_shared<TaskRoleCredentialsProvider>(
        *api_, absl::nullopt, cluster_manager_,
        [this](Http::RequestMessage& message) -> absl::optional<std::string> {
          return this->fetch_metadata_.fetch(message);
        },
        [this](Upstream::ClusterManager&, absl::string_view) {
          metadata_fetcher_.reset(raw_metadata_fetcher_);
          return std::move(metadata_fetcher_);
        },
        "169.254.170.2:80/path/to/doc", "auth_token", "credentials_provider_cluster");
  }

  void setupProviderWithContext() {
    EXPECT_CALL(context_.init_manager_, add(_)).WillOnce(Invoke([this](const Init::Target& target) {
      init_target_handle_ = target.createHandle("test");
    }));
    setupProvider();
    expected_duration_ = provider_->getCacheDuration();
    init_target_handle_->initialize(init_watcher_);
  }

  void setupProviderWithLibcurl() {
    scoped_runtime.mergeValues(
        {{"envoy.reloadable_features.use_libcurl_to_fetch_aws_credentials", "true"}});
    setupProvider();
  }

  void expectDocumentCurl(const absl::optional<std::string>& document) {
    Http::TestRequestHeaderMapImpl headers{{":path", "/path/to/doc"},
                                           {":authority", "169.254.170.2:80"},
                                           {":scheme", "http"},
                                           {":method", "GET"},
                                           {"authorization", "auth_token"}};
    EXPECT_CALL(fetch_metadata_, fetch(messageMatches(headers))).WillOnce(Return(document));
  }

  void expectDocumentHttpAsync(const std::string&& document) {
    Http::TestRequestHeaderMapImpl headers{{":path", "/path/to/doc"},
                                           {":authority", "169.254.170.2:80"},
                                           {":scheme", "http"},
                                           {":method", "GET"},
                                           {"authorization", "auth_token"}};
    EXPECT_CALL(*raw_metadata_fetcher_, fetch(messageMatches(headers), _, _))
        .WillRepeatedly(Invoke(
            [this, document = std::move(document)](Http::RequestMessage&, Tracing::Span&,
                                                   MetadataFetcher::MetadataReceiver& receiver) {
              receiver.onMetadataSuccess(std::move(document));
            }));
  }

  TestScopedRuntime scoped_runtime;
  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<MockFetchMetadata> fetch_metadata_;
  MockMetadataFetcher* raw_metadata_fetcher_;
  MetadataFetcherPtr metadata_fetcher_;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  TaskRoleCredentialsProviderPtr provider_;
  Init::TargetHandlePtr init_target_handle_;
  NiceMock<Init::ExpectableWatcherImpl> init_watcher_;
  Event::MockTimer* timer_{};
  std::chrono::milliseconds expected_duration_;
};

// Begin unit test for new option via Http Async
TEST_F(TaskRoleCredentialsProviderTest, TestAddMissingCluster) {
  // Setup without thread local cluster yet
  envoy::config::cluster::v3::Cluster expected_cluster;
  constexpr static const char* kStaticCluster = R"EOF(
name: credentials_provider_cluster
type: static
connectTimeout: 2s
lb_policy: ROUND_ROBIN
loadAssignment:
  clusterName: credentials_provider_cluster
  endpoints:
  - lbEndpoints:
    - endpoint:
        address:
          socketAddress:
            address: "169.254.170.2"
            portValue: 80
typed_extension_protocol_options:
  envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
    "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
    explicit_http_config:
      http_protocol_options:
        accept_http_10: true
  )EOF";
  MessageUtil::loadFromYaml(kStaticCluster, expected_cluster,
                            ProtobufMessage::getNullValidationVisitor());

  EXPECT_CALL(cluster_manager_, getThreadLocalCluster(_)).WillOnce(Return(nullptr));
  EXPECT_CALL(cluster_manager_, addOrUpdateCluster(WithAttribute(expected_cluster), _))
      .WillOnce(Return(true));

  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030500Z"
}
)EOF"));

  setupProviderWithContext();
}

TEST_F(TaskRoleCredentialsProviderTest, TestClusterMissingExpectEnvoyException) {
  // Setup without thread local cluster
  Http::RequestMessageImpl message;

  EXPECT_CALL(cluster_manager_, getThreadLocalCluster(_)).WillOnce(Return(nullptr));
  EXPECT_CALL(cluster_manager_, addOrUpdateCluster(WithName("credentials_provider_cluster"), _))
      .WillOnce(Throw(EnvoyException("exeption message")));
  EXPECT_THROW_WITH_MESSAGE(
      setupProvider(), EnvoyException,
      fmt::format("Failed to add [STATIC cluster = credentials_provider_cluster with "
                  "address = {}] or cluster not found",
                  CONTAINER_METADATA_HOST));
}

TEST_F(TaskRoleCredentialsProviderTest, FailedFetchingDocument) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectDocumentHttpAsync(std::move(std::string()));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // Cancel is called for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));

  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, MalformedDocumenet) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);

  expectDocumentHttpAsync(std::move(R"EOF(
not json
)EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // Cancel is called for fetching once again as previous attempt wasn't a success.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));

  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, EmptyValues) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);

  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "",
  "SecretAccessKey": "",
  "Token": "",
  "Expiration": ""
}
)EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // Cancel is called for fetching once again as previous attempt wasn't a success with updating
  // expiration time.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));

  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, FullCachedCredentials) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030500Z"
}
)EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // We don't expect any more call to cancel or fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // We don't expect any more call to cancel or fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, FullCachedCredentialsWithNullContext) {
  // refresh() will be called on initialization.
  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030500Z"
}
)EOF"));

  setupProviderWithNullContext();

  // Cancel won't be called again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  // We don't expect any more call to fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, RefreshOnNormalCredentialExpiration) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);

  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20190102T030405Z"
}
)EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // No need to restart timer since credentials are fetched from cache.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // We don't expect any more call to cancel or fetch again.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF"));
  // Expect timer to have expired but we would re-start the timer eventually after refresh.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  // Cancel will be called once more.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  time_system_.advanceTimeWait(std::chrono::minutes(61));
  timer_->invokeCallback();

  // We don't expect timer to be reset again for new fetch.
  EXPECT_CALL(*timer_, disableTimer()).Times(0);
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr)).Times(0);
  // Similary we won't call fetch or cancel on metadata fetcher.
  EXPECT_CALL(*raw_metadata_fetcher_, fetch(_, _, _)).Times(0);
  EXPECT_CALL(*raw_metadata_fetcher_, cancel()).Times(0);

  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, TimestampCredentialExpiration) {
  // Setup timer.
  timer_ = new NiceMock<Event::MockTimer>(&context_.dispatcher_);
  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030405Z"
}
)EOF"));
  // init_watcher ready is called.
  init_watcher_.expectReady();
  // Expect refresh timer to be started.
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  setupProviderWithContext();

  // init_watcher ready is not called again.
  init_watcher_.expectReady().Times(0);
  // Need to disable and restart timer since credentials are expired and fetched again
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  // We call cancel once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());

  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());

  // Cancel is called once.
  EXPECT_CALL(*raw_metadata_fetcher_, cancel());
  expectDocumentHttpAsync(std::move(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF"));
  // Expect refresh timer to be stopped and started.
  EXPECT_CALL(*timer_, disableTimer());
  EXPECT_CALL(*timer_, enableTimer(expected_duration_, nullptr));
  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}
// End unit test for new option via Http Async

// Begin unit test for deprecated option Libcurl
TEST_F(TaskRoleCredentialsProviderTest, FailedFetchingDocumentCurl) {
  setupProviderWithLibcurl();
  expectDocumentCurl(absl::optional<std::string>());
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, MalformedDocumenetCurl) {
  setupProviderWithLibcurl();
  expectDocumentCurl(R"EOF(
not json
)EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, EmptyValuesCurl) {
  setupProviderWithLibcurl();
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "",
  "SecretAccessKey": "",
  "Token": "",
  "Expiration": ""
}
)EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_FALSE(credentials.accessKeyId().has_value());
  EXPECT_FALSE(credentials.secretAccessKey().has_value());
  EXPECT_FALSE(credentials.sessionToken().has_value());
}

TEST_F(TaskRoleCredentialsProviderTest, FullCachedCredentialsCurl) {
  setupProviderWithLibcurl();
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030500Z"
}
)EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, NormalCredentialExpirationCurl) {
  setupProviderWithLibcurl();
  InSequence sequence;
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  time_system_.advanceTimeWait(std::chrono::hours(2));
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}

TEST_F(TaskRoleCredentialsProviderTest, TimestampCredentialExpirationCurl) {
  setupProviderWithLibcurl();
  InSequence sequence;
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "akid",
  "SecretAccessKey": "secret",
  "Token": "token",
  "Expiration": "20180102T030405Z"
}
)EOF");
  const auto credentials = provider_->getCredentials();
  EXPECT_EQ("akid", credentials.accessKeyId().value());
  EXPECT_EQ("secret", credentials.secretAccessKey().value());
  EXPECT_EQ("token", credentials.sessionToken().value());
  expectDocumentCurl(R"EOF(
{
  "AccessKeyId": "new_akid",
  "SecretAccessKey": "new_secret",
  "Token": "new_token",
  "Expiration": "20190102T030405Z"
}
)EOF");
  const auto cached_credentials = provider_->getCredentials();
  EXPECT_EQ("new_akid", cached_credentials.accessKeyId().value());
  EXPECT_EQ("new_secret", cached_credentials.secretAccessKey().value());
  EXPECT_EQ("new_token", cached_credentials.sessionToken().value());
}
// End unit test for deprecated option Libcurl

class DefaultCredentialsProviderChainTest : public testing::Test {
public:
  DefaultCredentialsProviderChainTest() : api_(Api::createApiForTest(time_system_)) {
    cluster_manager_.initializeThreadLocalClusters({"credentials_provider_cluster"});
    EXPECT_CALL(factories_, createEnvironmentCredentialsProvider());
  }

  ~DefaultCredentialsProviderChainTest() override {
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI");
    TestEnvironment::unsetEnvVar("AWS_CONTAINER_AUTHORIZATION_TOKEN");
    TestEnvironment::unsetEnvVar("AWS_EC2_METADATA_DISABLED");
  }

  class MockCredentialsProviderChainFactories : public CredentialsProviderChainFactories {
  public:
    MOCK_METHOD(CredentialsProviderSharedPtr, createEnvironmentCredentialsProvider, (), (const));
    MOCK_METHOD(CredentialsProviderSharedPtr, createTaskRoleCredentialsProvider,
                (Api::Api&, FactoryContextOptRef, Upstream::ClusterManager&,
                 const MetadataCredentialsProviderBase::FetchMetadataUsingCurl&,
                 CreateMetadataFetcherCb, absl::string_view, absl::string_view, absl::string_view),
                (const));
    MOCK_METHOD(CredentialsProviderSharedPtr, createInstanceProfileCredentialsProvider,
                (Api::Api&, FactoryContextOptRef, Upstream::ClusterManager&,
                 const MetadataCredentialsProviderBase::FetchMetadataUsingCurl&,
                 CreateMetadataFetcherCb, absl::string_view),
                (const));
  };

  Event::SimulatedTimeSystem time_system_;
  Api::ApiPtr api_;
  NiceMock<Upstream::MockClusterManager> cluster_manager_;
  NiceMock<Server::Configuration::MockFactoryContext> context_;
  NiceMock<MockCredentialsProviderChainFactories> factories_;
};

TEST_F(DefaultCredentialsProviderChainTest, NoEnvironmentVars) {
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _,
                                                                   Ref(cluster_manager_), _, _, _));
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, MetadataDisabled) {
  TestEnvironment::setEnvVar("AWS_EC2_METADATA_DISABLED", "true", 1);
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _,
                                                                   Ref(cluster_manager_), _, _, _))
      .Times(0);
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, MetadataNotDisabled) {
  TestEnvironment::setEnvVar("AWS_EC2_METADATA_DISABLED", "false", 1);
  EXPECT_CALL(factories_, createInstanceProfileCredentialsProvider(Ref(*api_), _,
                                                                   Ref(cluster_manager_), _, _, _));
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, RelativeUri) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/path/to/creds", 1);
  EXPECT_CALL(factories_,
              createTaskRoleCredentialsProvider(Ref(*api_), _, Ref(cluster_manager_), _, _, _,
                                                "169.254.170.2:80/path/to/creds", ""));
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, FullUriNoAuthorizationToken) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://host/path/to/creds", 1);
  EXPECT_CALL(factories_, createTaskRoleCredentialsProvider(Ref(*api_), _, Ref(cluster_manager_), _,
                                                            _, _, "http://host/path/to/creds", ""));
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST_F(DefaultCredentialsProviderChainTest, FullUriWithAuthorizationToken) {
  TestEnvironment::setEnvVar("AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://host/path/to/creds", 1);
  TestEnvironment::setEnvVar("AWS_CONTAINER_AUTHORIZATION_TOKEN", "auth_token", 1);
  EXPECT_CALL(factories_,
              createTaskRoleCredentialsProvider(Ref(*api_), _, Ref(cluster_manager_), _, _, _,
                                                "http://host/path/to/creds", "auth_token"));
  DefaultCredentialsProviderChain chain(*api_, context_, cluster_manager_, DummyFetchMetadata(),
                                        factories_);
}

TEST(CredentialsProviderChainTest, getCredentials_noCredentials) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  EXPECT_CALL(*mock_provider1, getCredentials());
  EXPECT_CALL(*mock_provider2, getCredentials());

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials creds = chain.getCredentials();
  EXPECT_EQ(Credentials(), creds);
}

TEST(CredentialsProviderChainTest, getCredentials_firstProviderReturns) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  const Credentials creds("access_key", "secret_key");

  EXPECT_CALL(*mock_provider1, getCredentials()).WillOnce(Return(creds));
  EXPECT_CALL(*mock_provider2, getCredentials()).Times(0);

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials ret_creds = chain.getCredentials();
  EXPECT_EQ(creds, ret_creds);
}

TEST(CredentialsProviderChainTest, getCredentials_secondProviderReturns) {
  auto mock_provider1 = std::make_shared<MockCredentialsProvider>();
  auto mock_provider2 = std::make_shared<MockCredentialsProvider>();

  const Credentials creds("access_key", "secret_key");

  EXPECT_CALL(*mock_provider1, getCredentials());
  EXPECT_CALL(*mock_provider2, getCredentials()).WillOnce(Return(creds));

  CredentialsProviderChain chain;
  chain.add(mock_provider1);
  chain.add(mock_provider2);

  const Credentials ret_creds = chain.getCredentials();
  EXPECT_EQ(creds, ret_creds);
}

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
