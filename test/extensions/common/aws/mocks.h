#pragma once

#include "source/common/http/message_impl.h"
#include "source/extensions/common/aws/credentials_provider.h"
#include "source/extensions/common/aws/signer.h"

#include "test/mocks/upstream/cluster_manager.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

class MockCredentialsProvider : public CredentialsProvider {
public:
  MockCredentialsProvider();
  ~MockCredentialsProvider() override;

  MOCK_METHOD(Credentials, getCredentials, ());
};

class MockSigner : public Signer {
public:
  MockSigner();
  ~MockSigner() override;

  MOCK_METHOD(void, sign, (Http::RequestMessage&, bool, absl::string_view));
  MOCK_METHOD(void, sign, (Http::RequestHeaderMap&, const std::string&, absl::string_view));
  MOCK_METHOD(void, signEmptyPayload, (Http::RequestHeaderMap&, absl::string_view));
  MOCK_METHOD(void, signUnsignedPayload, (Http::RequestHeaderMap&, absl::string_view));
};

class MockFetchMetadata {
public:
  virtual ~MockFetchMetadata() = default;

  MOCK_METHOD(absl::optional<std::string>, fetch, (Http::RequestMessage&), (const));
};

class DummyMetadataFetcher {
public:
  absl::optional<std::string> operator()(Http::RequestMessage&) { return absl::nullopt; }
};

// A mock HTTP upstream with response body.
class MockUpstream {
public:
  MockUpstream(Upstream::MockClusterManager& mock_cm, const std::string& response_body)
      : request_(&mock_cm.thread_local_cluster_.async_client_), response_body_(response_body) {
    ON_CALL(mock_cm.thread_local_cluster_.async_client_, send_(_, _, _))
        .WillByDefault(
            Invoke([this](Http::RequestMessagePtr&, Http::AsyncClient::Callbacks& cb,
                          const Http::AsyncClient::RequestOptions&) -> Http::AsyncClient::Request* {
              Http::ResponseMessagePtr response_message(
                  new Http::ResponseMessageImpl(Http::ResponseHeaderMapPtr{
                      new Http::TestResponseHeaderMapImpl{{":status", "200"}}}));
              response_message->body().add(response_body_);
              cb.onSuccess(request_, std::move(response_message));
              called_count_++;
              return &request_;
            }));
  }

  int called_count() const { return called_count_; }

private:
  Http::MockAsyncClientRequest request_;
  std::string response_body_;
  int called_count_{};
};

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
