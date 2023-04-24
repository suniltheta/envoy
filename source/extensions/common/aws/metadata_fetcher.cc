#include "source/extensions/common/aws/metadata_fetcher.h"

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/config/core/v3/http_uri.pb.h"

#include "source/common/common/enum_to_int.h"
#include "source/common/http/headers.h"
#include "source/common/http/utility.h"
#include "source/common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

namespace {

class MetadataFetcherImpl : public MetadataFetcher,
                            public Logger::Loggable<Logger::Id::aws>,
                            public Http::AsyncClient::Callbacks {

public:
  MetadataFetcherImpl(Upstream::ClusterManager& cm, absl::string_view cluster_name)
      : cm_(cm), cluster_name_(std::string(cluster_name)) {
    ENVOY_LOG(trace, "{}", __func__);
  }

  ~MetadataFetcherImpl() override { cancel(); }

  void cancel() override {
    if (request_ && !complete_) {
      request_->cancel();
      ENVOY_LOG(debug, "fetch AWS Metadata [cluster = {}]: cancelled", cluster_name_);
    }
    reset();
  }

  void fetch(Http::RequestMessage& message, Tracing::Span& parent_span,
             MetadataFetcher::MetadataReceiver& receiver) override {
    ENVOY_LOG(trace, "{}", __func__);

    complete_ = false;
    if (!receiver_) {
      receiver_ = &receiver;
    }
    // cm_.checkActiveStaticCluster(cluster_name_);
    ENVOY_LOG(error, "const auto thread_local_cluster = cm_.getThreadLocalCluster(cluster_name_);");
    const auto thread_local_cluster = cm_.getThreadLocalCluster(cluster_name_);
    ENVOY_LOG(error, "if (thread_local_cluster == nullptr) ");
    if (thread_local_cluster == nullptr) {
      ENVOY_LOG(error, "{} AWS Metadata failed: [cluster = {}] not found", __func__, cluster_name_);
      complete_ = true;
      receiver_->onMetadataError(MetadataFetcher::MetadataReceiver::Failure::MissingConfig);
      reset();
      return;
    }

    constexpr uint64_t MAX_RETRIES = 4;
    constexpr uint64_t RETRY_DELAY = 1000;
    constexpr uint64_t TIMEOUT = 5 * 1000;

    const auto host_attributes = Http::Utility::parseAuthority(message.headers().getHostValue());
    const auto host = host_attributes.host_;
    const auto path = message.headers().getPathValue();
    const auto scheme = message.headers().getSchemeValue();
    const auto method = message.headers().getMethodValue();
    ENVOY_LOG(debug, "fetch AWS Metadata at [uri = {}]: start from cluster {}",
              fmt::format("{}://{}{}", scheme, host, path), cluster_name_);

    // if (!provider_.clusterName()) {
    //   ENVOY_LOG(error, "{}: fetch AWS Metadata failed: cluster name is not configured",
    //             __func__);
    //   complete_ = true;
    //   receiver_->onMetadataError(
    //       MetadataFetcher::MetadataReceiver::Failure::MissingConfig);
    //   reset();
    //   return;
    // }
    // if (!Utility::addInternalClusterStatic(cm_, cluster_name_, "STATIC",
    //                                        message.headers().getHostValue())) {
    //   ENVOY_LOG(error, "{}: fetch AWS Metadata failed: Failed to add [cluster = {}]", __func__,
    //             cluster_name_);
    //   complete_ = true;
    //   receiver_->onMetadataError(MetadataFetcher::MetadataReceiver::Failure::MissingConfig);
    //   reset();
    //   return;
    // }

    Http::RequestHeaderMapPtr headersPtr =
        Envoy::Http::createHeaderMap<Envoy::Http::RequestHeaderMapImpl>(
            {{Envoy::Http::Headers::get().Method, std::string(method)},
             {Envoy::Http::Headers::get().Host, std::string(host)},
             {Envoy::Http::Headers::get().Scheme, std::string(scheme)},
             {Envoy::Http::Headers::get().Path, std::string(path)}});

    // Copy the remaining headers.
    message.headers().iterate([&headersPtr](const Http::HeaderEntry& entry) -> Http::HeaderMap::Iterate {
      // Skip pseudo-headers
      if (!entry.key().getStringView().empty() && entry.key().getStringView()[0] == ':') {
        return Http::HeaderMap::Iterate::Continue;
      }
      headersPtr->addCopy(Http::LowerCaseString(entry.key().getStringView()), entry.value().getStringView());
      return Http::HeaderMap::Iterate::Continue;
    });

    auto messagePtr = std::make_unique<Envoy::Http::RequestMessageImpl>(std::move(headersPtr));

    auto options = Http::AsyncClient::RequestOptions()
                       .setTimeout(std::chrono::milliseconds(TIMEOUT))
                       .setParentSpan(parent_span)
                       .setSendXff(false)
                       .setChildSpanName("AWS Metadata Fetch");

    // TODO (suniltheta): Get this retry policy from provider config
    envoy::config::route::v3::RetryPolicy route_retry_policy;
    route_retry_policy.mutable_num_retries()->set_value(MAX_RETRIES);
    route_retry_policy.mutable_per_try_timeout()->CopyFrom(
        Protobuf::util::TimeUtil::MillisecondsToDuration(TIMEOUT));
    route_retry_policy.mutable_per_try_idle_timeout()->CopyFrom(
        Protobuf::util::TimeUtil::MillisecondsToDuration(RETRY_DELAY));
    route_retry_policy.set_retry_on("5xx,gateway-error,connect-failure,reset,refused-stream");

    options.setRetryPolicy(route_retry_policy);
    options.setBufferBodyForRetry(true);
    request_ = thread_local_cluster->httpAsyncClient().send(std::move(messagePtr), *this, options);
  }

  // HTTP async receive methods
  void onSuccess(const Http::AsyncClient::Request&, Http::ResponseMessagePtr&& response) override {
    ENVOY_LOG(trace, "{}", __func__);
    complete_ = true;
    const uint64_t status_code = Http::Utility::getResponseStatus(response->headers());
    // const std::string& uri = provider_.http_uri().uri();
    if (status_code == enumToInt(Http::Code::OK)) {
      ENVOY_LOG(debug, "{}: fetch AWS Metadata [cluster = {}]: success", __func__, cluster_name_);
      if (response->body().length() != 0) {
        const auto body = response->bodyAsString();
        ENVOY_LOG(debug, "{}: fetch AWS Metadata [cluster = {}]: succeeded", __func__,
                  cluster_name_);
        receiver_->onMetadataSuccess(std::move(body));
      } else {
        ENVOY_LOG(debug, "{}: fetch AWS Metadata [cluster = {}]: body is empty", __func__,
                  cluster_name_);
        receiver_->onMetadataError(MetadataFetcher::MetadataReceiver::Failure::Network);
      }
    } else {
      if (response->body().length() != 0) {
        ENVOY_LOG(debug, "{}: fetch AWS Metadata [cluster = {}]: response status code {}, body: {}",
                  __func__, cluster_name_, status_code, response->bodyAsString());
      } else {
        ENVOY_LOG(debug,
                  "{}: fetch AWS Metadata [cluster = {}]: response status code {}, body is empty",
                  __func__, cluster_name_, status_code);
      }
      receiver_->onMetadataError(MetadataFetcher::MetadataReceiver::Failure::Network);
    }
    reset();
  }

  void onFailure(const Http::AsyncClient::Request&,
                 Http::AsyncClient::FailureReason reason) override {
    ENVOY_LOG(debug, "{}: fetch AWS Metadata [cluster = {}]: network error {}", __func__,
              cluster_name_, enumToInt(reason));
    complete_ = true;
    receiver_->onMetadataError(MetadataFetcher::MetadataReceiver::Failure::Network);
    reset();
  }

  void onBeforeFinalizeUpstreamSpan(Tracing::Span&, const Http::ResponseHeaderMap*) override {}

private:
  Upstream::ClusterManager& cm_;
  bool complete_{};
  MetadataFetcher::MetadataReceiver* receiver_{};
  // MetadataCredentialsProviderBase& provider_;
  std::string cluster_name_;
  Http::AsyncClient::Request* request_{};

  void reset() { request_ = nullptr; }
};
} // namespace

MetadataFetcherPtr MetadataFetcher::create(Upstream::ClusterManager& cm,
                                           absl::string_view cluster_name) {
  return std::make_unique<MetadataFetcherImpl>(cm, cluster_name);
}
} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy