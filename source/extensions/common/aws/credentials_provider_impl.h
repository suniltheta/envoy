#pragma once

#include <list>
#include <string>

#include "envoy/api/api.h"
#include "envoy/event/timer.h"
#include "envoy/http/message.h"
#include "envoy/thread_local/thread_local.h"

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/protobuf/message_validator_impl.h"
#include "source/common/protobuf/utility.h"
#include "source/common/runtime/runtime_features.h"
#include "source/extensions/common/aws/credentials_provider.h"
#include "source/extensions/common/aws/metadata_fetcher.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

/**
 *  CreateMetadataFetcherCb is a callback interface for creating a MetadataFetcher instance.
 */
using CreateMetadataFetcherCb =
    std::function<MetadataFetcherPtr(Upstream::ClusterManager&, absl::string_view)>;
using CredentialsConstSharedPtr = std::shared_ptr<const Credentials>;

/**
 * Retrieve AWS credentials from the environment variables.
 *
 * Adheres to conventions specified in:
 * https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
 */
class EnvironmentCredentialsProvider : public CredentialsProvider,
                                       public Logger::Loggable<Logger::Id::aws> {
public:
  Credentials getCredentials() override;
};

class MetadataCredentialsProviderBase : public CredentialsProvider,
                                        public Logger::Loggable<Logger::Id::aws> {
public:
  using FetchMetadataUsingCurl = std::function<absl::optional<std::string>(Http::RequestMessage&)>;
  using OnAsyncFetchCb = std::function<void(const std::string&&)>;

  MetadataCredentialsProviderBase(Api::Api& api,
                                  const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                                  CreateMetadataFetcherCb create_metadata_fetcher_cb,
                                  absl::string_view cluster_name)
      : api_(api), fetch_metadata_using_curl_(fetch_metadata_using_curl),
        create_metadata_fetcher_cb_(create_metadata_fetcher_cb),
        cluster_name_(std::string(cluster_name)), cache_duration_(getCacheDuration()),
        tls_(context_.threadLocal()) {
    tls_.set([](Envoy::Event::Dispatcher& dispatcher) {
      return std::make_shared<ThreadLocalCredentialsCache>();
    });
    cache_duration_timer_ = context_.mainThreadDispatcher().createTimer([this]() -> void {
      const Thread::LockGuard lock(lock_);
      refresh();
    });
  }

  Credentials getCredentials() override {
    refreshIfNeeded();
    return tls_->credentials_.get();
  }
  const std::string& clusterName() { return cluster_name_; }

protected:
  struct ThreadLocalCredentialsCache : public ThreadLocal::ThreadLocalObject {
    // TODO(suniltheta): Move credential expiration date in here
    ThreadLocalCredentialsCache() {
      // Creating empty credentials as default.
      credentials_ = std::make_shared<Credentials>();
    }
    // The credentials object
    CredentialsConstSharedPtr credentials_;
  };

  // Set Credentials shared_ptr to all threads.
  void setCredentialsToAllThreads(Credentials&& creds) {
    CredentialsConstSharedPtr shared_credentials = std::move(creds);
    tls_.runOnAllThreads([shared_credentials](OptRef<ThreadLocalCredentialsCache> obj) {
      obj->credentials_ = shared_credentials;
    });
  }

  Api::Api& api_;
  OnAsyncFetchCb on_async_fetch_cb_;
  // Store the method to fetch metadata from libcurl (deprecated)
  FetchMetadataUsingCurl fetch_metadata_using_curl_;
  // The Metadata fetcher object
  MetadataFetcherPtr metadata_fetcher_;
  // The callback used to create a MetadataFetcher instance.
  CreateMetadataFetcherCb create_metadata_fetcher_cb_;

  // The cache duration.
  const std::chrono::seconds cache_duration_;
  // The timer to trigger fetch due to cache duration.
  Envoy::Event::TimerPtr cache_duration_timer_;
  // the thread local slot for cache.
  ThreadLocal::TypedSlot<ThreadLocalCredentialsCache> tls_;

  // TODO (suniltheta) This value can come from config.
  std::string cluster_name_;
  SystemTime last_updated_;
  Thread::MutexBasicLockable lock_;

  void refreshIfNeeded();

  virtual bool needsRefresh() PURE;
  virtual void refresh() PURE;

  // Get the Metadata credentials cache duration.
  static std::chrono::seconds getCacheDuration();
};

/**
 * Retrieve AWS credentials from the instance metadata.
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
 */
class InstanceProfileCredentialsProvider : public MetadataCredentialsProviderBase,
                                           public MetadataFetcher::MetadataReceiver {
public:
  InstanceProfileCredentialsProvider(Api::Api& api, Upstream::ClusterManager& cm,
                                     const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                                     CreateMetadataFetcherCb create_metadata_fetcher_cb,
                                     absl::string_view cluster_name)
      : MetadataCredentialsProviderBase(api, fetch_metadata_using_curl, create_metadata_fetcher_cb,
                                        cluster_name),
        cm_(cm) {
    // Just trigger a refresh of credentials.
    // TODO (suniltheta) Add capability to register with init manager.
    const Thread::LockGuard lock(lock_);
    refresh();
  }

  // Handle fetch done.
  void handleFetchDone();
  // Following functions are for MetadataFetcher::MetadataReceiver interface
  void onMetadataSuccess(const std::string&& body) override;
  void onMetadataError(Failure reason) override;

private:
  Upstream::ClusterManager& cm_;

  bool needsRefresh() override;
  void refresh() override;
  void extractCredentials(const std::string&& credential_document_value);
  void fetchCredentialFromInstanceRole(const std::string&& instance_role, bool async = false);
  void fetchCredentialFromInstanceRoleAsync(const std::string&& instance_role) {
    fetchCredentialFromInstanceRole(std::move(instance_role), true);
  }
};

/**
 * Retrieve AWS credentials from the task metadata.
 *
 * https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html#enable_task_iam_roles
 */
class TaskRoleCredentialsProvider : public MetadataCredentialsProviderBase,
                                    public MetadataFetcher::MetadataReceiver {
public:
  TaskRoleCredentialsProvider(Api::Api& api, Upstream::ClusterManager& cm,
                              const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                              CreateMetadataFetcherCb create_metadata_fetcher_cb,
                              absl::string_view credential_uri,
                              absl::string_view authorization_token = {},
                              absl::string_view cluster_name = {})
      : MetadataCredentialsProviderBase(api, fetch_metadata_using_curl, create_metadata_fetcher_cb,
                                        cluster_name),
        cm_(cm), credential_uri_(credential_uri), authorization_token_(authorization_token) {
    // Just trigger a refresh of credentials.
    // TODO (suniltheta) Add capability to register with init manager.
    const Thread::LockGuard lock(lock_);
    refresh();
  }

  // Handle fetch done.
  void handleFetchDone();
  // Following functions are for MetadataFetcher::MetadataReceiver interface
  void onMetadataSuccess(const std::string&& body) override;
  void onMetadataError(Failure reason) override;

private:
  SystemTime expiration_time_;
  Upstream::ClusterManager& cm_;
  std::string credential_uri_;
  std::string authorization_token_;

  bool needsRefresh() override;
  void refresh() override;
  void extractCredentials(const std::string&& credential_document_value);
};

/**
 * AWS credentials provider chain, able to fallback between multiple credential providers.
 */
class CredentialsProviderChain : public CredentialsProvider,
                                 public Logger::Loggable<Logger::Id::aws> {
public:
  ~CredentialsProviderChain() override = default;

  void add(const CredentialsProviderSharedPtr& credentials_provider) {
    providers_.emplace_back(credentials_provider);
  }

  Credentials getCredentials() override;

protected:
  std::list<CredentialsProviderSharedPtr> providers_;
};

class CredentialsProviderChainFactories {
public:
  virtual ~CredentialsProviderChainFactories() = default;

  virtual CredentialsProviderSharedPtr createEnvironmentCredentialsProvider() const PURE;

  virtual CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb, absl::string_view cluster_name,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const PURE;

  virtual CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb,
      absl::string_view cluster_name) const PURE;
};

/**
 * Default AWS credentials provider chain.
 *
 * Reference implementation:
 * https://github.com/aws/aws-sdk-cpp/blob/master/aws-cpp-sdk-core/source/auth/AWSCredentialsProviderChain.cpp#L44
 */
class DefaultCredentialsProviderChain : public CredentialsProviderChain,
                                        public CredentialsProviderChainFactories {
public:
  DefaultCredentialsProviderChain(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl)
      : DefaultCredentialsProviderChain(api, cm, fetch_metadata_using_curl, *this) {}

  DefaultCredentialsProviderChain(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      const CredentialsProviderChainFactories& factories);

private:
  CredentialsProviderSharedPtr createEnvironmentCredentialsProvider() const override {
    return std::make_shared<EnvironmentCredentialsProvider>();
  }

  CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb, absl::string_view cluster_name,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const override {
    return std::make_shared<TaskRoleCredentialsProvider>(api, cm, fetch_metadata_using_curl,
                                                         create_metadata_fetcher_cb, credential_uri,
                                                         authorization_token, cluster_name);
  }

  CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb,
      absl::string_view cluster_name) const override {
    return std::make_shared<InstanceProfileCredentialsProvider>(
        api, cm, fetch_metadata_using_curl, create_metadata_fetcher_cb, cluster_name);
  }
};

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
