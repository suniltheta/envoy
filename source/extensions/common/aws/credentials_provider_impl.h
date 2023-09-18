#pragma once

#include <list>
#include <optional>
#include <string>

#include "envoy/api/api.h"
#include "envoy/common/optref.h"
#include "envoy/event/timer.h"
#include "envoy/http/message.h"
#include "envoy/server/factory_context.h"

#include "source/common/common/lock_guard.h"
#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/common/init/target_impl.h"
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

namespace {
constexpr char EC2_METADATA_IP[] = "169.254.169.254";
constexpr char EC2_METADATA_HOST[] = "169.254.169.254:80";
constexpr char CONTAINER_METADATA_IP[] = "169.254.170.2";
constexpr char CONTAINER_METADATA_HOST[] = "169.254.170.2:80";
}; // namespace

/**
 *  CreateMetadataFetcherCb is a callback interface for creating a MetadataFetcher instance.
 */
using CreateMetadataFetcherCb =
    std::function<MetadataFetcherPtr(Upstream::ClusterManager&, absl::string_view)>;
using FactoryContextOptRef = OptRef<Server::Configuration::FactoryContext>;

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

class CachedCredentialsProviderBase : public CredentialsProvider,
                                      public Logger::Loggable<Logger::Id::aws> {
public:
  Credentials getCredentials() override {
    refreshIfNeeded();
    return cached_credentials_;
  }

protected:
  SystemTime last_updated_;
  Credentials cached_credentials_;
  Thread::MutexBasicLockable lock_;

  void refreshIfNeeded();

  virtual bool needsRefresh() PURE;
  virtual void refresh() PURE;
};

/**
 * Retrieve AWS credentials from the credentials file.
 *
 * Adheres to conventions specified in:
 * https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
 */
class CredentialsFileCredentialsProvider : public CachedCredentialsProviderBase {
public:
  CredentialsFileCredentialsProvider(Api::Api& api) : api_(api) {}

private:
  Api::Api& api_;

  bool needsRefresh() override;
  void refresh() override;
  void extractCredentials(const std::string& credentials_file, const std::string& profile);
};

class MetadataCredentialsProviderBase : public CachedCredentialsProviderBase {
public:
  using FetchMetadataUsingCurl = std::function<absl::optional<std::string>(Http::RequestMessage&)>;
  using OnAsyncFetchCb = std::function<void(const std::string&&)>;

  MetadataCredentialsProviderBase(Api::Api& api, FactoryContextOptRef context,
                                  Upstream::ClusterManager& cm,
                                  const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                                  CreateMetadataFetcherCb create_metadata_fetcher_cb,
                                  absl::string_view cluster_name, absl::string_view host)
      : api_(api), context_(context), cm_(cm),
        fetch_metadata_using_curl_(fetch_metadata_using_curl),
        create_metadata_fetcher_cb_(create_metadata_fetcher_cb),
        cluster_name_(std::string(cluster_name)), cache_duration_(getCacheDuration()),
        debug_name_(absl::StrCat("Fetching aws credentials from cluster=", cluster_name)),
        use_libcurl_(Runtime::runtimeFeatureEnabled(
            "envoy.reloadable_features.use_libcurl_to_fetch_aws_credentials")) {

    if (!use_libcurl_ && context_) {
      context_->mainThreadDispatcher().post([this, host]() {
        if (!Utility::addInternalClusterStatic(cm_, cluster_name_, "STATIC", host)) {
          throw EnvoyException(fmt::format(
              "Failed to add [STATIC cluster = {} with address = {}] or cluster not found",
              cluster_name_, host));
        }
      });

      tls_ =
          ThreadLocal::TypedSlot<ThreadLocalCredentialsCache>::makeUnique(context_->threadLocal());
      tls_->set([](Envoy::Event::Dispatcher&) {
        return std::make_shared<ThreadLocalCredentialsCache>();
      });

      cache_duration_timer_ = context_->mainThreadDispatcher().createTimer([this]() -> void {
        const Thread::LockGuard lock(lock_);
        refresh();
      });

      // Register to init_manager, force the listener to wait for the fetching (refresh).
      init_target_ =
          std::make_unique<Init::TargetImpl>(debug_name_, [this]() -> void { refresh(); });
      context_->initManager().add(*init_target_);
    }
  }

  Credentials getCredentials() override;

  const std::string& clusterName() { return cluster_name_; }

  // Handle fetch done.
  void handleFetchDone();

  // Get the Metadata credentials cache duration.
  static std::chrono::seconds getCacheDuration();

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
  void setCredentialsToAllThreads(CredentialsConstUniquePtr&& creds) {
    CredentialsConstSharedPtr shared_credentials = std::move(creds);
    if (tls_) {
      tls_->runOnAllThreads([shared_credentials](OptRef<ThreadLocalCredentialsCache> obj) {
        obj->credentials_ = shared_credentials;
      });
    }
  }

  Api::Api& api_;
  // The opt factory context.
  FactoryContextOptRef context_;
  // The cluster manager object.
  Upstream::ClusterManager& cm_;
  // Store the method to fetch metadata from libcurl (deprecated)
  FetchMetadataUsingCurl fetch_metadata_using_curl_;
  // The callback used to create a MetadataFetcher instance.
  CreateMetadataFetcherCb create_metadata_fetcher_cb_;
  // TODO (suniltheta) This value can come from config.
  std::string cluster_name_;
  // The cache duration.
  const std::chrono::seconds cache_duration_;
  // the thread local slot for cache.
  ThreadLocal::TypedSlotPtr<ThreadLocalCredentialsCache> tls_;
  // The timer to trigger fetch due to cache duration.
  Envoy::Event::TimerPtr cache_duration_timer_;
  // The Metadata fetcher object
  MetadataFetcherPtr metadata_fetcher_;

  OnAsyncFetchCb on_async_fetch_cb_;
  SystemTime last_updated_;
  Credentials cached_credentials_;
  Thread::MutexBasicLockable lock_;

  // The init target.
  std::unique_ptr<Init::TargetImpl> init_target_;

  // Used in logs.
  const std::string debug_name_;

  const bool use_libcurl_;

  void refreshIfNeeded();

  virtual bool needsRefresh() PURE;
  virtual void refresh() PURE;
};


/**
 * Retrieve AWS credentials from the instance metadata.
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
 */
class InstanceProfileCredentialsProvider : public MetadataCredentialsProviderBase,
                                           public MetadataFetcher::MetadataReceiver {
public:
  InstanceProfileCredentialsProvider(Api::Api& api, FactoryContextOptRef context,
                                     Upstream::ClusterManager& cm,
                                     const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                                     CreateMetadataFetcherCb create_metadata_fetcher_cb,
                                     absl::string_view cluster_name)
      : MetadataCredentialsProviderBase(api, context, cm, fetch_metadata_using_curl,
                                        create_metadata_fetcher_cb, cluster_name,
                                        EC2_METADATA_HOST) {
    // Fetch the credentials as we are not registering with init manager.
    if (!use_libcurl_ && !context_) {
      refresh();
    }
  }

  // Following functions are for MetadataFetcher::MetadataReceiver interface
  void onMetadataSuccess(const std::string&& body) override;
  void onMetadataError(Failure reason) override;

private:
  bool needsRefresh() override;
  void refresh() override;
  void fetchInstanceRole(const std::string& token, bool async = false);
  void fetchInstanceRoleAsync(const std::string& token) {
    fetchInstanceRole(std::move(token), true);
  }
  void fetchCredentialFromInstanceRole(const std::string&& instance_role, const std::string&& token,
                                       bool async = false);
  void fetchCredentialFromInstanceRoleAsync(const std::string&& instance_role,
                                            const std::string&& token) {
    fetchCredentialFromInstanceRole(std::move(instance_role), std::move(token), true);
  }
  void extractCredentials(const std::string&& credential_document_value, bool async = false);
  void extractCredentialsAsync(const std::string&& credential_document_value) {
    extractCredentials(std::move(credential_document_value), true);
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
  TaskRoleCredentialsProvider(Api::Api& api, FactoryContextOptRef context,
                              Upstream::ClusterManager& cm,
                              const FetchMetadataUsingCurl& fetch_metadata_using_curl,
                              CreateMetadataFetcherCb create_metadata_fetcher_cb,
                              absl::string_view credential_uri,
                              absl::string_view authorization_token = {},
                              absl::string_view cluster_name = {})
      : MetadataCredentialsProviderBase(api, context, cm, fetch_metadata_using_curl,
                                        create_metadata_fetcher_cb, cluster_name,
                                        CONTAINER_METADATA_HOST),
        credential_uri_(credential_uri), authorization_token_(authorization_token) {
    // Fetch the credentials as we are not registering with init manager.
    if (!use_libcurl_ && !context_) {
      refresh();
    }
  }

  // Following functions are for MetadataFetcher::MetadataReceiver interface
  void onMetadataSuccess(const std::string&& body) override;
  void onMetadataError(Failure reason) override;

private:
  SystemTime expiration_time_;
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

  virtual CredentialsProviderSharedPtr
  createCredentialsFileCredentialsProvider(Api::Api& api) const PURE;

  virtual CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb, absl::string_view cluster_name,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const PURE;

  virtual CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
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
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl)
      : DefaultCredentialsProviderChain(api, context, cm, fetch_metadata_using_curl, *this) {}

  DefaultCredentialsProviderChain(
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      const CredentialsProviderChainFactories& factories);

private:
  CredentialsProviderSharedPtr createEnvironmentCredentialsProvider() const override {
    return std::make_shared<EnvironmentCredentialsProvider>();
  }

  CredentialsProviderSharedPtr
  createCredentialsFileCredentialsProvider(Api::Api& api) const override {
    return std::make_shared<CredentialsFileCredentialsProvider>(api);
  }

  CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb, absl::string_view cluster_name,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const override {
    return std::make_shared<TaskRoleCredentialsProvider>(
        api, context, cm, fetch_metadata_using_curl, create_metadata_fetcher_cb, credential_uri,
        authorization_token, cluster_name);
  }

  CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
      CreateMetadataFetcherCb create_metadata_fetcher_cb,
      absl::string_view cluster_name) const override {
    return std::make_shared<InstanceProfileCredentialsProvider>(
        api, context, cm, fetch_metadata_using_curl, create_metadata_fetcher_cb, cluster_name);
  }
};

using InstanceProfileCredentialsProviderPtr = std::shared_ptr<InstanceProfileCredentialsProvider>;
using TaskRoleCredentialsProviderPtr = std::shared_ptr<TaskRoleCredentialsProvider>;

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
