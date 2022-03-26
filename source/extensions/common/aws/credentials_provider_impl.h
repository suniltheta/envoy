#pragma once

#include <list>

#include "envoy/api/api.h"
#include "envoy/event/timer.h"
#include "envoy/http/message.h"

#include "source/common/common/logger.h"
#include "source/common/common/thread.h"
#include "source/extensions/common/aws/credentials_provider.h"

#include "absl/strings/string_view.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

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
  using MetadataFetcher = std::function<absl::optional<std::string>(Http::RequestMessage&)>;

  MetadataCredentialsProviderBase(Api::Api& api, const MetadataFetcher& metadata_fetcher)
      : api_(api), metadata_fetcher_(metadata_fetcher) {}

  Credentials getCredentials() override {
    refreshIfNeeded();
    return cached_credentials_;
  }

protected:
  Api::Api& api_;
  MetadataFetcher metadata_fetcher_;
  SystemTime last_updated_;
  Credentials cached_credentials_;
  Thread::MutexBasicLockable lock_;

  void refreshIfNeeded();

  virtual bool needsRefresh() PURE;
  virtual void refresh() PURE;
};

/**
 * Retrieve AWS credentials from the instance metadata.
 *
 * https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#instance-metadata-security-credentials
 */
class InstanceProfileCredentialsProvider : public MetadataCredentialsProviderBase {
public:
  InstanceProfileCredentialsProvider(Api::Api& api, Upstream::ClusterManager& cm,
                                     const MetadataFetcher& metadata_fetcher,
                                     absl::string_view cluster_name = {})
      : MetadataCredentialsProviderBase(api, metadata_fetcher), cm_(cm),
        cluster_name_(cluster_name) {
    UNREFERENCED_PARAMETER(cm_);
    UNREFERENCED_PARAMETER(cluster_name_);
  }

private:
  Upstream::ClusterManager& cm_;
  // TODO (suniltheta) This value can come from config.
  const std::string cluster_name_;

  bool needsRefresh() override;
  void refresh() override;
  void extractCredentials(const std::string& credential_document_value);
  void fetchCredentialFromInstanceRole(const std::string& instance_role, bool async = false);
  void fetchCredentialFromInstanceRoleAsync(const std::string& instance_role) {
    fetchCredentialFromInstanceRole(instance_role, true);
  }
};

/**
 * Retrieve AWS credentials from the task metadata.
 *
 * https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html#enable_task_iam_roles
 */
class TaskRoleCredentialsProvider : public MetadataCredentialsProviderBase {
public:
  TaskRoleCredentialsProvider(Api::Api& api, Upstream::ClusterManager& cm,
                              const MetadataFetcher& metadata_fetcher,
                              absl::string_view credential_uri,
                              absl::string_view authorization_token = {},
                              absl::string_view cluster_name = {})
      : MetadataCredentialsProviderBase(api, metadata_fetcher), cm_(cm),
        credential_uri_(credential_uri), authorization_token_(authorization_token),
        cluster_name_(cluster_name) {
    UNREFERENCED_PARAMETER(cm_);
    UNREFERENCED_PARAMETER(cluster_name_);
  }

private:
  SystemTime expiration_time_;
  Upstream::ClusterManager& cm_;
  std::string credential_uri_;
  std::string authorization_token_;
  // TODO (suniltheta) This value can come from config.
  const std::string cluster_name_;

  bool needsRefresh() override;
  void refresh() override;
  void extractCredentials(const std::string& credential_document_value);
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
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const PURE;

  virtual CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher) const PURE;
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
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher)
      : DefaultCredentialsProviderChain(api, cm, metadata_fetcher, *this) {}

  DefaultCredentialsProviderChain(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher,
      const CredentialsProviderChainFactories& factories);

private:
  CredentialsProviderSharedPtr createEnvironmentCredentialsProvider() const override {
    return std::make_shared<EnvironmentCredentialsProvider>();
  }

  CredentialsProviderSharedPtr createTaskRoleCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher,
      absl::string_view credential_uri, absl::string_view authorization_token = {}) const override {
    return std::make_shared<TaskRoleCredentialsProvider>(api, cm, metadata_fetcher, credential_uri,
                                                         authorization_token,
                                                         "task_metadata_server_internal");
  }

  CredentialsProviderSharedPtr createInstanceProfileCredentialsProvider(
      Api::Api& api, Upstream::ClusterManager& cm,
      const MetadataCredentialsProviderBase::MetadataFetcher& metadata_fetcher) const override {
    return std::make_shared<InstanceProfileCredentialsProvider>(
        api, cm, metadata_fetcher, "instance_metadata_server_internal");
  }
};

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
