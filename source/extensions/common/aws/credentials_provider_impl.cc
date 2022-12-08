#include "source/extensions/common/aws/credentials_provider_impl.h"

#include "envoy/common/exception.h"

#include "source/common/common/lock_guard.h"
#include "source/common/http/message_impl.h"
#include "source/common/http/utility.h"
#include "source/common/json/json_loader.h"
#include "source/common/tracing/http_tracer_impl.h"

namespace Envoy {
namespace Extensions {
namespace Common {
namespace Aws {

namespace {

constexpr char AWS_ACCESS_KEY_ID[] = "AWS_ACCESS_KEY_ID";
constexpr char AWS_SECRET_ACCESS_KEY[] = "AWS_SECRET_ACCESS_KEY";
constexpr char AWS_SESSION_TOKEN[] = "AWS_SESSION_TOKEN";

constexpr char ACCESS_KEY_ID[] = "AccessKeyId";
constexpr char SECRET_ACCESS_KEY[] = "SecretAccessKey";
constexpr char TOKEN[] = "Token";
constexpr char EXPIRATION[] = "Expiration";
constexpr char EXPIRATION_FORMAT[] = "%E4Y%m%dT%H%M%S%z";
constexpr char TRUE[] = "true";

constexpr char AWS_CONTAINER_CREDENTIALS_RELATIVE_URI[] = "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI";
constexpr char AWS_CONTAINER_CREDENTIALS_FULL_URI[] = "AWS_CONTAINER_CREDENTIALS_FULL_URI";
constexpr char AWS_CONTAINER_AUTHORIZATION_TOKEN[] = "AWS_CONTAINER_AUTHORIZATION_TOKEN";
constexpr char AWS_EC2_METADATA_DISABLED[] = "AWS_EC2_METADATA_DISABLED";

constexpr std::chrono::hours REFRESH_INTERVAL{1};
constexpr std::chrono::seconds REFRESH_GRACE_PERIOD{5};
constexpr char SECURITY_CREDENTIALS_PATH[] = "/latest/meta-data/iam/security-credentials";

constexpr char EC2_METADATA_CLUSTER[] = "ec2_instance_metadata_server_internal";
constexpr char CONTAINER_METADATA_CLUSTER[] = "ecs_task_metadata_server_internal";

} // namespace

Credentials EnvironmentCredentialsProvider::getCredentials() {
  ENVOY_LOG(debug, "Getting AWS credentials from the environment");

  const auto access_key_id = absl::NullSafeStringView(std::getenv(AWS_ACCESS_KEY_ID));
  if (access_key_id.empty()) {
    return Credentials();
  }

  const auto secret_access_key = absl::NullSafeStringView(std::getenv(AWS_SECRET_ACCESS_KEY));
  const auto session_token = absl::NullSafeStringView(std::getenv(AWS_SESSION_TOKEN));

  ENVOY_LOG(debug, "Found following AWS credentials in the environment: {}={}, {}={}, {}={}",
            AWS_ACCESS_KEY_ID, access_key_id, AWS_SECRET_ACCESS_KEY,
            secret_access_key.empty() ? "" : "*****", AWS_SESSION_TOKEN,
            session_token.empty() ? "" : "*****");

  return Credentials(access_key_id, secret_access_key, session_token);
}

Credentials MetadataCredentialsProviderBase::getCredentials() {
  refreshIfNeeded();
  if (!use_libcurl_ && context_ && tls_) {
    // If factor context was supplied then we would have thread local slot initialized.
    return *(*tls_)->credentials_.get();
  } else {
    return cached_credentials_;
  }
}

void MetadataCredentialsProviderBase::refreshIfNeeded() {
  ENVOY_LOG(trace, "{}", __func__);
  const Thread::LockGuard lock(lock_);
  if (needsRefresh()) {
    refresh();
  }
}

std::chrono::seconds MetadataCredentialsProviderBase::getCacheDuration() {
  // TODO (suniltheta) This value should be configurable.
  return std::chrono::seconds(
      REFRESH_INTERVAL * 60 * 60 -
      REFRESH_GRACE_PERIOD /*TODO: Add jitter from context.api().randomGenerator()*/);
}

void MetadataCredentialsProviderBase::handleFetchDone() {
  if (!use_libcurl_ && context_) {
    if (init_target_) {
      init_target_->ready();
      init_target_.reset();
    }
    if (cache_duration_timer_ && !cache_duration_timer_->enabled()) {
      cache_duration_timer_->enableTimer(cache_duration_);
    }
  }
}

bool InstanceProfileCredentialsProvider::needsRefresh() {
  bool needs_refresh = api_.timeSource().systemTime() - last_updated_ > REFRESH_INTERVAL;
  ENVOY_LOG(trace, "{} : {}", __func__, needs_refresh);
  return needs_refresh;
}

void InstanceProfileCredentialsProvider::refresh() {
  ENVOY_LOG(debug, "Getting AWS credentials from the instance metadata");
  Http::RequestMessageImpl message;
  message.headers().setScheme(Http::Headers::get().SchemeValues.Http);
  message.headers().setMethod(Http::Headers::get().MethodValues.Get);
  message.headers().setHost(EC2_METADATA_HOST);
  message.headers().setPath(SECURITY_CREDENTIALS_PATH);

  if (use_libcurl_) {
    // Using curl to fetch the AWS credentials where we first discover the instance Role.
    const auto instance_role_string = fetch_metadata_using_curl_(message);
    if (!instance_role_string) {
      ENVOY_LOG(error, "Could not retrieve credentials listing from the instance metadata");
      return;
    }
    fetchCredentialFromInstanceRole(std::move(instance_role_string.value()));
  } else {
    // Stop any existing timer.
    if (cache_duration_timer_ && cache_duration_timer_->enabled()) {
      cache_duration_timer_->disableTimer();
    }
    // Using Http async client to fetch the AWS credentials where we first discover the instance
    // Role.
    if (!metadata_fetcher_) {
      metadata_fetcher_ = create_metadata_fetcher_cb_(cm_, clusterName());
    } else {
      ENVOY_LOG(error, "{}: metadata_fetcher_->cancel();", __func__);
      metadata_fetcher_->cancel();
    }
    on_async_fetch_cb_ = [this](const std::string&& arg) {
      return this->fetchCredentialFromInstanceRoleAsync(std::move(arg));
    };
    metadata_fetcher_->fetch(message, Tracing::NullSpan::instance(), *this);
  }
}

void InstanceProfileCredentialsProvider::fetchCredentialFromInstanceRole(
    const std::string&& instance_role, bool async /*default = false*/) {
  ENVOY_LOG(trace, __func__);
  if (instance_role.empty()) {
    ENVOY_LOG(error, "No Roles found from the instance metadata");
    if (async) {
      handleFetchDone();
    }
    return;
  }
  const auto instance_role_list = StringUtil::splitToken(StringUtil::trim(instance_role), "\n");
  if (instance_role_list.empty()) {
    ENVOY_LOG(error, "No Roles found from the instance metadata");
    if (async) {
      handleFetchDone();
    }
    return;
  }
  ENVOY_LOG(debug, "AWS credentials list:\n{}", instance_role);

  // Only one Role can be associated with an instance:
  // https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html
  const auto credential_path =
      std::string(SECURITY_CREDENTIALS_PATH) + "/" +
      std::string(instance_role_list[0].data(), instance_role_list[0].size());
  ENVOY_LOG(debug, "AWS credentials path: {}", credential_path);

  Http::RequestMessageImpl message;
  message.headers().setScheme(Http::Headers::get().SchemeValues.Http);
  message.headers().setMethod(Http::Headers::get().MethodValues.Get);
  message.headers().setHost(EC2_METADATA_HOST);
  message.headers().setPath(credential_path);

  if (!async) {
    // Fetch and parse the credentials.
    const auto credential_document = fetch_metadata_using_curl_(message);
    if (!credential_document) {
      ENVOY_LOG(error, "Could not load AWS credentials document from the instance metadata");
      return;
    }
    extractCredentials(std::move(credential_document.value()));
  } else {
    // Using Http async client to fetch the AWS credentials.
    if (!metadata_fetcher_) {
      metadata_fetcher_ = create_metadata_fetcher_cb_(cm_, clusterName());
    } else {
      ENVOY_LOG(error, "{}: metadata_fetcher_->cancel();", __func__);
      metadata_fetcher_->cancel();
    }

    on_async_fetch_cb_ = [this](const std::string&& arg) {
      return this->extractCredentialsAsync(std::move(arg));
    };
    metadata_fetcher_->fetch(message, Tracing::NullSpan::instance(), *this);
  }
}

void InstanceProfileCredentialsProvider::extractCredentials(
    const std::string&& credential_document_value, bool async /*default = false*/) {
  ENVOY_LOG(trace, __func__);
  if (credential_document_value.empty()) {
    if (async) {
      handleFetchDone();
    }
    return;
  }
  Json::ObjectSharedPtr document_json;
  try {
    document_json = Json::Factory::loadFromString(credential_document_value);
  } catch (EnvoyException& e) {
    ENVOY_LOG(error, "Could not parse AWS credentials document: {}", e.what());
    if (async) {
      handleFetchDone();
    }
    return;
  }

  const auto access_key_id = document_json->getString(ACCESS_KEY_ID, "");
  const auto secret_access_key = document_json->getString(SECRET_ACCESS_KEY, "");
  const auto session_token = document_json->getString(TOKEN, "");

  ENVOY_LOG(debug, "Found following AWS credentials in the instance metadata: {}={}, {}={}, {}={}",
            AWS_ACCESS_KEY_ID, access_key_id, AWS_SECRET_ACCESS_KEY,
            secret_access_key.empty() ? "" : "*****", AWS_SESSION_TOKEN,
            session_token.empty() ? "" : "*****");

  last_updated_ = api_.timeSource().systemTime();
  if (!use_libcurl_ && context_) {
    setCredentialsToAllThreads(
        std::move(std::make_unique<Credentials>(access_key_id, secret_access_key, session_token)));
  } else {
    cached_credentials_ = Credentials(access_key_id, secret_access_key, session_token);
  }
  handleFetchDone();
}

void InstanceProfileCredentialsProvider::onMetadataSuccess(const std::string&& body) {
  // TODO (suniltheta) increment fetch success stats
  ENVOY_LOG(info, "AWS credentials document fetch success, calling callback func");
  on_async_fetch_cb_(std::move(body));
}

void InstanceProfileCredentialsProvider::onMetadataError(Failure) {
  // TODO (suniltheta) increment fetch failed stats
  ENVOY_LOG(error, "AWS credentials document fetch failure");
  handleFetchDone();
}

bool TaskRoleCredentialsProvider::needsRefresh() {
  const auto now = api_.timeSource().systemTime();
  bool needs_refresh =
      (now - last_updated_ > REFRESH_INTERVAL) || (expiration_time_ - now < REFRESH_GRACE_PERIOD);
  ENVOY_LOG(error, "{} : {}", __func__, needs_refresh);
  return needs_refresh;
}

void TaskRoleCredentialsProvider::refresh() {
  ENVOY_LOG(debug, "Getting AWS credentials from the task role at URI: {}", credential_uri_);

  absl::string_view host;
  absl::string_view path;
  Http::Utility::extractHostPathFromUri(credential_uri_, host, path);

  Http::RequestMessageImpl message;
  message.headers().setScheme(Http::Headers::get().SchemeValues.Http);
  message.headers().setMethod(Http::Headers::get().MethodValues.Get);
  message.headers().setHost(host);
  message.headers().setPath(path);
  message.headers().setCopy(Http::CustomHeaders::get().Authorization, authorization_token_);
  if (use_libcurl_) {
    // Using curl to fetch the AWS credentials.
    const auto credential_document = fetch_metadata_using_curl_(message);
    if (!credential_document) {
      ENVOY_LOG(error, "Could not load AWS credentials document from the task role");
      return;
    }
    extractCredentials(std::move(credential_document.value()));
  } else {
    // Stop any existing timer.
    if (cache_duration_timer_ && cache_duration_timer_->enabled()) {
      cache_duration_timer_->disableTimer();
    }
    // Using Http async client to fetch the AWS credentials.
    if (!metadata_fetcher_) {
      metadata_fetcher_ = create_metadata_fetcher_cb_(cm_, clusterName());
    } else {
      metadata_fetcher_->cancel();
    }
    on_async_fetch_cb_ = [this](const std::string&& arg) {
      return this->extractCredentials(std::move(arg));
    };
    metadata_fetcher_->fetch(message, Tracing::NullSpan::instance(), *this);
  }
}

void TaskRoleCredentialsProvider::extractCredentials(
    const std::string&& credential_document_value) {
  ENVOY_LOG(trace, __func__);
  if (credential_document_value.empty()) {
    handleFetchDone();
    return;
  }
  Json::ObjectSharedPtr document_json;
  try {
    document_json = Json::Factory::loadFromString(credential_document_value);
  } catch (EnvoyException& e) {
    ENVOY_LOG(error, "Could not parse AWS credentials document from the task role: {}", e.what());
    handleFetchDone();
    return;
  }

  const auto access_key_id = document_json->getString(ACCESS_KEY_ID, "");
  const auto secret_access_key = document_json->getString(SECRET_ACCESS_KEY, "");
  const auto session_token = document_json->getString(TOKEN, "");

  ENVOY_LOG(debug, "Found following AWS credentials in the task role: {}={}, {}={}, {}={}",
            AWS_ACCESS_KEY_ID, access_key_id, AWS_SECRET_ACCESS_KEY,
            secret_access_key.empty() ? "" : "*****", AWS_SESSION_TOKEN,
            session_token.empty() ? "" : "*****");

  const auto expiration_str = document_json->getString(EXPIRATION, "");
  if (!expiration_str.empty()) {
    absl::Time expiration_time;
    if (absl::ParseTime(EXPIRATION_FORMAT, expiration_str, &expiration_time, nullptr)) {
      ENVOY_LOG(debug, "Task role AWS credentials expiration time: {}", expiration_str);
      expiration_time_ = absl::ToChronoTime(expiration_time);
    }
  }

  last_updated_ = api_.timeSource().systemTime();
  if (!use_libcurl_ && context_) {
    setCredentialsToAllThreads(
        std::move(std::make_unique<Credentials>(access_key_id, secret_access_key, session_token)));
  } else {
    cached_credentials_ = Credentials(access_key_id, secret_access_key, session_token);
  }
  handleFetchDone();
}

void TaskRoleCredentialsProvider::onMetadataSuccess(const std::string&& body) {
  // TODO (suniltheta) increment fetch success stats
  ENVOY_LOG(debug, "AWS credentials document fetch success, calling callback func");
  on_async_fetch_cb_(std::move(body));
}

void TaskRoleCredentialsProvider::onMetadataError(Failure) {
  // TODO (suniltheta) increment fetch failed stats
  ENVOY_LOG(error, "AWS credentials document fetch failure");
  handleFetchDone();
}

Credentials CredentialsProviderChain::getCredentials() {
  for (auto& provider : providers_) {
    const auto credentials = provider->getCredentials();
    if (credentials.accessKeyId() && credentials.secretAccessKey()) {
      return credentials;
    }
  }

  ENVOY_LOG(debug, "No AWS credentials found, using anonymous credentials");
  return Credentials();
}

DefaultCredentialsProviderChain::DefaultCredentialsProviderChain(
    Api::Api& api, FactoryContextOptRef context, Upstream::ClusterManager& cm,
    const MetadataCredentialsProviderBase::FetchMetadataUsingCurl& fetch_metadata_using_curl,
    const CredentialsProviderChainFactories& factories) {
  ENVOY_LOG(debug, "Using environment credentials provider");
  add(factories.createEnvironmentCredentialsProvider());

  const auto relative_uri =
      absl::NullSafeStringView(std::getenv(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI));
  const auto full_uri = absl::NullSafeStringView(std::getenv(AWS_CONTAINER_CREDENTIALS_FULL_URI));
  const auto metadata_disabled = absl::NullSafeStringView(std::getenv(AWS_EC2_METADATA_DISABLED));

  if (!relative_uri.empty()) {
    const auto uri = absl::StrCat(CONTAINER_METADATA_HOST, relative_uri);
    ENVOY_LOG(debug, "Using task role credentials provider with URI: {}", uri);
    add(factories.createTaskRoleCredentialsProvider(api, context, cm, fetch_metadata_using_curl,
                                                    MetadataFetcher::create,
                                                    CONTAINER_METADATA_CLUSTER, uri));
  } else if (!full_uri.empty()) {
    const auto authorization_token =
        absl::NullSafeStringView(std::getenv(AWS_CONTAINER_AUTHORIZATION_TOKEN));
    if (!authorization_token.empty()) {
      ENVOY_LOG(debug,
                "Using task role credentials provider with URI: "
                "{} and authorization token",
                full_uri);
      add(factories.createTaskRoleCredentialsProvider(
          api, context, cm, fetch_metadata_using_curl, MetadataFetcher::create,
          CONTAINER_METADATA_CLUSTER, full_uri, authorization_token));
    } else {
      ENVOY_LOG(debug, "Using task role credentials provider with URI: {}", full_uri);
      add(factories.createTaskRoleCredentialsProvider(api, context, cm, fetch_metadata_using_curl,
                                                      MetadataFetcher::create,
                                                      CONTAINER_METADATA_CLUSTER, full_uri));
    }
  } else if (metadata_disabled != TRUE) {
    ENVOY_LOG(debug, "Using instance profile credentials provider");
    add(factories.createInstanceProfileCredentialsProvider(
        api, context, cm, fetch_metadata_using_curl, MetadataFetcher::create,
        EC2_METADATA_CLUSTER)); // TODO: Make cluster name configurable if custom cluster is
                                // provided
  }
}

} // namespace Aws
} // namespace Common
} // namespace Extensions
} // namespace Envoy
