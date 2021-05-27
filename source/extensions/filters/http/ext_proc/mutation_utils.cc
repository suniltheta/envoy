#include "extensions/filters/http/ext_proc/mutation_utils.h"

#include "envoy/http/header_map.h"

#include "common/http/header_utility.h"
#include "common/http/headers.h"
#include "common/protobuf/utility.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace ExternalProcessing {

using Http::Headers;
using Http::LowerCaseString;

using envoy::service::ext_proc::v3alpha::BodyMutation;
using envoy::service::ext_proc::v3alpha::BodyResponse;
using envoy::service::ext_proc::v3alpha::CommonResponse;
using envoy::service::ext_proc::v3alpha::HeaderMutation;
using envoy::service::ext_proc::v3alpha::HeadersResponse;

void MutationUtils::headersToProto(const Http::HeaderMap& headers_in,
                                   envoy::config::core::v3::HeaderMap& proto_out) {
  headers_in.iterate([&proto_out](const Http::HeaderEntry& e) -> Http::HeaderMap::Iterate {
    auto* new_header = proto_out.add_headers();
    new_header->set_key(std::string(e.key().getStringView()));
    new_header->set_value(std::string(e.value().getStringView()));
    return Http::HeaderMap::Iterate::Continue;
  });
}

void MutationUtils::applyCommonHeaderResponse(const HeadersResponse& response,
                                              Http::HeaderMap& headers) {
  if (response.has_response()) {
    const auto& common_response = response.response();
    if (common_response.has_header_mutation()) {
      applyHeaderMutations(common_response.header_mutation(), headers,
                           common_response.status() == CommonResponse::CONTINUE_AND_REPLACE);
    }
  }
}

void MutationUtils::applyHeaderMutations(const HeaderMutation& mutation, Http::HeaderMap& headers,
                                         bool replacing_message) {
  for (const auto& remove_header : mutation.remove_headers()) {
    if (Http::HeaderUtility::isRemovableHeader(remove_header)) {
      ENVOY_LOG(trace, "Removing header {}", remove_header);
      headers.remove(LowerCaseString(remove_header));
    } else {
      ENVOY_LOG(debug, "Header {} is not removable", remove_header);
    }
  }

  for (const auto& sh : mutation.set_headers()) {
    if (!sh.has_header()) {
      continue;
    }
    if (isSettableHeader(sh.header().key(), replacing_message)) {
      // Make "false" the default. This is logical and matches the ext_authz
      // filter. However, the router handles this same protobuf and uses "true"
      // as the default instead.
      const bool append = PROTOBUF_GET_WRAPPED_OR_DEFAULT(sh, append, false);
      ENVOY_LOG(trace, "Setting header {} append = {}", sh.header().key(), append);
      if (append) {
        headers.addCopy(LowerCaseString(sh.header().key()), sh.header().value());
      } else {
        headers.setCopy(LowerCaseString(sh.header().key()), sh.header().value());
      }
    } else {
      ENVOY_LOG(debug, "Header {} is not settable", sh.header().key());
    }
  }
}

void MutationUtils::applyCommonBodyResponse(const BodyResponse& response,
                                            Http::RequestOrResponseHeaderMap* headers,
                                            Buffer::Instance& buffer) {
  if (response.has_response()) {
    const auto& common_response = response.response();
    if (headers != nullptr && common_response.has_header_mutation()) {
      applyHeaderMutations(common_response.header_mutation(), *headers,
                           common_response.status() == CommonResponse::CONTINUE_AND_REPLACE);
    }
    if (common_response.has_body_mutation()) {
      if (headers != nullptr) {
        // Always clear content length if we can before modifying body
        headers->removeContentLength();
      }
      applyBodyMutations(common_response.body_mutation(), buffer);
    }
  }
}

void MutationUtils::applyBodyMutations(const BodyMutation& mutation, Buffer::Instance& buffer) {
  switch (mutation.mutation_case()) {
  case BodyMutation::MutationCase::kClearBody:
    if (mutation.clear_body()) {
      ENVOY_LOG(trace, "Clearing HTTP body");
      buffer.drain(buffer.length());
    }
    break;
  case BodyMutation::MutationCase::kBody:
    ENVOY_LOG(trace, "Replacing body of {} bytes with new body of {} bytes", buffer.length(),
              mutation.body().size());
    buffer.drain(buffer.length());
    buffer.add(mutation.body());
    break;
  default:
    // Nothing to do on default
    break;
  }
}

// Ignore attempts to set certain sensitive headers that can break later processing.
// We may re-enable some of these after further testing. This logic is specific
// to the ext_proc filter so it is not shared with HeaderUtils.
bool MutationUtils::isSettableHeader(absl::string_view key, bool replacing_message) {
  const auto& headers = Headers::get();
  return !absl::EqualsIgnoreCase(key, headers.HostLegacy.get()) &&
         !absl::EqualsIgnoreCase(key, headers.Host.get()) &&
         (!absl::EqualsIgnoreCase(key, headers.Method.get()) || replacing_message) &&
         !absl::EqualsIgnoreCase(key, headers.Scheme.get()) &&
         !absl::StartsWithIgnoreCase(key, headers.prefix());
}

} // namespace ExternalProcessing
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
