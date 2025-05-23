load(
    "//bazel:envoy_build_system.bzl",
    "envoy_package",
)
load(
    "//test/extensions:extensions_build_system.bzl",
    "envoy_extension_cc_test",
    "envoy_extension_cc_test_library",
)

licenses(["notice"])  # Apache 2

envoy_package()

envoy_extension_cc_test(
    name = "config_test",
    size = "small",
    srcs = ["config_test.cc"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    rbe_pool = "6gig",
    tags = ["skip_on_windows"],
    deps = [
        ":client_test_utils",
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/rate_limit_quota:config",
        "//test/mocks/server:factory_context_mocks",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "filter_test",
    size = "small",
    srcs = ["filter_test.cc"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    rbe_pool = "6gig",
    tags = ["skip_on_windows"],
    deps = [
        ":client_test_utils",
        ":test_utils",
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/rate_limit_quota",
        "//test/common/http:common_lib",
        "//test/mocks/event:event_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:server_mocks",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test(
    name = "client_test",
    size = "small",
    srcs = ["client_test.cc"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    rbe_pool = "6gig",
    tags = ["skip_on_windows"],
    deps = [
        ":client_test_utils",
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/rate_limit_quota",
        "//source/extensions/filters/http/rate_limit_quota:config",
        "//source/extensions/filters/http/rate_limit_quota:global_client_lib",
        "//test/common/http:common_lib",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/service/rate_limit_quota/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test_library(
    name = "client_test_utils",
    hdrs = ["client_test_utils.h"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    tags = ["skip_on_windows"],
    deps = [
        "//source/common/http:header_map_lib",
        "//source/extensions/filters/http/rate_limit_quota:client_lib",
        "//test/mocks/grpc:grpc_mocks",
        "//test/mocks/server:factory_context_mocks",
        "//test/mocks/server:server_mocks",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota/v3:pkg_cc_proto",
    ],
)

envoy_extension_cc_test_library(
    name = "test_utils",
    hdrs = ["test_utils.h"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    tags = ["skip_on_windows"],
)

envoy_extension_cc_test(
    name = "integration_test",
    size = "large",
    srcs = ["integration_test.cc"],
    extension_names = ["envoy.filters.http.rate_limit_quota"],
    rbe_pool = "4core",
    shard_count = 4,
    tags = [
        "cpu:3",
        "skip_on_windows",
    ],
    deps = [
        ":test_utils",
        "//source/common/http:message_lib",
        "//source/extensions/filters/http/rate_limit_quota",
        "//source/extensions/filters/http/rate_limit_quota:config",
        "//test/common/http:common_lib",
        "//test/integration:http_integration_lib",
        "//test/mocks/server:factory_context_mocks",
        "//test/test_common:status_utility_lib",
        "//test/test_common:test_runtime_lib",
        "//test/test_common:utility_lib",
        "@envoy_api//envoy/config/core/v3:pkg_cc_proto",
        "@envoy_api//envoy/extensions/filters/http/rate_limit_quota/v3:pkg_cc_proto",
        "@envoy_api//envoy/service/rate_limit_quota/v3:pkg_cc_proto",
        "@envoy_api//envoy/type/v3:pkg_cc_proto",
    ],
)
