load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "stateiotest",
    testonly = 1,
    srcs = ["held_writer.go"],
    importpath = "gvisor.dev/gvisor/pkg/sentry/state/stateio/stateiotest",
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/hostarch",
        "//pkg/sentry/memmap",
        "//pkg/sentry/state/stateio",
        "//pkg/sync",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
