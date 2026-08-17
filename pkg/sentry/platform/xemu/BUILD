load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "xemu",
    srcs = [
        "addressspace.go",
        "context.go",
        "donor.go",
        "filters.go",
        "filters_amd64.go",
        "filters_arm64.go",
        "switch_amd64.s",
        "switch_arm64.s",
        "xemu.go",
        "xemu_amd64.go",
        "xemu_arm64.go",
        "xemu_unsafe.go",
    ],
    visibility = ["//:sandbox"],
    deps = [
        "//pkg/abi/linux",
        "//pkg/atomicbitops",
        "//pkg/context",
        "//pkg/cpuid",
        "//pkg/fd",
        "//pkg/hostarch",
        "//pkg/hostsyscall",
        "//pkg/hosttid",
        "//pkg/log",
        "//pkg/seccomp",
        "//pkg/sentry/arch",
        "//pkg/sentry/arch/fpu",
        "//pkg/sentry/hostmm",
        "//pkg/sentry/memmap",
        "//pkg/sentry/platform",
        "//pkg/sentry/platform/interrupt",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
