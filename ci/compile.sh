#!/bin/bash
set -euxo pipefail

source "${WORKDIR}"/ci/env.sh
source "${WORKDIR}"/ci/archs.sh

# Since race detector has huge performance price and it works only on amd64 and does not
# work with pie executables, its enabled only for development builds.
# shellcheck disable=SC2153
if [ "${ENVIRONMENT}" = "dev" ]; then
	[ "${ARCH}" = "amd64" ] && [ "${RACE_DETECTOR_ENABLED:-""}" == "1" ] && BUILDMODE="-race"
	TRIMPATH=""
else
	BUILDMODE="-buildmode=pie"
	TRIMPATH="-trimpath"
fi

# SALT is deprecated, therefore, example value can safely be used
ldflags="-X 'main.Version=${VERSION}' \
	-X 'main.Environment=${ENVIRONMENT}' \
	-X 'main.Hash=${HASH}' \
	-X 'main.Arch=${ARCH}' \
	-X 'main.RemotePath=${REMOTE_PATH:-rc}' \
	-X 'main.PackageType=${PACKAGE:-deb}' \
	-X 'main.Salt=${SALT:-f1nd1ngn3m0}'"

declare -A names_map=(
	[cli]=nordvpn
	[daemon]=nordvpnd
	[downloader]=downloader
	[fileshare]=nordfileshare
	[norduser]=norduserd
)

# shellcheck disable=SC2034
declare -A cross_compiler_map=(
    [i386]=i686-linux-gnu-gcc
    [amd64]=x86_64-linux-gnu-gcc
    [armel]=arm-linux-gnueabi-gcc
    [armhf]=arm-linux-gnueabihf-gcc
    [aarch64]=aarch64-linux-gnu-gcc
)

# Required by Go when cross-compiling
export CGO_ENABLED=1
GOARCH="${ARCHS_GO["${ARCH}"]}"
export GOARCH="${GOARCH}"

# C compiler flags for binary hardening.
export CGO_CFLAGS="-g -O2 -D_FORTIFY_SOURCE=2"

# These C linker flags get appended to the ones specified in the source code
export CGO_LDFLAGS="${CGO_LDFLAGS:-""} -Wl,-z,relro,-z,now"

# Required by Go when cross-compiling to 32bit ARM architectures
[ "${ARCH}" == "armel" ] && export GOARM=5
[ "${ARCH}" == "armhf" ] && export GOARM=7

# In order to enable additional features, provide `FEATURES` environment variable
tags="${FEATURES:-"none"}"

source "${WORKDIR}"/ci/set_bindings_version.sh libtelio
source "${WORKDIR}"/ci/set_bindings_version.sh libdrop

trap -- '${WORKDIR}/ci/remove_private_bindings.sh moose/events; ${WORKDIR}/ci/remove_private_bindings.sh moose/worker; ${WORKDIR}/ci/remove_private_bindings.sh quench' EXIT
if [[ $tags == *"moose"* ]]; then
	# Set correct events domain in case compiling with moose
	if [[ "${ENVIRONMENT}" == "prod" ]]; then
		events_domain="${EVENTS_PROD_DOMAIN}"
	else
		events_domain="${EVENTS_STAGING_DOMAIN}"
	fi

	ldflags="${ldflags} \
		-X 'main.EventsDomain=${events_domain:-""}' \
		-X 'main.EventsSubdomain=${EVENTS_SUBDOMAIN:-""}'"

	source "${WORKDIR}"/ci/add_private_bindings.sh moose/events ./third-party/moose-events/moosenordvpnappgo/v16
	source "${WORKDIR}"/ci/add_private_bindings.sh moose/worker ./third-party/moose-worker/mooseworkergo/v16
fi

if [[ $tags == *"quench"* ]]; then
	source "${WORKDIR}"/ci/add_private_bindings.sh quench ./third-party/libquench-go
fi

for program in ${!names_map[*]}; do # looping over keys
	pushd "${WORKDIR}/cmd/${program}"
	# BUILDMODE can be no value and `go` does not like empty parameter ''
	# this is why surrounding double quotes are removed to not cause empty parameter i.e. ''
	# shellcheck disable=SC2086
	CC="${cross_compiler_map[${ARCH}]}" \
		go build ${BUILD_FLAGS:+"${BUILD_FLAGS}"} ${BUILDMODE:-} -tags "${tags}" \
		${TRIMPATH:-} -ldflags "-linkmode=external ${ldflags}" \
		-o "${WORKDIR}/bin/${ARCH}/${names_map[${program}]}"
	popd
done
