cmake_minimum_required(VERSION 3.20)
project(s3mm VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_library(ARGON2_LIBRARY NAMES argon2 REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/include)

# ---------------------------------------------------------------- core library
add_library(s3mm_core STATIC
  src/common/str.cpp
  src/common/units.cpp
  src/common/time.cpp
  src/common/log.cpp
  src/common/fs.cpp
  src/common/glob.cpp
  src/common/value.cpp
  src/common/secret.cpp
  src/common/crypto.cpp
  src/common/zip.cpp
  src/config/config.cpp
  src/policy/lexer.cpp
  src/policy/expr.cpp
  src/policy/rule.cpp
  src/policy/bundle.cpp
  src/policy/engine.cpp
  src/s3/http.cpp
  src/s3/sigv4.cpp
  src/s3/xml.cpp
  src/s3/client.cpp
  src/module/loader.cpp
  src/module/iam_export.cpp
  src/registry/registry.cpp
  src/registry/mutate.cpp
  src/replication/cache.cpp
  src/replication/target.cpp
  src/replication/basket.cpp
  src/replication/stat.cpp
  src/replication/access.cpp
  src/replication/engine.cpp
)
target_link_libraries(s3mm_core PUBLIC
  CURL::libcurl OpenSSL::SSL OpenSSL::Crypto Threads::Threads ZLIB::ZLIB ${CMAKE_DL_LIBS})
target_compile_definitions(s3mm_core PUBLIC S3MM_VERSION="${PROJECT_VERSION}")

# --------------------------------------------------------------------- daemon
add_executable(s3mmd
  src/daemon/daemon.cpp
  src/daemon/server.cpp
  src/daemon/peerserver.cpp
  src/daemon/metrics.cpp
  src/daemon/main.cpp
)
target_link_libraries(s3mmd PRIVATE s3mm_core)

# ------------------------------------------------------------------------ cli
add_executable(s3mm
  src/cli/main.cpp
  src/cli/commands.cpp
  src/cli/render.cpp
  src/cli/client.cpp
)
target_link_libraries(s3mm PRIVATE s3mm_core)

# --------------------------------------------------------------- rest daemon
add_executable(s3mmws
  src/rest/main.cpp
  src/rest/daemon.cpp
  src/rest/server.cpp
  src/rest/router.cpp
  src/rest/loader.cpp
  src/rest/auth.cpp
  src/rest/rbac_store.cpp
  src/rest/cluster.cpp
  src/cli/client.cpp
)
target_link_libraries(s3mmws PRIVATE s3mm_core ${ARGON2_LIBRARY} ldap lber)

# -------------------------------------------------------------------- modules
function(s3mm_module name)
  add_library(s3mm_mod_${name} MODULE ${ARGN})
  target_link_libraries(s3mm_mod_${name} PRIVATE s3mm_core)
  set_target_properties(s3mm_mod_${name} PROPERTIES
    PREFIX "" OUTPUT_NAME "s3mm_mod_${name}"
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/modules)
endfunction()

s3mm_module(minio modules/minio/mod_minio.cpp)
target_link_libraries(s3mm_mod_minio PRIVATE ${ARGON2_LIBRARY})
s3mm_module(aws    modules/aws/mod_aws.cpp)
s3mm_module(ceph   modules/ceph/mod_ceph.cpp)
s3mm_module(rustfs modules/rustfs/mod_rustfs.cpp)

# ---------------------------------------------------------------------- tests
enable_testing()
add_executable(s3mm_tests
  tests/unit/main.cpp
  tests/unit/test_units.cpp
  tests/unit/test_str.cpp
  tests/unit/test_glob.cpp
  tests/unit/test_value.cpp
  tests/unit/test_config.cpp
  tests/unit/test_lexer.cpp
  tests/unit/test_expr.cpp
  tests/unit/test_rule.cpp
  tests/unit/test_bundle.cpp
  tests/unit/test_engine.cpp
  tests/unit/test_sigv4.cpp
  tests/unit/test_xml.cpp
  tests/unit/test_cache.cpp
  tests/unit/test_zip.cpp
  tests/unit/test_template.cpp
  tests/unit/test_target.cpp
  tests/unit/test_secrets.cpp
  tests/unit/test_registry.cpp
)
target_link_libraries(s3mm_tests PRIVATE s3mm_core)
add_test(NAME unit COMMAND s3mm_tests)

add_executable(s3mm_e2e
  tests/e2e/fake_s3.cpp
  tests/e2e/main.cpp
)
target_link_libraries(s3mm_e2e PRIVATE s3mm_core)
add_test(NAME e2e COMMAND s3mm_e2e)

# ------------------------------------------------------------------- install
install(TARGETS s3mmd s3mm s3mmws RUNTIME DESTINATION bin)
install(DIRECTORY ${CMAKE_BINARY_DIR}/modules/ DESTINATION lib/s3mm/modules FILES_MATCHING PATTERN "*.so")
