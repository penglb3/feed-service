#include "client.h"
#include "common/root_certificate.hpp"
#include "common/server_certificate.hpp"
#include <algorithm>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/string_body_fwd.hpp>
#include <boost/beast/version.hpp>
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <openssl/sha.h>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace json = boost::json;

#ifdef FEED_USE_SSL
using stream_type = net::ssl::stream<beast::tcp_stream>;
#else
using stream_type = beast::tcp_stream;
#endif

using std::string;
using std::string_view;

// Performs an HTTP GET and prints the response
auto do_session(string_view host, string_view port, const string &token,
                string_view target, http::verb method, json::object body)
    -> net::awaitable<std::string> {
  auto executor = co_await net::this_coro::executor;
  auto resolver = net::ip::tcp::resolver{executor};

#ifdef FEED_USE_SSL
  net::ssl::context ctx(net::ssl::context::tlsv13);
  load_server_certificate(ctx);
  // ctx.use_certificate_chain_file("server.crt");
  // ctx.use_private_key_file("client.key",
  //                          boost::asio::ssl::context::file_format::pem);
  // ctx.use_tmp_dh_file("dh.pem");
  stream_type stream{executor, ctx};
  if (!SSL_set_tlsext_host_name(stream.native_handle(), host.data())) {
    throw beast::system_error(static_cast<int>(::ERR_get_error()),
                              net::error::get_ssl_category());
  }
  stream.set_verify_callback(ssl::host_name_verification(host.data()));
  // Look up the domain name
  auto const results = co_await resolver.async_resolve(host, port);
  co_await beast::get_lowest_layer(stream).async_connect(results);

  co_await stream.async_handshake(net::ssl::stream_base::client);
#else
  stream_type stream = beast::tcp_stream{executor};
  // Look up the domain name
  auto const results = co_await resolver.async_resolve(host, port);
  // Make the connection on the IP address we get from a lookup
  co_await stream.async_connect(results);
#endif

  // Set up an HTTP GET request message
  http::request<http::string_body> req{method, target, 11};
  req.set(http::field::host, host);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.set(http::field::content_type, "application/json");
  if (!token.empty()) {
    req.set(http::field::authorization, "Bearer " + token);
  }
  req.keep_alive(false);
  req.body() = json::serialize(body);
  req.prepare_payload();

  // Set the timeout.
#ifdef FEED_USE_SSL
  beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
#else
  stream.expires_after(std::chrono::seconds(30));
#endif
  // Send the HTTP request to the remote host
  co_await http::async_write(stream, req, net::as_tuple);

  // This buffer is used for reading and must be persisted
  beast::flat_buffer buffer;

  // Declare a container to hold the response
  http::response<http::string_body> res;

  // Receive the HTTP response
  co_await http::async_read(stream, buffer, res);

  // Write the message to standard out
  std::cout << res << std::endl;

  // Gracefully close the socket
  beast::error_code ec;
#ifdef FEED_USE_SSL
  std::tie(ec) = co_await stream.async_shutdown(net::as_tuple);
#else
  stream.socket().shutdown(net::ip::tcp::socket::shutdown_send, ec);
  stream.close();
#endif

  // not_connected happens sometimes
  // so don't bother reporting it.
  //
  if (ec && ec != beast::errc::not_connected) {
    throw boost::system::system_error(ec, "shutdown");
  }

  // If we get here then the connection is closed gracefully
  co_return res.body();
}

auto client::request(string_view api, http::verb method,
                     json::object &&body = {}) -> json::object {
  // The io_context is required for all I/O
  net::io_context ctx;

  // Launch the asynchronous operation
  auto future =
      net::co_spawn(ctx, do_session(host_, port_, token_, api, method, body),
                    net::use_future);

  // Run the I/O service. The call will return when
  // the operation is complete.
  ctx.run();
  std::error_code ec;
  json::value result = json::parse(future.get(), ec);
  if (ec) {
    return {{"error", "invalid json"}};
  }
  return result.as_object();
}

inline auto encode64(const std::vector<uint8_t> &val) -> std::string {
  namespace iterators = boost::archive::iterators;
  using It = iterators::base64_from_binary<
      iterators::transform_width<std::vector<uint8_t>::const_iterator, 6, 8>>;
  auto tmp = std::string(It(std::begin(val)), It(std::end(val)));
  return tmp.append((3 - val.size() % 3) % 3, '=');
}

auto client::password_hash_base64(string_view password) -> std::string {
  std::vector<uint8_t> md(SHA256_DIGEST_LENGTH, 0);
  if (SHA256(reinterpret_cast<const uint8_t *>(password.data()),
             password.size(), md.data()) != nullptr) {
    return encode64(md);
  }
  return {};
}

auto client::user_register(string_view username, string_view password) -> int {
  json::object body({{"username", username},
                     {"password_hash", password_hash_base64(password)}});
  json::object resp =
      request("/api/register/", http::verb::post, std::move(body));
  if (resp.contains("user_id") && resp.contains("token")) {
    token_ = resp.at("token").as_string();
    return user_id_ = resp.at("user_id").as_int64();
  }
  return kFailed;
}

auto client::user_login(string_view username, string_view password) -> int {
  json::object body({{"username", username},
                     {"password_hash", password_hash_base64(password)}});
  json::object resp = request("/api/login/", http::verb::post, std::move(body));
  if (resp.contains("user_id") && resp.contains("token")) {
    token_ = resp.at("token").as_string();
    return user_id_ = resp.at("user_id").as_int64();
  }
  return kFailed;
}

auto client::_get_posts(int user_id, string_view username)
    -> result<std::vector<json::object>> {
  json::object body;
  if (user_id != -1) {
    body["user_id"] = user_id;
  } else {
    body["username"] = username;
  }
  json::object resp = request("/api/post/", http::verb::get, std::move(body));
  if (resp.contains("posts")) {
    const json::array &arr = resp.at("posts").as_array();
    std::vector<json::object> res;
    res.reserve(arr.size());
    std::for_each(arr.begin(), arr.end(), [&res](const json::value &v) {
      if (v.is_string()) {
        res.emplace_back(json::parse(v.as_string()).as_object());
      } else {
        res.emplace_back(v.as_object());
      }
    });
    return {0, res};
  }
  return {kFailed};
}

#define REQUIRE_LOGIN(nil_value)                                               \
  if (user_id_ == -1) {                                                        \
    return nil_value;                                                          \
  }

auto client::follow_user(string_view follow_name) -> int {
  REQUIRE_LOGIN(kNotLoggedIn);
  json::object resp = request("/api/follow/" + get_id_str(), http::verb::post,
                              {{"follow_name", follow_name}});
  return resp.contains("status") && resp.at("status").as_string() == "success"
             ? 0
             : kFailed;
}

auto client::publish_post(string_view post_content) -> int {
  REQUIRE_LOGIN(kNotLoggedIn);
  json::object resp =
      request("/api/post/", http::verb::post,
              {{"user_id", user_id_}, {"content", post_content}});
  return resp.contains("post_id") ? 0 : kFailed;
}

auto client::get_follow_list() -> result<std::vector<int>> {
  REQUIRE_LOGIN({kNotLoggedIn});
  json::object resp = request("/api/follow/" + get_id_str(), http::verb::get);
  if (resp.contains("followed")) {
    const json::array &arr = resp.at("followed").as_array();
    std::vector<int> res;
    res.reserve(arr.size());
    std::for_each(arr.begin(), arr.end(), [&res](const json::value &v) {
      res.emplace_back(v.as_int64());
    });
    return {0, res};
  }
  return {kFailed};
}

auto client::get_feed() -> result<std::vector<json::object>> {
  REQUIRE_LOGIN({kNotLoggedIn});
  json::object resp = request("/api/feed/" + get_id_str(), http::verb::get);
  if (resp.contains("posts")) {
    const json::array &arr = resp.at("posts").as_array();
    std::vector<json::object> res;
    res.reserve(arr.size());
    std::for_each(arr.begin(), arr.end(), [&res](const json::value &v) {
      if (v.is_string()) {
        res.emplace_back(json::parse(v.as_string()).as_object());
      } else if (v.is_object()) {
        res.emplace_back(v.as_object());
      }
    });
    return {0, res};
  }
  return {kFailed};
}