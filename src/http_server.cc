#include "common/config.h"
#include "common/server_certificate.hpp"
#include "jwt-cpp/traits/boost-json/traits.h"
#include <algorithm>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/deferred.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/version.hpp>
#include <boost/config.hpp>
#include <boost/json.hpp>
#include <boost/json/object.hpp>
#include <boost/json/serialize.hpp>
#include <boost/mysql.hpp>
#include <boost/mysql/datetime.hpp>
#include <boost/mysql/diagnostics.hpp>
#include <boost/redis.hpp>
#include <boost/redis/request.hpp>
#include <boost/redis/response.hpp>
#include <boost/redis/src.hpp> // REQUIRED to compile
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <jwt-cpp/jwt.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace redis = boost::redis;
namespace mysql = boost::mysql;
namespace json = boost::json;

using mysql_conn_ptr = std::shared_ptr<mysql::any_connection>;
using redis_conn_ptr = std::shared_ptr<redis::connection>;

template <class Body, class Allocator>
inline auto
json_response(const http::request<Body, http::basic_fields<Allocator>> &req,
              const json::value &data, http::status status = http::status::ok)
    -> http::response<http::string_body> {
  http::response<http::string_body> res{status, req.version()};
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::content_type, "application/json");
  res.keep_alive(req.keep_alive());
  res.body() = json::serialize(data);
  res.prepare_payload();
  return res;
}

// Return a response for the given request.
//
// The concrete type of the response message (which depends on the
// request), is type-erased in message_generator.
template <class Body, class Allocator>
auto handle_request(http::request<Body, http::basic_fields<Allocator>> &&req,
                    mysql_conn_ptr mysql_conn, redis_conn_ptr redis_conn)
    -> net::awaitable<http::message_generator> {

  using Clock = std::chrono::system_clock;
  using TimePoint = mysql::datetime::time_point;
  /* Redis connection needs to be executed on the same thread that created it,
     otherwise the connection may hang. */
  // auto redis_executor = redis_conn->get_executor();
  // auto redis_token = net::bind_executor(redis_executor, net::deferred);
  auto redis_token = net::deferred;
  // Returns a bad request response
  auto const bad_request = [&req](beast::string_view why) {
    http::response<http::string_body> res{http::status::bad_request,
                                          req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = std::string(why);
    res.prepare_payload();
    return res;
  };

  // Returns a not found response
  auto const not_implemented = [&req](beast::string_view target) {
    http::response<http::string_body> res{http::status::not_found,
                                          req.version()};
    res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res.set(http::field::content_type, "text/html");
    res.keep_alive(req.keep_alive());
    res.body() = "The API '" + std::string(target) + "' was not found.";
    res.prepare_payload();
    return res;
  };

  // Make sure we can handle the method
  if (req.method() != http::verb::get && req.method() != http::verb::post &&
      req.method() != http::verb::head) {
    co_return bad_request("Unknown HTTP-method");
  }

  // Request path must be absolute and not contain "..".
  if (req.target().empty() || req.target()[0] != '/' ||
      req.target().find("..") != beast::string_view::npos) {
    co_return bad_request("Illegal request-target");
  }

  auto api_match = [&req](const std::string_view url, http::verb method) {
    return req.target().starts_with(url) && req.method() == method;
  };

  bool bypass_redis_global = false;

  // Use a function so that it will be easier to extend.
  auto bypass_redis = [&bypass_redis_global]() { return bypass_redis_global; };

  const std::string_view issuer("feed-service");
  const jwt::algorithm::es256k jwt_algo(kEs256kPubKey.data(),
                                        kEs256kPrivKey.data(), "", "");
  using traits = jwt::traits::boost_json;
  using claim = jwt::basic_claim<traits>;
  auto create_jwt = [&issuer, &jwt_algo](const std::string &user_id) {
    return jwt::create<traits>()
        .set_issuer(issuer.data())
        .set_type("JWT")
        .set_id(user_id)
        .set_issued_now()
        .set_expires_in(std::chrono::seconds{36000})
        .set_payload_claim("sample", claim(std::string{"test"}))
        .sign(jwt_algo);
  };

  try {
    // 用户注册 POST
    if (api_match("/api/register/", http::verb::post)) {
      auto value = json::parse(req.body());
      std::string_view username = value.at("username").as_string().c_str();
      std::string_view password = value.at("password_hash").as_string().c_str();

      // 插入用户
      mysql::results result;
      mysql::diagnostics diag;
      auto stmt = co_await mysql_conn->async_prepare_statement(
          "INSERT INTO users (username, password_hash) VALUES (?, ?)");
      co_await mysql_conn->async_execute(stmt.bind(username, password), result,
                                         diag);
      co_await mysql_conn->async_close_statement(stmt);
      if (!diag.server_message().empty()) {
        co_return json_response(req, {{"error", diag.server_message()}});
      }

      uint64_t user_id = result.last_insert_id();

      redis::request redis_req;
      std::string id_str(std::to_string(user_id));
      redis_req.push("SET", username, user_id);
      redis_req.push("TS.CREATE", "post_id:" + id_str, "LABELS", "user_id",
                     id_str);
      co_await redis_conn->async_exec(redis_req, redis::ignore, redis_token);

      co_return json_response(std::move(req), {{"user_id", user_id},
                                               {"token", create_jwt(id_str)}});
    }
    if (api_match("/api/login/", http::verb::post)) {
      auto value = json::parse(req.body());
      std::string_view username = value.at("username").as_string().c_str();
      std::string_view password_hash =
          value.at("password_hash").as_string().c_str();

      mysql::results result;
      auto stmt = co_await mysql_conn->async_prepare_statement(
          "SELECT user_id, password_hash FROM users WHERE username = ?");
      co_await mysql_conn->async_execute(stmt.bind(username), result);
      co_await mysql_conn->async_close_statement(stmt);

      json::object res;
      if (!result.empty()) {
        const auto &row = result.rows().at(0);
        if (row.at(1).as_string() == password_hash) {
          res["user_id"] = row.at(0).as_int64();
          res["token"] = create_jwt(std::to_string(row.at(0).as_int64()));
        }
      }
      co_return json_response(req, res);
    }
    // 获取某个用户的动态历史 GET
    if (api_match("/api/post/", http::verb::get)) {
      json::object value;
      try {
        value = json::parse(req.body()).as_object();
      } catch (const std::exception &e) {
        co_return json_response(req, {{"error", e.what()}},
                                http::status::bad_request);
      }
      int user_id;
      std::string_view username;
      if (value.contains("user_id")) {
        user_id = value.at("user_id").as_int64();
      } else if (value.contains("username")) {
        username = value.at("username").as_string().c_str();
        redis::request redis_req;
        redis::response<std::optional<std::string>> resp_id;
        redis_req.push("GET", username);
        co_await redis_conn->async_exec(redis_req, resp_id, redis_token);
        if (!bypass_redis() && std::get<0>(resp_id).value()) {
          user_id = std::stoi(std::get<0>(resp_id).value().value());
        } else {
          mysql::results mysql_result;
          auto stmt = co_await mysql_conn->async_prepare_statement(
              "SELECT id FROM users WHERE username = ?");
          co_await mysql_conn->async_execute(stmt.bind(username), mysql_result);
          co_await mysql_conn->async_close_statement(stmt);
          user_id = mysql_result.rows().at(0).at(0).as_int64();
        }
      } else {
        co_return json_response(req, {{"error", "no user id specified"}},
                                http::status::bad_request);
      }

      redis::request redis_req;
      redis::generic_response redis_resp_id;
      redis_req.push("TS.REVRANGE", "post_id:" + std::to_string(user_id), "-",
                     "+");
      co_await redis_conn->async_exec(redis_req, redis_resp_id, redis_token);
      json::array post_hist;
      if (!bypass_redis() && redis_resp_id.has_value()) {
        std::vector<std::string_view> post_ids(1, "posts");
        for (const auto &node : redis_resp_id.value()) {
          if (node.data_type == redis::resp3::type::doublean) {
            post_ids.emplace_back(node.value);
          }
        }
        redis_req.clear();
        redis_req.push_range("HMGET", post_ids.begin(), post_ids.end());
        redis::response<std::optional<std::vector<std::string>>>
            redis_resp_post;
        co_await redis_conn->async_exec(redis_req, redis_resp_post,
                                        redis_token);
        if (std::get<0>(redis_resp_post).value()) {
          const auto &posts = std::get<0>(redis_resp_post).value().value();
          post_hist = json::array(posts.begin(), posts.end());
        }
      }
      if (post_hist.empty()) {
        mysql::results mysql_result;
        auto stmt = co_await mysql_conn->async_prepare_statement(
            "SELECT * FROM posts WHERE user_id = ?");
        co_await mysql_conn->async_execute(stmt.bind(user_id), mysql_result);
        co_await mysql_conn->async_close_statement(stmt);
        if (mysql_result.empty()) {
          co_return json_response(req, {});
        }
        for (const auto &row : mysql_result.rows()) {
          int64_t t = row.at(3)
                          .as_datetime()
                          .get_time_point()
                          .time_since_epoch()
                          .count();
          json::object obj({{"post_id", row.at(0).as_int64()},
                            {"user_id", row.at(1).as_int64()},
                            {"content", row.at(2).as_string()},
                            {"created_at", t}});
          post_hist.push_back(obj);
        }
      }
      co_return json_response(req, {{"posts", post_hist}});
    }

    // All operations starting from here requires JWT auth.
    std::string_view token = req[http::field::authorization];
    if (token.empty()) {
      co_return json_response(req, {{"error", "unauthorized"}},
                              http::status::unauthorized);
    }
    token.remove_prefix(strlen("Bearer "));
    const auto decoded = jwt::decode<traits>({token.data(), token.size()});
    auto verify = jwt::verify<traits>().allow_algorithm(jwt_algo).with_issuer(
        issuer.data());
    int id_from_token = std::stoi(decoded.get_id());
    std::error_code ec;
    verify.verify(decoded, ec);
    if (ec || id_from_token == 0) {
      co_return json_response(req, {{"error", "authorization failed"}},
                              http::status::unauthorized);
    }
    // 关注用户 POST
    if (api_match("/api/follow/", http::verb::post)) {
      int user_id = std::stoi(req.target().substr(strlen("/api/follow/")));
      if (id_from_token != user_id) {
        co_return json_response(req, {{"error", "authorization failed"}},
                                http::status::unauthorized);
      }
      std::string_view follow_name =
          json::parse(req.body()).at("follow_name").as_string().c_str();

      redis::request redis_req;
      redis::response<std::optional<int64_t>> redis_resp;
      mysql::results result;
      redis_req.push("GET", follow_name);
      co_await redis_conn->async_exec(redis_req, redis_resp, redis_token);
      if (std::get<0>(redis_resp).value()) {
        redis_req.clear();
        int follow_id = std::get<0>(redis_resp).value().value();
        redis_req.push("SADD", "follow:" + std::to_string(user_id), follow_id);
        co_await redis_conn->async_exec(redis_req, redis::ignore, redis_token);

        auto stmt = co_await mysql_conn->async_prepare_statement(
            "INSERT INTO follows (follower_id, followee_id) VALUES (?, ?)");
        co_await mysql_conn->async_execute(stmt.bind(user_id, follow_id),
                                           result);
        co_await mysql_conn->async_close_statement(stmt);
      } else {
        auto stmt = co_await mysql_conn->async_prepare_statement(
            "INSERT INTO follows (follower_id, followee_id) "
            "SELECT ?, user_id from users WHERE username = ?");
        co_await mysql_conn->async_execute(stmt.bind(user_id, follow_name),
                                           result);
        co_await mysql_conn->async_close_statement(stmt);
        // TODO(): non-existent username
      }

      co_return json_response(req, {{"status", "success"}});
    }
    // 获取关注列表 GET
    if (api_match("/api/follow/", http::verb::get)) {
      int user_id = std::stoi(req.target().substr(strlen("/api/follow/")));
      if (id_from_token != user_id) {
        co_return json_response(req, {{"error", "authorization failed"}},
                                http::status::unauthorized);
      }
      redis::request redis_req;
      redis::response<std::optional<std::vector<int64_t>>, int> redis_resp;
      std::string key = "follow:" + std::to_string(user_id);
      redis_req.push("SMEMBERS", key);
      // redis_req.push("EXPIRE", key, 60);

      co_await redis_conn->async_exec(redis_req, redis_resp, redis_token);
      json::array all_follows;
      if (!bypass_redis() && std::get<0>(redis_resp).value()) {
        const auto &result = std::get<0>(redis_resp).value().value();
        all_follows = json::array(result.begin(), result.end());
      } else {
        // Query MySQL
        mysql::results mysql_result;
        auto stmt = co_await mysql_conn->async_prepare_statement(
            "SELECT followee_id from follows WHERE follower_id=?");
        co_await mysql_conn->async_execute(stmt.bind(user_id), mysql_result);
        co_await mysql_conn->async_close_statement(stmt);
        all_follows.reserve(mysql_result.size());
        for (const auto row : mysql_result.rows()) {
          all_follows.push_back(row.at(0).as_int64());
        }
      }
      co_return json_response(req, {{"followed", all_follows}});
    }

    // 发布动态 POST
    if (api_match("/api/post/", http::verb::post)) {
      int user_id;
      std::string_view content;
      auto local_time = std::chrono::time_point_cast<TimePoint::duration>(
          Clock::now() + std::chrono::hours(8));
      int64_t time_pt = local_time.time_since_epoch().count();
      try {
        auto value = json::parse(req.body()).as_object();
        if (!value.contains("user_id")) {
          co_return json_response(req, {{"error", "no user_id"}},
                                  http::status::bad_request);
        }
        user_id = value.at("user_id").as_int64();
        if (!value.contains("content")) {
          co_return json_response(req, {{"error", "no content"}},
                                  http::status::bad_request);
        }
        content = value.at("content").as_string().c_str();
      } catch (const std::exception &e) {
        co_return json_response(req, {{"error", e.what()}},
                                http::status::bad_request);
      }
      if (id_from_token != user_id) {
        co_return json_response(req, {{"error", "authorization failed"}},
                                http::status::unauthorized);
      }
      // 插入动态
      mysql::results result;
      // TODO(): statement pool along with mysql connection pool
      auto stmt = co_await mysql_conn->async_prepare_statement(
          "INSERT INTO posts (user_id, content) VALUES (?, ?)");
      co_await mysql_conn->async_execute(stmt.bind(user_id, content), result);
      co_await mysql_conn->async_close_statement(stmt);

      // 获取刚插入的post_id
      uint64_t post_id = result.last_insert_id();

      redis::request redis_req;
      json::object post_cont({{"id", post_id},
                              {"user_id", user_id},
                              {"content", content},
                              {"created_at", time_pt}});
      redis_req.push("HSET", "posts", post_id, json::serialize(post_cont));
      redis_req.push("TS.ADD", "post_id:" + std::to_string(user_id), time_pt,
                     post_id);
      co_await redis_conn->async_exec(redis_req, redis::ignore, redis_token);

      co_return json_response(req, {{"post_id", post_id}});
    }


    // 获取time时间点前最近n个订阅流
    if (api_match("/api/feed", http::verb::get)) {
      int user_id = std::stoi(req.target().substr(strlen("/api/feed/")));
      if (id_from_token != user_id) {
        co_return json_response(req, {{"error", "authorization failed"}},
                                http::status::unauthorized);
      }
      auto local_time = std::chrono::time_point_cast<TimePoint::duration>(
          Clock::now() + std::chrono::hours(8));
      auto time_pt = mysql::datetime(local_time);
      // TODO(): get time diff from mysql

      std::string max_time(
          std::to_string(local_time.time_since_epoch().count()));
      int page_size = 10;
      try {
        auto value = json::parse(req.body()).as_object();
        if (value.contains("max_time")) {
          max_time = value.at("max_time").as_string();
          time_pt = mysql::datetime(
              TimePoint(TimePoint::duration(std::stoll(max_time))));
        }
        if (value.contains("page_size")) {
          page_size = value.at("page_size").as_int64();
        }
      } catch (const std::exception &e) {
        co_return json_response(req, {{"error", e.what()}},
                                http::status::bad_request);
      }
      redis::request redis_req;
      redis_req.push("SMEMBERS", "follow:" + std::to_string(user_id));
      redis::response<std::optional<std::vector<int64_t>>> redis_resp_id;
      co_await redis_conn->async_exec(redis_req, redis_resp_id, redis_token);
      if (!bypass_redis() && std::get<0>(redis_resp_id).value()) {
        const auto &my_follow = std::get<0>(redis_resp_id).value().value();
        std::stringstream ss;
        ss << "user_id=(";
        for (int i = 0; i < my_follow.size(); i++) {
          ss << my_follow[i] << (i != my_follow.size() - 1 ? "," : ")");
        }
        redis_req.clear();
        redis_req.push("TS.MREVRANGE", "-", max_time, "COUNT", page_size,
                       "FILTER", ss.str());
        redis::generic_response resp_post_id;
        co_await redis_conn->async_exec(redis_req, resp_post_id, redis_token);
        if (resp_post_id.has_value() && !resp_post_id.value().empty()) {
          std::vector<std::string_view> post_ids(1, "posts");
          for (const auto &node : resp_post_id.value()) {
            if (node.data_type == redis::resp3::type::doublean) {
              post_ids.emplace_back(node.value);
            }
          }
          redis_req.clear();
          redis_req.push_range("HMGET", post_ids.begin(), post_ids.end());
          redis::response<std::optional<std::vector<std::string>>> resp_content;
          co_await redis_conn->async_exec(redis_req, resp_content, redis_token);
          if (std::get<0>(resp_content).value()) {
            const auto &contents = std::get<0>(resp_content).value().value();
            json::array posts(contents.begin(), contents.end());
            co_return json_response(req, {{"posts", posts}});
          } // TODO(PLB): SELECT * FROM posts WHERE id IN (...)
        }
      }

      // 从MySQL查询详细信息
      json::array posts;
      mysql::results result;
      auto stmt = co_await mysql_conn->async_prepare_statement(
          "SELECT p.* FROM posts p JOIN follows f ON p.user_id = f.followee_id "
          "WHERE f.follower_id = ? AND p.created_at < ? "
          "ORDER BY created_at DESC LIMIT ?");
      co_await mysql_conn->async_execute(stmt.bind(user_id, time_pt, page_size),
                                         result);
      co_await mysql_conn->async_close_statement(stmt);
      // 组装JSON...
      posts.reserve(page_size);
      for (const auto &row : result.rows()) {
        int64_t t =
            row.at(3).as_datetime().get_time_point().time_since_epoch().count();
        json::object obj({{"post_id", row.at(0).as_int64()},
                          {"user_id", row.at(1).as_int64()},
                          {"content", row.at(2).as_string()},
                          {"created_at", t}});
        posts.push_back(obj);
      }
      co_return json_response(req, {{"posts", posts}});
    }
  } catch (const std::exception &e) {
    co_return json_response(req, {{"error", e.what()}},
                            http::status::internal_server_error);
  }

  co_return not_implemented(req.target());
}

#ifdef FEED_USE_SSL
using stream_type = net::ssl::stream<beast::tcp_stream>;
#else
using stream_type = beast::tcp_stream;
#endif

// Handles an HTTP server connection
auto do_session(stream_type stream, redis::config redis_cfg,
                mysql::connect_params mysql_params) -> net::awaitable<void> {
  // This buffer is required to persist across reads
  beast::flat_buffer buffer;
  auto executor = co_await net::this_coro::executor;

#ifdef FEED_USE_SSL
  co_await stream.async_handshake(net::ssl::stream_base::server);
#endif

  auto redis_conn = std::make_shared<redis::connection>(executor);
  redis_conn->async_run(redis_cfg, {redis::logger::level::err},
                        net::consign(net::detached, redis_conn));

  auto mysql_conn = std::make_shared<mysql::any_connection>(executor);

  // Connect to the server
  co_await mysql_conn->async_connect(mysql_params);
  bool keep_alive;

  do {
    // Set the timeout.
#ifdef FEED_USE_SSL
    beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(30));
#else
    stream.expires_after(std::chrono::seconds(30));
#endif

    // Read a request
    http::request<http::string_body> req;
    auto [ec, _] =
        co_await http::async_read(stream, buffer, req, net::as_tuple);
    if (ec) {
      break;
    }

    // Handle the request
    http::message_generator msg =
        co_await handle_request(std::move(req), mysql_conn, redis_conn);
    keep_alive = msg.keep_alive();

    // Send the response
    std::tie(ec, _) =
        co_await beast::async_write(stream, std::move(msg), net::as_tuple);
    if (ec) {
      break;
    }
  } while (keep_alive);

  redis_conn->cancel();
  co_await mysql_conn->async_close();
// Send a TCP shutdown
#ifdef FEED_USE_SSL
  co_await stream.async_shutdown();
#else
  stream.socket().shutdown(net::ip::tcp::socket::shutdown_send);
  stream.close();
#endif

  // At this point the connection is closed gracefully
  // we ignore the error because the client might have
  // dropped the connection already.
}

template <typename T>
inline void pass_cfg_if_exists(T &dest, const json::object &cfg,
                               const std::string_view field) {
  if (cfg.contains(field)) {
    dest = cfg.at(field).as_string();
  }
}

auto generate_config(const json::object &config)
    -> std::pair<redis::config, mysql::connect_params> {
  redis::config redis_cfg;
  if (config.contains("redis")) {
    const auto &cfg = config.at("redis").as_object();
    pass_cfg_if_exists(redis_cfg.addr.host, cfg, "host");
    pass_cfg_if_exists(redis_cfg.addr.port, cfg, "port");
    pass_cfg_if_exists(redis_cfg.username, cfg, "username");
    pass_cfg_if_exists(redis_cfg.password, cfg, "password");
  }

  mysql::connect_params mysql_params;
  if (!config.contains("mysql")) {
    std::cerr << "Cannot find mysql config!\n";
    abort();
  }
  const auto &cfg = config.at("mysql").as_object();
  std::string hostname("localhost");
  pass_cfg_if_exists(hostname, cfg, "host");
  uint16_t port = mysql::default_port;
  if (cfg.contains("port")) {
    port = cfg.at("port").as_int64();
  }
  mysql_params.server_address.emplace_host_and_port(hostname, port);
  pass_cfg_if_exists(mysql_params.username, cfg, "username");
  pass_cfg_if_exists(mysql_params.password, cfg, "password");
  pass_cfg_if_exists(mysql_params.database, cfg, "database");
  return {redis_cfg, mysql_params};
}

// Accepts incoming connections and launches the sessions
auto do_listen(net::ip::tcp::endpoint endpoint, json::object config)
    -> net::awaitable<void> {
  auto executor = co_await net::this_coro::executor;
  auto acceptor = net::ip::tcp::acceptor{executor, endpoint};

  auto [redis_cfg, mysql_params] = generate_config(config);
  net::ssl::context ctx(net::ssl::context::tlsv13);
  load_server_certificate(ctx);

  for (;;) {
    net::co_spawn(executor,
                  do_session(
#ifdef FEED_USE_SSL
                      stream_type{co_await acceptor.async_accept(), ctx},
#else
                      stream_type{co_await acceptor.async_accept()},
#endif
                      redis_cfg, mysql_params),
                  net::detached);
  }
}

auto main(int argc, char *argv[]) -> int {
  // Check command line arguments.
  if (argc != 5) {
    std::cerr
        << "Usage: feed-service <address> <port> <config_file> <threads>\n"
        << "Example:\n"
        << "    feed-service 0.0.0.0 8080 ./config.json 1\n";
    return EXIT_FAILURE;
  }
  auto const address = net::ip::make_address(argv[1]);
  auto const port = static_cast<uint16_t>(std::atoi(argv[2]));
  auto const config_file = argv[3];
  auto const threads = std::max<int>(1, std::atoi(argv[4]));

  std::ifstream fs(config_file);
  std::stringstream buffer;
  buffer << fs.rdbuf();
  json::object config = json::parse(buffer.str()).as_object();

#define THREAD_LOCAL_IO_CONTEXT
#ifndef THREAD_LOCAL_IO_CONTEXT
  // The io_context is required for all I/O
  net::io_context ioc(threads);

  // Spawn a listening port
  net::co_spawn(ioc, do_listen(net::ip::tcp::endpoint{address, port}, config),
                net::detached);
  auto func = [&ioc]() { ioc.run(); };
#else
  auto func = [&config, &threads, &address, &port]() {
    // The io_context is required for all I/O
    net::io_context ioc(threads);

    // Spawn a listening port
    net::co_spawn(ioc, do_listen(net::ip::tcp::endpoint{address, port}, config),
                  net::detached);
    ioc.run();
  };
#endif
  // Run the I/O service on the requested number of threads
  std::vector<std::thread> v;
  v.reserve(threads);
  for (auto i = threads; i > 0; --i) {
    v.emplace_back(func);
  }

  for (auto i = 0; i < threads; ++i) {
    v[i].join();
  }

  return EXIT_SUCCESS;
}
