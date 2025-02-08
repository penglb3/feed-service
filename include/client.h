#include <boost/beast/http/verb.hpp>
#include <boost/json/object.hpp>
#include <string>
#include <string_view>
#include <vector>

template <typename T>
struct result {
  int status_;
  T value_;

  auto value() const -> const T & { return value_; }

  auto value() -> T & { return value_; }

  auto status() const -> int { return status_; }

  auto success() const -> bool { return status_ == 0; }
};

class client {
  using verb = boost::beast::http::verb;
  using string_view = std::string_view;

  const string_view host_, port_;
  int user_id_ = -1;
  std::string id_str_;

  auto request(string_view api, verb method, boost::json::object &&body)
      -> boost::json::object;

  auto password_hash_base64(string_view password) -> std::string;

  inline auto get_id_str() -> const std::string & {
    if (id_str_.empty()) {
      id_str_ = std::to_string(user_id_);
    }
    return id_str_;
  }

  auto _get_posts(int user_id, std::string_view username = {})
      -> result<std::vector<std::string>>;

public:
  enum status_code { kFailed = -1, kNotLoggedIn = -2 };

  inline auto get_posts(int user_id) -> result<std::vector<std::string>> {
    return _get_posts(user_id);
  };

  inline auto get_posts(std::string_view username)
      -> result<std::vector<std::string>> {
    return _get_posts(-1, username);
  }

  client(string_view host, string_view port) : host_(host), port_(port){};
  auto user_register(string_view username, string_view password) -> int;
  auto user_login(string_view username, string_view password) -> int;

  inline auto is_logged_in() -> bool { return user_id_ != -1; };

  // The following functions require that the user is logged in
  auto follow_user(string_view follow_name) -> int;
  auto publish_post(string_view post_content) -> int;
  auto get_follow_list() -> result<std::vector<int>>;
  auto get_feed() -> result<std::vector<std::string>>;
};
