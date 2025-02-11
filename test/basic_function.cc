#include "client.h"
#include <iostream>

using std::cout;
using std::endl;

#define ASSERT(x, y)                                                           \
  if ((x) != (y)) {                                                            \
    cout << "Line: " << __LINE__ << " " #x "!=" #y "\n";                       \
    abort();                                                                   \
  }

auto main() -> int {
  client c1("127.0.0.1", "12345");
  client c2("127.0.0.1", "12345");
  client c3("127.0.0.1", "12345");
  client c4("127.0.0.1", "12345");
  ASSERT(c1.user_register("user1", "pass1"), 1);
  ASSERT(c1.publish_post("hello user1"), 0);
  ASSERT(c1.publish_post("another post!"), 0);
  auto posts = c1.get_posts("user1");
  ASSERT(posts.success(), true);
  for (int i = 0; i < posts.value().size(); i++) {
    std::cout << "#" << i << ": " << posts.value()[i] << std::endl;
  }

  ASSERT(c2.user_register("user2", "pass2"), 2);
  ASSERT(c2.publish_post("hello user2"), 0);
  ASSERT(c2.follow_user("user1"), 0);

  ASSERT(c3.user_register("user3", "pass3"), 3);
  ASSERT(c3.publish_post("hello user3"), 0);
  ASSERT(c3.follow_user("user1"), 0);

  ASSERT(c4.user_register("user4", "pass4"), 4);

  ASSERT(c4.follow_user("user1"), 0);
  ASSERT(c4.follow_user("user2"), 0);
  ASSERT(c4.follow_user("user3"), 0);
  auto follow_list = c4.get_follow_list();
  ASSERT(follow_list.success(), true);
  for (auto id : follow_list.value()) {
    printf("%d,", id);
  }
  puts("");

  posts = c4.get_feed();
  ASSERT(posts.success(), true);
  for (int i = 0; i < posts.value().size(); i++) {
    std::cout << "#" << i << ": " << posts.value()[i] << std::endl;
  }
}