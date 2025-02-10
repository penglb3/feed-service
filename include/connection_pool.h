#include <boost/asio/awaitable.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/lockfree/spsc_queue.hpp>
#include <boost/redis/connection.hpp>
#include <thread>
#include <vector>

class redis_connection_pool {
  using Conn = boost::redis::connection;
  boost::lockfree::spsc_queue<std::shared_ptr<Conn>> pool_;
  explicit redis_connection_pool(int queue_size) : pool_(queue_size){};

  auto init(boost::redis::config redis_cfg, int size)
      -> boost::asio::awaitable<void> {
    auto executor = co_await boost::asio::this_coro::executor;
    auto conn = std::make_shared<Conn>(executor);
    for (int i = 0; i < size; i++) {
      conn->async_run(redis_cfg, {},
                      boost::asio::consign(boost::asio::detached, conn));
      pool_.push(conn);
    }
  }

  template <typename Resp, typename Token>
  auto try_async_exec(const boost::redis::request &req, Resp &resp,
                      Token &&token) -> boost::asio::awaitable<bool> {
    std::shared_ptr<Conn> conn;
    if (pool_.pop(conn)) {
      co_await conn->async_exec(req, resp, token);
      pool_.push(conn);
      // TODO(): when pushing the pool_, somehow notify awaiting coros.
      // Currently I'm thinking about using a message_queue.
      co_return true;
    }
    co_return false;
    // TODO(): How to design an awaitable for this? How can it continue?
  }
};